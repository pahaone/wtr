// Package trace — the traceroute engine: growing TTL, parallel probes, per-hop
// statistics aggregation and state snapshots for the renderers.
package trace

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"wtr/internal/probe"
	"wtr/internal/stats"
)

// Resolver is asynchronous reverse DNS and ASN lookup (implemented by internal/dnsx).
// The engine only enqueues addresses and reads the finished cache, so resolving never
// slows down the probing cycle.
type Resolver interface {
	Enqueue(addr netip.Addr)
	Name(addr netip.Addr) string
	Asn(addr netip.Addr) string
}

// Options are the ready-to-use traceroute settings (validated in the CLI).
type Options struct {
	Target        string
	Family        probe.Family
	MaxHops       int
	Cycles        int // 0 = infinite (interactive mode)
	QueriesPerHop int
	Interval      time.Duration
	Timeout       time.Duration
	PayloadSize   int
	Workers       int
	Src           netip.Addr // optional source address binding
	IfIndex       uint32     // 0 = auto
	// Gap is a micro-pause between neighbouring TTL probes within one cycle. Without it
	// all TTLs leave as a "burst" and routers start dropping ICMP Time Exceeded to
	// rate-limit (inflated loss on distant hops).
	Gap time.Duration
	// DNSServer is the DNS server address used for reverse names (used by the CLI, not the engine).
	DNSServer string
}

// closeDrainDelay is how long Close waits before releasing the ICMP handles.
//
// When Ctrl+C cancels ctx, wg.Wait() guarantees only that the synchronous
// IcmpSendEcho2 calls have returned — it does NOT mean iphlpapi has finished
// processing the late ICMP Time-Exceeded replies still in flight for probes sent
// moments ago. Those replies are tied to our reply buffers and to the handle's
// internal context. Closing the handle while the stack is still delivering them
// frees memory iphlpapi is touching, which crashes with an access violation
// (0xc0000005) inside IcmpCloseHandle. A short drain pause lets the stack settle.
const closeDrainDelay = 150 * time.Millisecond

// Engine is the state of a single traceroute.
type Engine struct {
	opt   Options
	dst   netip.Addr
	route probe.RouteInfo
	res   Resolver

	workers []*worker
	seq     atomic.Uint64

	// closeOnce guards against double-closing the ICMP handles: New() closes on a
	// setup error and cli.Run defers Close() again, and Run() defers Close() too.
	closeOnce sync.Once

	mu         sync.Mutex
	hops       []*hopState
	reachedTTL int // TTL at which the target answers in the current route (0 = not reached yet)
	// cycleReplyTTL — the smallest TTL with a reply from the target in the current cycle. The
	// target also answers at TTLs above the real distance, so the maximum must not be
	// accumulated: the hop list would grow to --max-hops. The minimum per cycle is computed
	// and adopted as a whole — so routing may get longer if the path changes.
	cycleReplyTTL int
	cycle         int
	stale         int64
	started       time.Time
	finished      time.Time
}

// worker owns its own ICMP handle: iphlpapi calls are blocking, so parallelism is
// achieved by a set of handles rather than by goroutines on top of a single one.
type worker struct {
	be      probe.Backend
	payload []byte
}

type hopState struct {
	ttl     int
	st      stats.Hop
	hits    map[netip.Addr]int // ECMP: several routers may answer at one TTL
	primary netip.Addr
	status  uint32
	flags   map[string]struct{}
}

func newHopState(ttl int) *hopState {
	return &hopState{ttl: ttl, hits: map[netip.Addr]int{}, flags: map[string]struct{}{}}
}

func (h *hopState) observe(a netip.Addr) {
	if !a.IsValid() {
		return
	}
	h.hits[a]++
	if !h.primary.IsValid() || h.hits[a] > h.hits[h.primary] {
		h.primary = a
	}
}

// Hooks for unit tests: replaced without touching the real network/iphlpapi.
var (
	newBackend = probe.NewBackend
	routeTo    = probe.RouteTo
)

// New resolves the target, determines the route and opens the ICMP handles.
func New(ctx context.Context, opt Options, res Resolver) (*Engine, error) {
	dst, err := ResolveTarget(ctx, opt.Target, opt.Family)
	if err != nil {
		return nil, err
	}
	opt.Family = familyOf(dst)

	route, err := routeTo(dst)
	if err != nil {
		return nil, fmt.Errorf("failed to determine the interface to %s: %w", dst, err)
	}
	if opt.IfIndex != 0 && opt.IfIndex != route.IfIndex {
		route.IfIndex = opt.IfIndex
		route.LUID, _ = probe.InterfaceLUID(opt.IfIndex)
	}
	if opt.Family == probe.Family6 && route.LUID == 0 {
		return nil, fmt.Errorf("failed to get the LUID of interface %d for IPv6", route.IfIndex)
	}

	nw := opt.Workers
	if nw < 1 {
		nw = 1
	}
	e := &Engine{opt: opt, dst: dst, route: route, res: res}
	for i := 0; i < nw; i++ {
		be, err := newBackend(probe.Config{
			Family:  opt.Family,
			Dst:     dst,
			Src:     opt.Src,
			IfIndex: route.IfIndex,
			LUID:    route.LUID,
		})
		if err != nil {
			e.Close()
			return nil, fmt.Errorf("probe backend #%d: %w", i, err)
		}
		e.workers = append(e.workers, &worker{be: be, payload: make([]byte, opt.PayloadSize)})
	}
	return e, nil
}

// Target is the address of the target.
func (e *Engine) Target() netip.Addr { return e.dst }

// Route is the interface the traceroute goes through.
func (e *Engine) Route() probe.RouteInfo { return e.route }

// Close closes all ICMP handles. It first waits closeDrainDelay so iphlpapi can
// finish delivering the late replies tied to probes that were still in flight when
// ctx was cancelled — closing a handle mid-delivery crashes inside IcmpCloseHandle
// (see closeDrainDelay). Safe to call more than once.
func (e *Engine) Close() error {
	time.Sleep(closeDrainDelay)
	e.closeOnce.Do(func() {
		for _, w := range e.workers {
			if w.be != nil {
				w.be.Close()
			}
		}
		e.workers = nil
	})
	return nil
}

// Run spins the probing cycles until --cycles is exhausted or ctx is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	defer e.Close()

	e.mu.Lock()
	e.started = time.Now()
	e.mu.Unlock()

	for cycle := 1; e.opt.Cycles == 0 || cycle <= e.opt.Cycles; cycle++ {
		cycleStart := time.Now()
		if err := e.runCycle(ctx, uint32(cycle)); err != nil && ctx.Err() != nil {
			e.markFinished()
			return nil // a normal interruption (Ctrl+C)
		}
		e.mu.Lock()
		e.cycle = cycle
		e.finished = time.Now()
		e.mu.Unlock()

		if e.opt.Cycles > 0 && cycle >= e.opt.Cycles {
			break
		}
		wait := e.opt.Interval - time.Since(cycleStart)
		if wait < 0 {
			wait = 0
		}
		select {
		case <-ctx.Done():
			e.markFinished()
			return nil
		case <-time.After(wait):
		}
	}
	e.markFinished()
	return nil
}

func (e *Engine) markFinished() {
	e.mu.Lock()
	e.finished = time.Now()
	e.mu.Unlock()
}

// runCycle sends QueriesPerHop probes for every TTL from 1 up to the current maximum.
// Once the target has been reached, the TTL is not grown beyond it.
func (e *Engine) runCycle(ctx context.Context, cycle uint32) error {
	e.mu.Lock()
	maxTTL := e.opt.MaxHops
	if e.reachedTTL > 0 && e.reachedTTL < maxTTL {
		maxTTL = e.reachedTTL
	}
	e.ensureHopsLocked(maxTTL)
	e.mu.Unlock()

	pool := make(chan *worker, len(e.workers))
	for _, w := range e.workers {
		pool <- w
	}

	var wg sync.WaitGroup
	finalize := func() {
		e.mu.Lock()
		e.finishCycleLocked()
		e.mu.Unlock()
	}
	var gapCh <-chan time.Time
	var timer *time.Timer
	if e.opt.Gap > 0 {
		timer = time.NewTimer(e.opt.Gap)
		defer timer.Stop()
		gapCh = timer.C
	}
dispatch:
	for ttl := 1; ttl <= maxTTL; ttl++ {
		for q := 0; q < e.opt.QueriesPerHop; q++ {
			var w *worker
			select {
			case w = <-pool:
			case <-ctx.Done():
				wg.Wait()
				finalize()
				return ctx.Err()
			}
			seq := uint32(e.seq.Add(1))
			wg.Add(1)
			go func(w *worker, ttl int, seq uint32) {
				defer wg.Done()
				payload := probe.MakePayload(w.payload[:cap(w.payload)], e.opt.PayloadSize, cycle, ttl, seq)
				r, err := w.be.Probe(ctx, ttl, payload, e.opt.Timeout)
				switch {
				case err != nil: // a call error — simply not accounted for
				case r.Stale:
					e.mu.Lock()
					e.stale++
					e.mu.Unlock()
				default:
					e.record(ttl, r)
				}
				pool <- w
			}(w, ttl, seq)

			if gapCh == nil {
				continue
			}
			select {
			case <-gapCh:
				timer.Reset(e.opt.Gap)
			case <-ctx.Done():
				break dispatch
			}
		}
	}
	wg.Wait()
	finalize()
	return ctx.Err()
}

func (e *Engine) ensureHopsLocked(maxTTL int) {
	for len(e.hops) < maxTTL {
		e.hops = append(e.hops, newHopState(len(e.hops)+1))
	}
}

// noteTargetReplyLocked remembers the shortest TTL at which the target address itself
// answered in this cycle. Called with e.mu held.
func (e *Engine) noteTargetReplyLocked(ttl int) {
	if e.cycleReplyTTL == 0 || ttl < e.cycleReplyTTL {
		e.cycleReplyTTL = ttl
	}
}

// finishCycleLocked adopts the cycle result: the route length is the shortest TTL with a
// reply from the target in this cycle. If the target did not answer in the cycle (timeouts,
// ICMP rate-limit on an intermediate router), the previous length is kept — otherwise the
// table would flicker between the full route and its beginning.
func (e *Engine) finishCycleLocked() {
	if e.cycleReplyTTL > 0 {
		e.reachedTTL = e.cycleReplyTTL
	}
	e.cycleReplyTTL = 0
}

// reachedLocked is the route length to display: the current cycle is taken into account as
// well, so hops beyond the target disappear immediately without waiting for the cycle to
// end. Called with e.mu held.
func (e *Engine) reachedLocked() int {
	r := e.reachedTTL
	if e.cycleReplyTTL > 0 && (r == 0 || e.cycleReplyTTL < r) {
		r = e.cycleReplyTTL
	}
	return r
}

// record folds a probe result into the hop statistics.
func (e *Engine) record(ttl int, r probe.Reply) {
	if ttl < 1 || ttl > len(e.hops) {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	h := e.hops[ttl-1]
	h.status = r.Status
	kind := r.Kind()

	switch kind {
	case probe.KindReply:
		h.st.Add(r.RTT, true)
		h.observe(r.From)
		e.noteTargetReplyLocked(ttl)
	case probe.KindHop:
		if !r.From.IsValid() {
			h.st.Add(0, false) // TTL expired without an address — counted as a loss
			return
		}
		h.st.Add(r.RTT, true)
		h.observe(r.From)
	case probe.KindUnreachable:
		h.st.Add(0, false)
		if f := probe.ShortFlag(r.Status); f != "" {
			h.flags[f] = struct{}{}
		} else {
			h.flags["!"] = struct{}{}
		}
		if r.From.IsValid() {
			h.observe(r.From)
			if r.From == e.dst {
				// "Reached but administratively prohibited" — the target was found here.
				e.noteTargetReplyLocked(ttl)
			}
		}
	default: // KindTimeout, KindError
		h.st.Add(0, false)
		if kind == probe.KindError {
			h.flags["!"] = struct{}{}
		}
	}

	if r.From.IsValid() && e.res != nil {
		e.res.Enqueue(r.From)
	}
}

// HopView is the hop representation for the renderers.
type HopView struct {
	TTL     int            `json:"ttl"`
	Addrs   []netip.Addr   `json:"addrs"` // all repliers (ECMP), most frequent first
	Names   []string       `json:"names"` // parallel to Addrs; "" if the name has not resolved yet
	Asns    []string       `json:"asns,omitempty"`
	Snap    stats.Snapshot `json:"stats"`
	Status  uint32         `json:"status"`
	Flags   []string       `json:"flags,omitempty"`
	Pending bool           `json:"pending"` // no reply yet
}

// View is a traceroute state snapshot for rendering/output.
type View struct {
	Target       netip.Addr    `json:"target"`
	TargetName   string        `json:"target_name,omitempty"`
	Family       probe.Family  `json:"family"`
	Iface        string        `json:"iface,omitempty"`
	IfIndex      uint32        `json:"ifindex,omitempty"`
	Cycle        int           `json:"cycle"`
	Hops         []HopView     `json:"hops"`
	Started      time.Time     `json:"started"`
	Elapsed      time.Duration `json:"elapsed_ns"`
	Reached      bool          `json:"reached"`
	StaleDropped int64         `json:"stale_dropped,omitempty"`
}

// Snapshot collects an immutable snapshot of the current results.
func (e *Engine) Snapshot() View {
	e.mu.Lock()
	defer e.mu.Unlock()

	v := View{
		Target:       e.dst,
		Family:       e.opt.Family,
		Iface:        e.route.FriendlyName,
		IfIndex:      e.route.IfIndex,
		Cycle:        e.cycle,
		Started:      e.started,
		Reached:      e.reachedLocked() > 0,
		StaleDropped: e.stale,
	}
	if !e.started.IsZero() {
		end := e.finished
		if end.IsZero() {
			end = time.Now()
		}
		v.Elapsed = end.Sub(e.started)
	}
	if e.res != nil {
		v.TargetName = e.res.Name(e.dst)
	}

	// Hops beyond the target are not shown: at a TTL greater than the reached one the echo
	// request gets to the target and it answers again — those are not separate hops.
	limit := len(e.hops)
	if r := e.reachedLocked(); r > 0 && r < limit {
		limit = r
	}
	// Trailing hops where no probe was ever recorded have nothing to show: either the first
	// cycle is still in flight (those TTLs have not been dispatched yet) or every probe at
	// that TTL failed at the API level, which is not accounted for. Left alone, they turn the
	// bottom of the table into a column of empty "???" rows.
	for limit > 1 {
		if sent, _ := e.hops[limit-1].st.Counters(); sent != 0 {
			break
		}
		limit--
	}
	for _, h := range e.hops[:limit] {
		snap := h.st.Snapshot()
		hv := HopView{
			TTL:     h.ttl,
			Snap:    snap,
			Status:  h.status,
			Pending: !h.st.HasData(),
		}
		for f := range h.flags {
			hv.Flags = append(hv.Flags, f)
		}
		sort.Strings(hv.Flags)

		if len(h.hits) > 0 {
			hv.Addrs = make([]netip.Addr, 0, len(h.hits))
			for a := range h.hits {
				hv.Addrs = append(hv.Addrs, a)
			}
			sort.Slice(hv.Addrs, func(i, j int) bool {
				if h.hits[hv.Addrs[i]] != h.hits[hv.Addrs[j]] {
					return h.hits[hv.Addrs[i]] > h.hits[hv.Addrs[j]]
				}
				return hv.Addrs[i].Compare(hv.Addrs[j]) < 0
			})
			for _, a := range hv.Addrs {
				if e.res != nil {
					hv.Names = append(hv.Names, e.res.Name(a))
					hv.Asns = append(hv.Asns, e.res.Asn(a))
				} else {
					hv.Names = append(hv.Names, "")
				}
			}
		}
		v.Hops = append(v.Hops, hv)
	}
	return v
}
