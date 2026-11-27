// Package dnsx caches reverse DNS names and ASNs with background lookups.
//
// Resolution is deliberately asynchronous: the probing cycle must not wait for DNS,
// otherwise the interval between cycles drifts and the names of intermediate routers
// turn the traceroute into waiting for resolver timeouts.
package dnsx

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type entry struct {
	value string
	done  bool
}

// Resolver caches names and ASNs. Implements trace.Resolver.
type Resolver struct {
	ctx     context.Context
	res     *net.Resolver
	workers int
	asnOn   bool
	lookupT time.Duration

	mu     sync.Mutex
	names  map[netip.Addr]*entry
	asns   map[netip.Addr]*entry
	queued map[netip.Addr]bool

	queue chan netip.Addr
	wg    sync.WaitGroup
}

// Config holds the resolver parameters.
type Config struct {
	Workers       int
	ASNLookup     bool
	LookupTimeout time.Duration
	Server        string // optional DNS server, e.g. "8.8.8.8:53"
}

// New creates the resolver and starts the workers (they stop when ctx is cancelled).
func New(ctx context.Context, cfg Config) *Resolver {
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.LookupTimeout <= 0 {
		cfg.LookupTimeout = 3 * time.Second
	}
	res := net.DefaultResolver
	if cfg.Server != "" {
		d := &net.Dialer{Timeout: cfg.LookupTimeout}
		res = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return d.DialContext(ctx, network, cfg.Server)
		}}
	}
	r := &Resolver{
		ctx:     ctx,
		res:     res,
		workers: cfg.Workers,
		asnOn:   cfg.ASNLookup,
		lookupT: cfg.LookupTimeout,
		names:   map[netip.Addr]*entry{},
		asns:    map[netip.Addr]*entry{},
		queued:  map[netip.Addr]bool{},
		queue:   make(chan netip.Addr, 1024),
	}
	for i := 0; i < cfg.Workers; i++ {
		r.wg.Add(1)
		go r.worker()
	}
	return r
}

// Enqueue puts an address in the resolution queue (never blocks; on overflow it is dropped).
func (r *Resolver) Enqueue(a netip.Addr) {
	if !a.IsValid() {
		return
	}
	a = a.WithZone("")
	r.mu.Lock()
	if _, ok := r.names[a]; !ok {
		r.names[a] = &entry{}
	}
	if r.asnOn {
		if _, ok := r.asns[a]; !ok {
			r.asns[a] = &entry{}
		}
	}
	need := !r.queued[a]
	if need {
		r.queued[a] = true
	}
	r.mu.Unlock()
	if !need {
		return
	}
	select {
	case r.queue <- a:
	default:
		r.mu.Lock()
		delete(r.queued, a) // the queue is jammed — try again later
		r.mu.Unlock()
	}
}

// Name returns the reverse name of an address or "" (still resolving / not found).
func (r *Resolver) Name(a netip.Addr) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.names[a.WithZone("")]; ok && e.done {
		return e.value
	}
	return ""
}

// Asn returns a string like "AS12345" or "".
func (r *Resolver) Asn(a netip.Addr) string {
	if !r.asnOn {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.asns[a.WithZone("")]; ok && e.done {
		return e.value
	}
	return ""
}

// Wait finishes processing the queue (after ctx has been cancelled).
func (r *Resolver) Wait() { close(r.queue); r.wg.Wait() }

func (r *Resolver) worker() {
	defer r.wg.Done()
	for a := range r.queue {
		r.resolveOne(a)
	}
}

func (r *Resolver) resolveOne(a netip.Addr) {
	ctx, cancel := context.WithTimeout(r.ctx, r.lookupT)
	defer cancel()

	names, err := r.res.LookupAddr(ctx, a.String())
	name := ""
	if err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}
	r.mu.Lock()
	e := r.names[a]
	if e != nil {
		e.value, e.done = name, true
	}
	r.mu.Unlock()

	if r.asnOn {
		asn := lookupASN(ctx, r.res, a)
		r.mu.Lock()
		ae := r.asns[a]
		if ae != nil {
			ae.value, ae.done = asn, true
		}
		r.mu.Unlock()
	}

	r.mu.Lock()
	delete(r.queued, a)
	r.mu.Unlock()
}

// lookupASN performs a Team Cymru query (origin.asn.cymru.com), the standard for mtr --aslookup.
func lookupASN(ctx context.Context, res *net.Resolver, a netip.Addr) string {
	q := asnQuery(a)
	txts, err := res.LookupTXT(ctx, q)
	if err != nil || len(txts) == 0 {
		return ""
	}
	f := strings.Fields(txts[0])
	if len(f) == 0 {
		return ""
	}
	if !strings.HasPrefix(f[0], "AS") {
		return "AS" + f[0]
	}
	return f[0]
}

// asnQuery builds the Team Cymru query name: reversed octets for IPv4, reversed
// half-nibbles of the /48 prefix for IPv6.
func asnQuery(a netip.Addr) string {
	if a.Is4() || a.Is4In6() {
		b := a.AsSlice()
		if len(b) == 16 { // 4-in-6
			b = b[12:]
		}
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", b[3], b[2], b[1], b[0])
	}
	b := a.AsSlice()[:6]
	var sb strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		fmt.Fprintf(&sb, "%x.%x.", b[i]&0xf, b[i]>>4)
	}
	return sb.String() + "origin.asn.cymru.com"
}
