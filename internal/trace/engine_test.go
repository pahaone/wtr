package trace

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"wtr/internal/probe"
)

// Raw iphlpapi codes: we check the "numeric code -> Kind" contract, not just the internals.
const (
	statusSuccess    uint32 = 0     // IP_SUCCESS
	statusTTLExpired uint32 = 11013 // IP_TTL_EXPIRED_TRANSIT
	statusTimeout    uint32 = 11010 // IP_REQ_TIMED_OUT
)

var fakeStaleOnce atomic.Bool

// fakeBackend imitates a traceroute: TTL 1-2 are routers, TTL 3 is the target, TTL 4 is
// silence. The first probe of the second hop is marked "late" to verify stale rejection.
type fakeBackend struct{}

var errNoMarker = errors.New("probe: no probe marker in the payload")

func (fakeBackend) Probe(_ context.Context, ttl int, payload []byte, _ time.Duration) (probe.Reply, error) {
	// The marker must be present: without it the rejection of "late" replies does not work.
	if len(payload) < 14 || string(payload[:4]) != "WTR1" {
		return probe.Reply{}, errNoMarker
	}
	switch ttl {
	case 1:
		return probe.Reply{From: netip.MustParseAddr("10.0.0.1"), Status: statusTTLExpired, RTT: 900 * time.Microsecond}, nil
	case 2:
		if fakeStaleOnce.CompareAndSwap(false, true) {
			return probe.Reply{From: netip.MustParseAddr("10.0.0.2"), Status: statusTTLExpired, RTT: 5 * time.Millisecond, Stale: true}, nil
		}
		return probe.Reply{From: netip.MustParseAddr("10.0.0.2"), Status: statusTTLExpired, RTT: 4 * time.Millisecond}, nil
	case 3:
		return probe.Reply{From: netip.MustParseAddr("192.0.2.1"), Status: statusSuccess, RTT: 20 * time.Millisecond}, nil
	default:
		return probe.Reply{Status: statusTimeout}, nil
	}
}

func (fakeBackend) Close() error { return nil }

func TestEngineCycleAndStats(t *testing.T) {
	fakeStaleOnce.Store(false)

	oldNew, oldRoute := newBackend, routeTo
	t.Cleanup(func() { newBackend, routeTo = oldNew, oldRoute })
	newBackend = func(probe.Config) (probe.Backend, error) { return fakeBackend{}, nil }
	routeTo = func(netip.Addr) (probe.RouteInfo, error) { return probe.RouteInfo{IfIndex: 17, LUID: 0x42}, nil }

	opt := Options{
		Target:        "192.0.2.1", // TEST-NET-1, a literal — DNS is not touched
		MaxHops:       4,
		Cycles:        2,
		QueriesPerHop: 2,
		Interval:      10 * time.Millisecond,
		Timeout:       50 * time.Millisecond,
		PayloadSize:   56,
		Workers:       4,
	}
	e, err := New(context.Background(), opt, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close()

	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	v := e.Snapshot()

	if !v.Reached {
		t.Fatal("the target must be reached at TTL=3")
	}
	if v.Cycle != 2 {
		t.Fatalf("Cycle=%d, want 2", v.Cycle)
	}
	// Exactly the hops up to the target: TTL 4 was probed in the first cycle but it must not
	// be shown — beyond the target the target itself answers, there are no separate hops.
	if len(v.Hops) != 3 {
		t.Fatalf("%d hops, want 3 (hops beyond the target are hidden)", len(v.Hops))
	}

	h1 := v.Hops[0]
	if h1.Snap.Sent != 4 || h1.Snap.Lost != 0 {
		t.Errorf("hop1 sent/lost = %d/%d, want 4/0", h1.Snap.Sent, h1.Snap.Lost)
	}
	if len(h1.Addrs) != 1 || h1.Addrs[0] != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("hop1 addrs = %v, want [10.0.0.1]", h1.Addrs)
	}
	if h1.Pending {
		t.Error("hop1 must not be pending")
	}

	h2 := v.Hops[1]
	if h2.Snap.Sent != 3 || h2.Snap.Lost != 0 {
		t.Errorf("hop2 sent/lost = %d/%d, want 3/0 (one stale reply dropped)", h2.Snap.Sent, h2.Snap.Lost)
	}
	if v.StaleDropped != 1 {
		t.Errorf("StaleDropped=%d, want 1", v.StaleDropped)
	}

	h3 := v.Hops[2]
	if h3.Snap.Lost != 0 || h3.Addrs[0] != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("hop3 = %+v, want a reply from the target", h3)
	}

	for _, h := range v.Hops {
		if h.TTL > 3 {
			t.Errorf("the snapshot got a hop TTL=%d beyond the target", h.TTL)
		}
	}
}

// TestEngineStopsGrowingAfterReach checks that after the target is reached the engine
// stops sending probes at TTLs beyond the target (saves traffic and reduces network load).
func TestEngineStopsGrowingAfterReach(t *testing.T) {
	fakeStaleOnce.Store(true) // disable the stale scenario

	oldNew, oldRoute := newBackend, routeTo
	t.Cleanup(func() { newBackend, routeTo = oldNew, oldRoute })
	var calls atomic.Int32
	newBackend = func(probe.Config) (probe.Backend, error) { return countingBackend{&calls}, nil }
	routeTo = func(netip.Addr) (probe.RouteInfo, error) { return probe.RouteInfo{IfIndex: 17, LUID: 0x42}, nil }

	opt := Options{
		Target: "192.0.2.1", MaxHops: 5, Cycles: 3, QueriesPerHop: 1,
		Interval: time.Millisecond, Timeout: 20 * time.Millisecond, PayloadSize: 56, Workers: 8,
	}
	e, err := New(context.Background(), opt, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close()
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Cycle 1: TTL 1..5 = 5 probes. After it the target is found at TTL=3,
	// cycles 2 and 3 send only TTL 1..3 => 5 + 3 + 3 = 11 in total.
	if got := calls.Load(); got != 11 {
		t.Fatalf("%d probes in total, want 11 (5+3+3)", got)
	}
}

type countingBackend struct{ c *atomic.Int32 }

func (b countingBackend) Probe(_ context.Context, ttl int, _ []byte, _ time.Duration) (probe.Reply, error) {
	b.c.Add(1)
	if ttl < 3 {
		return probe.Reply{From: netip.MustParseAddr("10.0.0.9"), Status: statusTTLExpired, RTT: time.Millisecond}, nil
	}
	if ttl == 3 {
		return probe.Reply{From: netip.MustParseAddr("192.0.2.1"), Status: statusSuccess, RTT: 5 * time.Millisecond}, nil
	}
	return probe.Reply{Status: statusTimeout}, nil
}

func (countingBackend) Close() error { return nil }

// eagerBackend imitates a target that answers at every TTL starting from its distance
// (this is how, for example, the local gateway behaves: it also answers at TTL=1).
type eagerBackend struct{ c *atomic.Int32 }

func (b eagerBackend) Probe(_ context.Context, ttl int, _ []byte, _ time.Duration) (probe.Reply, error) {
	b.c.Add(1)
	if ttl == 1 {
		return probe.Reply{From: netip.MustParseAddr("10.0.0.1"), Status: statusTTLExpired, RTT: time.Millisecond}, nil
	}
	return probe.Reply{From: netip.MustParseAddr("192.0.2.1"), Status: statusSuccess, RTT: 2 * time.Millisecond}, nil
}

func (eagerBackend) Close() error { return nil }

// TestTargetAnsweringAtEveryTTLDoesNotInflateHops — regression for a real case:
// tracerouting the local gateway showed 30 hops because the route length was computed as
// the maximum TTL that got a reply from the target.
func TestTargetAnsweringAtEveryTTLDoesNotInflateHops(t *testing.T) {
	oldNew, oldRoute := newBackend, routeTo
	t.Cleanup(func() { newBackend, routeTo = oldNew, oldRoute })
	var calls atomic.Int32
	newBackend = func(probe.Config) (probe.Backend, error) { return eagerBackend{&calls}, nil }
	routeTo = func(netip.Addr) (probe.RouteInfo, error) { return probe.RouteInfo{IfIndex: 17}, nil }

	e, err := New(context.Background(), Options{
		Target: "192.0.2.1", MaxHops: 5, Cycles: 2, QueriesPerHop: 1,
		Interval: time.Millisecond, Timeout: 20 * time.Millisecond, PayloadSize: 56, Workers: 8,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close()
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	v := e.Snapshot()
	if !v.Reached {
		t.Fatal("the target must be reached")
	}
	if len(v.Hops) != 2 {
		t.Fatalf("%d hops, want 2 (hops 3..5 are the same target at an inflated TTL)", len(v.Hops))
	}
	if v.Hops[1].Addrs[0] != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("hop 2 = %v, want the target", v.Hops[1].Addrs)
	}
	// Cycle 1: TTL 1..5, cycle 2: only TTL 1..2.
	if got := calls.Load(); got != 7 {
		t.Fatalf("%d probes in total, want 7 (5+2)", got)
	}
}
