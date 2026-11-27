// Package probe sends ICMP probes with a controlled TTL and collects the replies.
//
// The only backend is iphlpapi (IcmpSendEcho2 / Icmp6SendEcho2): it works without
// administrator rights, like the system tracert.exe, and reports the address of the
// replying node in the Address field of the reply record. Verified empirically
// (see README).
package probe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Family is the address family of the target.
type Family int

const (
	Family4 Family = 4
	Family6 Family = 6
)

func (f Family) String() string {
	if f == Family6 {
		return "ipv6"
	}
	return "ipv4"
}

// Reply is the result of a single probe.
type Reply struct {
	From     netip.Addr    // address of the replying node (intermediate router or target)
	Status   uint32        // raw iphlpapi status code
	RTT      time.Duration // RTT from the high-resolution monotonic clock (QPC)
	APIRTT   time.Duration // RTT measured by Windows itself (quantised to 1 ms)
	DataSize int           // size of the returned reply data
	// Stale means the reply data did not match this probe's marker: most likely a
	// "late" reply from a previous send. Such a reply is not counted in the statistics.
	Stale bool
}

// Kind returns the classification of the reply.
func (r Reply) Kind() Kind { return Classify(r.Status) }

// Backend is an encapsulated iphlpapi ICMP handle for a single target.
//
// IcmpSendEcho2/Icmp6SendEcho2 calls are blocking, so parallelism is achieved with one
// handle per worker: each worker owns its own Backend and calls it sequentially. It has
// been confirmed experimentally that replies do not get mixed up between handles (the
// markers in the payload always match).
type Backend interface {
	// Probe sends an echo request with the given TTL/hop limit and waits for a reply
	// until timeout. A timeout is NOT an error: a Reply with status IP_REQ_TIMED_OUT is
	// returned.
	Probe(ctx context.Context, ttl int, payload []byte, timeout time.Duration) (Reply, error)
	Close() error
}

// Config holds the parameters for creating a backend.
type Config struct {
	Family Family
	Dst    netip.Addr
	// Src is an optional source address binding (the equivalent of -B/--bind).
	Src netip.Addr
	// IfIndex is the interface index (0 = choose automatically). IPv6 requires the LUID
	// of this interface; it is resolved once in the engine and passed in here.
	IfIndex uint32
	// LUID is the interface identifier for Icmp6SendEcho2 (the sin6_scope_id field).
	LUID uint64
}

// ErrUnsupported is returned on platforms where iphlpapi is unavailable.
var ErrUnsupported = errors.New("probe: the iphlpapi backend is available only on Windows")

// APIError is a Win32/API error unrelated to packet loss (e.g. an invalid handle).
type APIError struct {
	Proc string
	Code uint32
}

func (e *APIError) Error() string {
	return fmt.Sprintf("probe: %s failed: winerr=%d (%s)", e.Proc, e.Code, StatusName(e.Code))
}

// The probe marker written into the payload. It is what lets us drop "late" echo
// replies, since iphlpapi gives no other way to match a reply with its request.
const markerMagic = "WTR1"

// MakePayload writes the probe marker into buf and returns a slice of the wanted length.
func MakePayload(buf []byte, size int, cycle uint32, ttl int, seq uint32) []byte {
	if size < len(markerMagic)+10 {
		size = len(markerMagic) + 10
	}
	copy(buf, markerMagic)
	putBE32(buf[4:8], cycle)
	buf[8] = byte(ttl >> 8)
	buf[9] = byte(ttl)
	putBE32(buf[10:14], seq)
	for i := 14; i < size; i++ {
		buf[i] = byte('A' + (i % 26))
	}
	return buf[:size]
}

// MatchMarker checks that p is the data of exactly this probe.
func MatchMarker(p []byte, cycle uint32, ttl int, seq uint32) bool {
	if len(p) < 14 || string(p[:4]) != markerMagic {
		return false
	}
	if getBE32(p[4:8]) != cycle {
		return false
	}
	if int(p[8])<<8|int(p[9]) != ttl {
		return false
	}
	return getBE32(p[10:14]) == seq
}

func putBE32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func getBE32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
