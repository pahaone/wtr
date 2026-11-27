//go:build windows

package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	modiphlpapi         = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreateFile  = modiphlpapi.NewProc("IcmpCreateFile")
	procIcmp6CreateFile = modiphlpapi.NewProc("Icmp6CreateFile")
	procIcmpCloseHandle = modiphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2   = modiphlpapi.NewProc("IcmpSendEcho2")
	procIcmpSendEcho2Ex = modiphlpapi.NewProc("IcmpSendEcho2Ex")
	procIcmp6SendEcho2  = modiphlpapi.NewProc("Icmp6SendEcho2")
)

// ---------------------------------------------------------------------------
// Layouts of the iphlpapi structures (confirmed by tests and live measurements).
// ---------------------------------------------------------------------------

// ipOptionInformation is IP_OPTION_INFORMATION for x64 (16 bytes).
type ipOptionInformation struct {
	Ttl         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr // Go inserts 4 padding bytes on its own -> offset 8, size 16
}

// ipOptionInformation32 is IP_OPTION_INFORMATION32 (8 bytes). This is exactly what
// Icmp6SendEcho2 requires on x64: a 64-bit pointer in the v6 options is not read.
type ipOptionInformation32 struct {
	Ttl         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uint32
}

// icmpEchoReply is ICMP_ECHO_REPLY (40 bytes on x64).
type icmpEchoReply struct {
	Address       uint32 // IPAddr: the 4 octets laid out in a DWORD as they are (see ipToUlong)
	Status        uint32
	RoundTripTime uint32 // milliseconds on the Windows clock
	DataSize      uint16
	Reserved      uint16
	Data          uintptr // pointer to the reply data inside our own buffer
	Ttl           uint8
	Tos           uint8
	Flags         uint8
	OptionsSize   uint8
	OptionsData   uintptr
}

// sockaddrIn is SOCKADDR_IN (16 bytes), needed for IcmpSendEcho2Ex with a source binding.
type sockaddrIn struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

// sockaddrIn6 is SOCKADDR_IN6 (28 bytes). For Icmp6SendEcho2 the interface LUID is passed in ScopeId.
type sockaddrIn6 struct {
	Family   uint16
	Port     uint16
	FlowInfo uint32
	Addr     [16]byte
	ScopeID  uint32
}

// Offsets inside the ICMPv6 reply record (ICMPV6_ECHO_REPLY).
//
// Established empirically on x64: IPV6_ADDRESS_EX is packed (pack(1)) and takes 26 bytes,
// so the address itself sits at offset 6 while the reply data always starts at 36. Hence
// Status/RTT = 28/32 (4-byte aligned after the 26-byte Address). Offset 26 is kept as a
// fallback candidate: if the primary offset yields an unrecognised code and the fallback
// yields a known one, the fallback is used. RTT is unaffected: RTT comes from QPC.
const (
	v6RecAddrOff    = 6
	v6RecStatusOff  = 28
	v6RecRTTOff     = 32
	v6RecStatusAlt  = 26
	v6RecRTTAlt     = 30
	v6RecordMinSize = 36
)

// ipToUlong converts an IPv4 address into the DestinationAddress parameter of type IPAddr.
//
// IMPORTANT: IPAddr is the same 4 octets as in the packet, laid out in a DWORD as they are
// (the equivalent of inet_addr). On little-endian that is LittleEndian.Uint32, NOT
// BigEndian. A byte-order mistake is invisible on "palindromic" addresses such as
// 8.8.8.8/1.1.1.1, but it turns 192.168.1.254 into 254.1.168.192 (verified: the reply comes
// from a foreign address with ERROR_NETWORK_UNREACHABLE).
func ipToUlong(ip netip.Addr) uint32 {
	b := ip.AsSlice()
	return binary.LittleEndian.Uint32(b[:4])
}

// ulongToIP is the reverse conversion of an IPAddr into a netip.Addr.
func ulongToIP(v uint32) netip.Addr {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	a, _ := netip.AddrFromSlice(b[:])
	return a
}

// ---------------------------------------------------------------------------
// Shared utilities
// ---------------------------------------------------------------------------

const replyBufferSize = 64 * 1024

func closeHandle(h uintptr) {
	if h != 0 && h != ^uintptr(0) {
		procIcmpCloseHandle.Call(h)
	}
}

// errnoCode extracts the Win32 code from the error returned by LazyProc.Call.
func errnoCode(err error) uint32 {
	if en, ok := err.(syscall.Errno); ok {
		return uint32(en)
	}
	return 0
}

// knownStatus checks whether a code looks like a valid iphlpapi status (for the v6 heuristic).
func knownStatus(s uint32) bool {
	switch s {
	case ipSuccess, ipBufTooSmall, ipDestNetUnreachable, ipDestHostUnreachable,
		ipDestProtUnreachable, ipDestPortUnreachable, ipPathMTUChanged, ipReqTimedOut,
		ipBadOption, ipBadDestination, ipTTLExpiredTransit, ipProtocolUnreachable,
		ipSourceQuench, ipOptionTooBig, ipBadHeader, ipGeneralFailure, ipPending,
		winErrorNetworkUnreachable, winErrorHostUnreachable:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// IPv4 backend
// ---------------------------------------------------------------------------

type backendV4 struct {
	handle uintptr
	dst    uint32
	src    *sockaddrIn // nil => IcmpSendEcho2, otherwise IcmpSendEcho2Ex
	buf    []byte
}

func newBackendV4(cfg Config) (Backend, error) {
	if !cfg.Dst.Is4() {
		return nil, fmt.Errorf("probe: цель %s не IPv4", cfg.Dst)
	}
	h, _, cerr := procIcmpCreateFile.Call()
	if h == 0 || h == ^uintptr(0) {
		return nil, &APIError{Proc: "IcmpCreateFile", Code: errnoCode(cerr)}
	}
	b := &backendV4{handle: h, dst: ipToUlong(cfg.Dst), buf: make([]byte, replyBufferSize)}
	if cfg.Src.IsValid() && cfg.Src.Is4() {
		si := &sockaddrIn{Family: syscall.AF_INET}
		copy(si.Addr[:], cfg.Src.AsSlice())
		b.src = si
	}
	return b, nil
}

func (b *backendV4) Probe(ctx context.Context, ttl int, payload []byte, timeout time.Duration) (Reply, error) {
	if err := ctx.Err(); err != nil {
		return Reply{}, err
	}
	if len(payload) == 0 {
		return Reply{}, fmt.Errorf("probe: пустой payload")
	}
	opts := ipOptionInformation{Ttl: uint8(ttl)}
	timeoutMs := uint32(timeout / time.Millisecond)
	if timeoutMs == 0 {
		timeoutMs = 1
	}

	var (
		n    uintptr
		cerr error
	)
	t0 := qpcTicks()
	if b.src != nil {
		n, _, cerr = procIcmpSendEcho2Ex.Call(
			b.handle, 0, 0, 0,
			uintptr(unsafe.Pointer(b.src)),
			uintptr(b.dst),
			uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
			uintptr(unsafe.Pointer(&opts)),
			uintptr(unsafe.Pointer(&b.buf[0])), uintptr(len(b.buf)),
			uintptr(timeoutMs),
		)
	} else {
		n, _, cerr = procIcmpSendEcho2.Call(
			b.handle, 0, 0, 0,
			uintptr(b.dst),
			uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
			uintptr(unsafe.Pointer(&opts)),
			uintptr(unsafe.Pointer(&b.buf[0])), uintptr(len(b.buf)),
			uintptr(timeoutMs),
		)
	}
	rtt := ticksToDuration(qpcTicks() - t0)
	runtime.KeepAlive(payload)

	if n == 0 {
		// There is no reply. 11010 (IP_REQ_TIMED_OUT) is the ordinary timeout; other codes
		// are stack errors (e.g. 1231 ERROR_NETWORK_UNREACHABLE). Both are a normal probe
		// result, not a call error.
		return Reply{Status: errnoCode(cerr), RTT: rtt}, nil
	}

	rec := (*icmpEchoReply)(unsafe.Pointer(&b.buf[0]))
	r := Reply{
		From:     ulongToIP(rec.Address),
		Status:   rec.Status,
		RTT:      rtt,
		APIRTT:   time.Duration(rec.RoundTripTime) * time.Millisecond,
		DataSize: int(rec.DataSize),
	}
	if data := replyData(b.buf, rec); len(data) > 0 && !MatchMarker(data, cycleOf(payload), ttlOf(payload), seqOf(payload)) {
		r.Stale = true
	}
	return r, nil
}

// replyData extracts the reply data without converting a uintptr into an unsafe.Pointer
// (otherwise go vet complains about "possible misuse of unsafe.Pointer"): the offset is
// computed inside our own buffer.
func replyData(buf []byte, rec *icmpEchoReply) []byte {
	if rec.Data == 0 || rec.DataSize == 0 {
		return nil
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	off := int(rec.Data - base)
	if off < 0 || off+int(rec.DataSize) > len(buf) {
		return nil
	}
	return buf[off : off+int(rec.DataSize)]
}

func (b *backendV4) Close() error {
	closeHandle(b.handle)
	b.handle = 0
	return nil
}

// ---------------------------------------------------------------------------
// IPv6 backend
// ---------------------------------------------------------------------------

type backendV6 struct {
	handle uintptr
	src    sockaddrIn6
	dst    sockaddrIn6
	buf    []byte
}

func newBackendV6(cfg Config) (Backend, error) {
	if !cfg.Dst.Is6() || cfg.Dst.Is4In6() {
		return nil, fmt.Errorf("probe: цель %s не IPv6", cfg.Dst)
	}
	h, _, cerr := procIcmp6CreateFile.Call()
	if h == 0 || h == ^uintptr(0) {
		return nil, &APIError{Proc: "Icmp6CreateFile", Code: errnoCode(cerr)}
	}
	b := &backendV6{handle: h, buf: make([]byte, replyBufferSize)}
	b.src.Family = syscall.AF_INET6
	b.dst.Family = syscall.AF_INET6
	copy(b.dst.Addr[:], cfg.Dst.AsSlice())

	// sin6_scope_id must contain the interface LUID. With a zero source the stack picks
	// the source address on its own, but the scope is still required — otherwise sending
	// to link-local/ULA does not work reliably.
	if cfg.LUID != 0 {
		b.src.ScopeID = uint32(cfg.LUID)
		b.dst.ScopeID = uint32(cfg.LUID)
	}
	if cfg.Src.IsValid() && cfg.Src.Is6() {
		copy(b.src.Addr[:], cfg.Src.AsSlice())
	}
	return b, nil
}

func (b *backendV6) Probe(ctx context.Context, ttl int, payload []byte, timeout time.Duration) (Reply, error) {
	if err := ctx.Err(); err != nil {
		return Reply{}, err
	}
	if len(payload) == 0 {
		return Reply{}, fmt.Errorf("probe: пустой payload")
	}
	opts := ipOptionInformation32{Ttl: uint8(ttl)}
	timeoutMs := uint32(timeout / time.Millisecond)
	if timeoutMs == 0 {
		timeoutMs = 1
	}

	t0 := qpcTicks()
	n, _, cerr := procIcmp6SendEcho2.Call(
		b.handle, 0, 0, 0,
		uintptr(unsafe.Pointer(&b.src)),
		uintptr(unsafe.Pointer(&b.dst)),
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&b.buf[0])), uintptr(len(b.buf)),
		uintptr(timeoutMs),
	)
	rtt := ticksToDuration(qpcTicks() - t0)
	runtime.KeepAlive(payload)

	if n == 0 {
		return Reply{Status: errnoCode(cerr), RTT: rtt}, nil
	}
	if len(b.buf) < v6RecordMinSize {
		return Reply{}, fmt.Errorf("probe: буфер ответа слишком мал")
	}
	status, apiMS := parseV6StatusRTT(b.buf)
	var addr [16]byte
	copy(addr[:], b.buf[v6RecAddrOff:v6RecAddrOff+16])
	a, _ := netip.AddrFromSlice(addr[:])
	r := Reply{
		From:   a.WithZone(""),
		Status: status,
		RTT:    rtt,
		APIRTT: time.Duration(apiMS) * time.Millisecond,
	}
	// The reply data follows right after the 36-byte record. Its length is not stated in
	// ICMPV6_ECHO_REPLY, and TTL-expired replies carry no data at all — so we key off the
	// magic marker: when it is present we compare cycle/ttl/seq and catch "late" replies;
	// when it is absent, this is a router reply without embedded data.
	if len(b.buf) >= v6RecordMinSize+len(markerMagic) &&
		string(b.buf[v6RecordMinSize:v6RecordMinSize+len(markerMagic)]) == markerMagic {
		data := b.buf[v6RecordMinSize:]
		want := len(payload)
		if want > len(data) {
			want = len(data)
		}
		r.DataSize = want
		if !MatchMarker(data[:want], cycleOf(payload), ttlOf(payload), seqOf(payload)) {
			r.Stale = true
		}
	}
	return r, nil
}

// parseV6StatusRTT reads Status/RoundTripTime out of an ICMPv6 record.
// The primary layout is 28/32; if it yields an unrecognised code while 26/30 yields a known
// one, the latter is taken.
func parseV6StatusRTT(buf []byte) (status uint32, rttMS uint32) {
	s := binary.LittleEndian.Uint32(buf[v6RecStatusOff:])
	rt := binary.LittleEndian.Uint32(buf[v6RecRTTOff:])
	if knownStatus(s) {
		return s, rt
	}
	if alt := binary.LittleEndian.Uint32(buf[v6RecStatusAlt:]); knownStatus(alt) {
		return alt, binary.LittleEndian.Uint32(buf[v6RecRTTAlt:])
	}
	return s, rt
}

func (b *backendV6) Close() error {
	closeHandle(b.handle)
	b.handle = 0
	return nil
}

// ---------------------------------------------------------------------------
// Factory and extraction of marker fields from the payload
// ---------------------------------------------------------------------------

var onceCheckABI sync.Once

// NewBackend creates an ICMP handle for the target from cfg.
func NewBackend(cfg Config) (Backend, error) {
	onceCheckABI.Do(checkABI)
	if cfg.Family == Family6 {
		return newBackendV6(cfg)
	}
	return newBackendV4(cfg)
}

// checkABI is a cheap layout check at startup (x86/amd64/arm64 LE).
func checkABI() {
	if unsafe.Sizeof(icmpEchoReply{}) != 40 ||
		unsafe.Sizeof(ipOptionInformation{}) != 16 ||
		unsafe.Sizeof(ipOptionInformation32{}) != 8 ||
		unsafe.Sizeof(sockaddrIn6{}) != 28 {
		panic("probe: неожиданные размеры структур iphlpapi — проверьте раскладку на этой платформе")
	}
}

// cycleOf/ttlOf/seqOf read the marker out of the payload that was sent (see MakePayload).
func cycleOf(p []byte) uint32 {
	if len(p) < 8 {
		return 0
	}
	return getBE32(p[4:8])
}

func ttlOf(p []byte) int {
	if len(p) < 10 {
		return 0
	}
	return int(p[8])<<8 | int(p[9])
}

func seqOf(p []byte) uint32 {
	if len(p) < 14 {
		return 0
	}
	return getBE32(p[10:14])
}
