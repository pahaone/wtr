//go:build windows

package probe

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"unsafe"
)

func TestStructSizes(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want int
	}{
		{"icmpEchoReply", unsafe.Sizeof(icmpEchoReply{}), 40},
		{"ipOptionInformation", unsafe.Sizeof(ipOptionInformation{}), 16},
		{"ipOptionInformation32", unsafe.Sizeof(ipOptionInformation32{}), 8},
		{"sockaddrIn6", unsafe.Sizeof(sockaddrIn6{}), 28},
		{"sockaddrIn", unsafe.Sizeof(sockaddrIn{}), 16},
	}
	for _, c := range cases {
		if int(c.got) != c.want {
			t.Errorf("%s: sizeof=%d, хотим %d — раскладка iphlpapi не совпадает", c.name, c.got, c.want)
		}
	}
}

func TestIPOctetOrder(t *testing.T) {
	// IPAddr is the 4 octets laid out in a DWORD as they are (the inet_addr equivalent),
	// i.e. on little-endian the lowest DWORD byte = the first octet of the address.
	cases := []struct {
		ip   string
		want uint32
	}{
		{"192.168.1.254", 0xFE01A8C0}, // LittleEndian: 192 | 168<<8 | 1<<16 | 254<<24
		{"1.2.3.4", 0x04030201},
		{"8.8.8.8", 0x08080808}, // palindrome: a byte-order mistake is invisible here
	}
	for _, c := range cases {
		a := netip.MustParseAddr(c.ip)
		if got := ipToUlong(a); got != c.want {
			t.Errorf("ipToUlong(%s)=0x%08X, хотим 0x%08X", c.ip, got, c.want)
		}
		if back := ulongToIP(c.want); back != a {
			t.Errorf("ulongToIP(0x%08X)=%s, хотим %s", c.want, back, a)
		}
	}
}

// TestIPOctetOrderIsNotBigEndian — regression for a frequent mistake: BigEndian turns
// 192.168.1.254 into 254.1.168.192 and the request leaves for a different network (ERROR_NETWORK_UNREACHABLE).
func TestIPOctetOrderIsNotBigEndian(t *testing.T) {
	a := netip.MustParseAddr("192.168.1.254")
	if got := binary.BigEndian.Uint32(a.AsSlice()); got == ipToUlong(a) {
		t.Fatal("порядок байт совпал с BigEndian — вероятно, регрессия в ipToUlong")
	}
}

func TestParseV6StatusRTT(t *testing.T) {
	buf := make([]byte, v6RecordMinSize)

	// The primary layout is Status@28/RTT@32.
	binary.LittleEndian.PutUint32(buf[v6RecStatusOff:], ipTTLExpiredTransit)
	binary.LittleEndian.PutUint32(buf[v6RecRTTOff:], 17)
	st, rtt := parseV6StatusRTT(buf)
	if st != ipTTLExpiredTransit || rtt != 17 {
		t.Fatalf("основной раскладка: status=%d rtt=%d", st, rtt)
	}

	// The realistic "layout shifted by -2 bytes" case: known values are written at the
	// fallback offsets 26/30. Reading at the primary offset 28 then yields a definitely
	// unrecognised code (overlapping bytes), and the function must fall back to 26/30.
	buf = make([]byte, v6RecordMinSize)
	binary.LittleEndian.PutUint32(buf[v6RecStatusAlt:], ipDestHostUnreachable)
	binary.LittleEndian.PutUint32(buf[v6RecRTTAlt:], 42)
	if knownStatus(binary.LittleEndian.Uint32(buf[v6RecStatusOff:])) {
		t.Skip("смещение 28 случайно дало известный код — кейс не показателен")
	}
	st, rtt = parseV6StatusRTT(buf)
	if st != ipDestHostUnreachable || rtt != 42 {
		t.Fatalf("запасная раскладка: status=%d(%s) rtt=%d", st, StatusName(st), rtt)
	}

	// Zeros (success without RTT) are treated as success by the primary layout.
	buf = make([]byte, v6RecordMinSize)
	st, _ = parseV6StatusRTT(buf)
	if st != ipSuccess {
		t.Fatalf("пустой буфер: status=%d, хотим IP_SUCCESS", st)
	}
}

func TestV6AddressOffset(t *testing.T) {
	// Empirically verified layout: the replier's address starts at the 6th byte.
	buf := make([]byte, v6RecordMinSize)
	want := netip.MustParseAddr("fd00::e9a3:2344:7528:5528")
	copy(buf[v6RecAddrOff:], want.AsSlice())
	var got [16]byte
	copy(got[:], buf[v6RecAddrOff:v6RecAddrOff+16])
	a, _ := netip.AddrFromSlice(got[:])
	if a != want {
		t.Fatalf("addr@%d: получили %s, хотим %s", v6RecAddrOff, a, want)
	}
}
