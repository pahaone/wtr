package dnsx

import (
	"net/netip"
	"testing"
)

func TestASNQueryNames(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		// IPv4: octets in reverse order (Team Cymru format).
		{"8.8.8.8", "8.8.8.8.origin.asn.cymru.com"},
		{"1.2.3.4", "4.3.2.1.origin.asn.cymru.com"},
		{"208.69.34.220", "220.34.69.208.origin.asn.cymru.com"},
		// 4-in-6 must expand into the IPv4 form, not into half-nibbles.
		{"::ffff:1.2.3.4", "4.3.2.1.origin.asn.cymru.com"},
		// IPv6: 12 half-nibbles of the /48 prefix in reverse order.
		{"2001:df5:c00::1", "0.0.c.0.5.f.d.0.1.0.0.2.origin.asn.cymru.com"},
		{"2001:4860::1", "0.0.0.0.0.6.8.4.1.0.0.2.origin.asn.cymru.com"},
	}
	for _, c := range cases {
		got := asnQuery(netip.MustParseAddr(c.addr))
		if got != c.want {
			t.Errorf("asnQuery(%s):\n  got  %s\n  want %s", c.addr, got, c.want)
		}
	}
}

func TestASNQueryIPv6NibbleCount(t *testing.T) {
	// /48 = 12 half-nibbles, plus 4 suffix labels = 16 labels, i.e. 15 dots.
	q := asnQuery(netip.MustParseAddr("2a02:6b8::1:1"))
	n := 1
	for _, r := range q {
		if r == '.' {
			n++
		}
	}
	if n != 16 {
		t.Errorf("labels in %q: %d, want 16", q, n)
	}
}
