package trace

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"wtr/internal/probe"
)

// ResolveTarget turns an IP literal or a domain name into a target address.
// With fam == 0 IPv4 is preferred (like mtr's default), IPv6 is used only when the
// AAAA record is the sole one.
func ResolveTarget(ctx context.Context, target string, fam probe.Family) (netip.Addr, error) {
	if target == "" {
		return netip.Addr{}, fmt.Errorf("trace: empty target")
	}
	if ip, err := netip.ParseAddr(target); err == nil {
		switch fam {
		case probe.Family4:
			if !ip.Is4() && !ip.Is4In6() {
				return netip.Addr{}, fmt.Errorf("%s is not IPv4 (use -6 or drop -4)", target)
			}
		case probe.Family6:
			if !ip.Is6() || ip.Is4In6() {
				return netip.Addr{}, fmt.Errorf("%s is not IPv6", target)
			}
		}
		return ip, nil
	}

	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip", target)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to resolve %q: %w", target, err)
	}
	var v4, v6 netip.Addr
	for _, a := range addrs {
		na, ok := netip.AddrFromSlice(a)
		if !ok {
			continue
		}
		na = na.Unmap()
		if na.Is4() && !v4.IsValid() {
			v4 = na
		} else if na.Is6() && !v6.IsValid() {
			v6 = na
		}
	}
	switch fam {
	case probe.Family4:
		if v4.IsValid() {
			return v4, nil
		}
		return netip.Addr{}, fmt.Errorf("%q has no A record (IPv4)", target)
	case probe.Family6:
		if v6.IsValid() {
			return v6, nil
		}
		return netip.Addr{}, fmt.Errorf("%q has no AAAA record (IPv6)", target)
	default:
		if v4.IsValid() {
			return v4, nil
		}
		if v6.IsValid() {
			return v6, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%q has no usable address records", target)
}

func familyOf(a netip.Addr) probe.Family {
	if a.Is4() || a.Is4In6() {
		return probe.Family4
	}
	return probe.Family6
}
