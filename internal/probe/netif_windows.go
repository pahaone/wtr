//go:build windows

package probe

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// RouteInfo is the route to the target that the backends need.
type RouteInfo struct {
	IfIndex      uint32 // interface index chosen by the OS routing table
	LUID         uint64 // interface LUID: put into sin6_scope_id for Icmp6SendEcho2
	FriendlyName string // human-readable name (for the header)
}

// RouteTo determines the interface through which Windows will send packets to dst.
func RouteTo(dst netip.Addr) (RouteInfo, error) {
	sa, err := sockaddrFor(dst)
	if err != nil {
		return RouteInfo{}, err
	}
	var idx uint32
	if err := windows.GetBestInterfaceEx(sa, &idx); err != nil {
		return RouteInfo{}, fmt.Errorf("probe: GetBestInterfaceEx(%s): %w", dst, unwrapWinError(err))
	}
	info := RouteInfo{IfIndex: idx}
	if luid, name, err := interfaceLUIDAndName(idx); err == nil {
		info.LUID = luid
		info.FriendlyName = name
	} else if dst.Is6() {
		return RouteInfo{}, fmt.Errorf("probe: the LUID of interface %d was not found: %w", idx, err)
	}
	return info, nil
}

// InterfaceLUID returns the LUID of an interface by index.
func InterfaceLUID(ifIndex uint32) (uint64, error) {
	luid, _, err := interfaceLUIDAndName(ifIndex)
	return luid, err
}

// InterfaceByFlag parses the --interface value: an index or a name ("Ethernet", "Wi-Fi").
func InterfaceByFlag(s string) (uint32, error) {
	if idx, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(idx), nil
	}
	iface, err := net.InterfaceByName(s)
	if err != nil {
		return 0, fmt.Errorf("probe: unknown interface %q: %w", s, err)
	}
	return uint32(iface.Index), nil
}

func interfaceLUIDAndName(ifIndex uint32) (uint64, string, error) {
	const flags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(16 * 1024)
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.ERROR_BUFFER_OVERFLOW {
				continue // size has been updated with the real requirement — retry
			}
			return 0, "", unwrapWinError(err)
		}
		for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
			if a.IfIndex == ifIndex {
				runtime.KeepAlive(buf)
				return a.Luid, windows.UTF16PtrToString(a.FriendlyName), nil
			}
		}
		runtime.KeepAlive(buf)
		return 0, "", fmt.Errorf("interface %d not found", ifIndex)
	}
	return 0, "", fmt.Errorf("GetAdaptersAddresses: buffer too small")
}

// sockaddrFor builds a Sockaddr for GetBestInterfaceEx.
func sockaddrFor(dst netip.Addr) (windows.Sockaddr, error) {
	if dst.Is4() || dst.Is4In6() {
		var sa windows.SockaddrInet4
		copy(sa.Addr[:], dst.AsSlice())
		return &sa, nil
	}
	if !dst.Is6() {
		return nil, fmt.Errorf("probe: invalid address %s", dst)
	}
	sa := &windows.SockaddrInet6{}
	copy(sa.Addr[:], dst.AsSlice())
	if zone := dst.Zone(); zone != "" {
		if z, err := strconv.ParseUint(zone, 10, 32); err == nil {
			sa.ZoneId = uint32(z)
		} else if iface, err := net.InterfaceByName(zone); err == nil {
			sa.ZoneId = uint32(iface.Index)
		}
	}
	return sa, nil
}

func unwrapWinError(err error) error {
	if errno, ok := err.(syscall.Errno); ok {
		return &APIError{Proc: "iphlpapi", Code: uint32(errno)}
	}
	return err
}
