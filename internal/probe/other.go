//go:build !windows

package probe

import (
	"net/netip"
	"time"
)

// Stubs for cross-compilation and unit tests on non-Windows systems: the traceroute
// itself targets iphlpapi, so this is only the minimum needed to compile.

func qpcTicks() int64 { return time.Now().UnixNano() }

func ticksToDuration(d int64) time.Duration { return time.Duration(d) }

// RouteInfo — see netif_windows.go.
type RouteInfo struct {
	IfIndex      uint32
	LUID         uint64
	FriendlyName string
}

func RouteTo(dst netip.Addr) (RouteInfo, error) { return RouteInfo{}, ErrUnsupported }

func InterfaceLUID(ifIndex uint32) (uint64, error) { return 0, ErrUnsupported }

func InterfaceByFlag(s string) (uint32, error) { return 0, ErrUnsupported }

func NewBackend(cfg Config) (Backend, error) { return nil, ErrUnsupported }
