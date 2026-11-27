//go:build windows

package probe

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	modkernel32     = syscall.NewLazyDLL("kernel32.dll")
	procQPC         = modkernel32.NewProc("QueryPerformanceCounter")
	procQPFrequency = modkernel32.NewProc("QueryPerformanceFrequency")
)

// qpcTicks returns the current value of QueryPerformanceCounter.
//
// Deltas are computed in ticks and only then converted into a duration, so no precision is
// lost at large counter values.
//
// Why this is needed: on the machine under test, Go's monotonic clock (time.Now) is
// quantised to a ~0.5 ms step, which would make LAN hop RTTs look like 0.0 ms. QPC gives ~100 ns.
func qpcTicks() int64 {
	var c int64
	procQPC.Call(uintptr(unsafe.Pointer(&c)))
	return c
}

// qpcScale is the "tick -> nanosecond" multiplier, computed once at process start.
var qpcScale = func() float64 {
	var f int64
	procQPFrequency.Call(uintptr(unsafe.Pointer(&f)))
	if f <= 0 {
		f = 10_000_000 // typical QPC frequency if the query somehow failed
	}
	return float64(time.Second) / float64(f)
}()

func ticksToDuration(d int64) time.Duration {
	return time.Duration(float64(d) * qpcScale)
}
