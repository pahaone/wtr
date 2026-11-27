package stats

import (
	"math"
	"testing"
	"time"
)

func approx(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-6 {
		t.Errorf("%s = %.6f, хотим %.6f", name, got, want)
	}
}

func TestLossAndRTTAggregates(t *testing.T) {
	var h Hop
	rtts := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond}
	for _, r := range rtts {
		h.Add(r, true)
	}
	h.Add(0, false) // a loss (timeout)
	s := h.Snapshot()

	if s.Sent != 4 || s.Lost != 1 {
		t.Fatalf("sent/lost = %d/%d, хотим 4/1", s.Sent, s.Lost)
	}
	approx(t, "LossP", s.LossP, 25.0)
	approx(t, "LastMS", s.LastMS, 30.0)
	approx(t, "BestMS", s.BestMS, 10.0)
	approx(t, "WrstMS", s.WrstMS, 30.0)
	approx(t, "AvgMS", s.AvgMS, 20.0)
}

func TestStDevMatchesSampleFormula(t *testing.T) {
	var h Hop
	vals := []float64{2, 4, 4, 4, 5, 5, 7, 9} // classic example: sample standard deviation = 2.138…
	for _, v := range vals {
		h.Add(time.Duration(v*float64(time.Millisecond)), true)
	}
	s := h.Snapshot()
	// The sample (n-1) standard deviation of this set equals sqrt(32/7).
	approx(t, "StDev", s.StDev, math.Sqrt(32.0/7.0))
}

func TestJitter(t *testing.T) {
	var h Hop
	// 10 -> 20 (+10), 20 -> 15 (-5 => 5), 15 -> 25 (+10): average jitter = 25/3.
	for _, ms := range []int{10, 20, 15, 25} {
		h.Add(time.Duration(ms)*time.Millisecond, true)
	}
	s := h.Snapshot()
	approx(t, "JitterMS", s.JitterMS, 10.0) // last |25-15|
	approx(t, "AvgJitterMS", s.AvgJitterMS, 25.0/3.0)
	approx(t, "MaxJitterMS", s.MaxJitterMS, 10.0)
}

func TestEmptyAndAllLost(t *testing.T) {
	var empty Hop
	s := empty.Snapshot()
	if s.Sent != 0 || s.LossP != 0 || s.StDev != 0 {
		t.Fatalf("пустой хоп дал %+v", s)
	}
	if empty.HasData() {
		t.Fatal("HasData на пустом хопе должен быть false")
	}

	var lost Hop
	for i := 0; i < 3; i++ {
		lost.Add(0, false)
	}
	s = lost.Snapshot()
	if s.LossP != 100 || lost.HasData() {
		t.Fatalf("все потеряны: %+v", s)
	}
}
