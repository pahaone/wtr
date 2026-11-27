// Package stats aggregates probe results per hop (loss, RTT, jitter).
package stats

import (
	"math"
	"time"
)

// Hop is the cumulative statistics of a single hop. It is not thread-safe: the caller
// provides synchronisation (the engine keeps a mutex around the updates).
type Hop struct {
	sent int
	lost int

	last, best, worst time.Duration

	mean float64 // nanoseconds, Welford's algorithm
	m2   float64
	n    int

	prev       time.Duration
	havePrev   bool
	jitSum     float64 // sum of |rtt_i - rtt_{i-1}| for the average jitter
	jitCount   int
	jitMax     float64
	lastJitter float64
}

// Add records a probe result. ok=false means a loss (timeout/error).
func (h *Hop) Add(rtt time.Duration, ok bool) {
	h.sent++
	if !ok || rtt <= 0 {
		h.lost++
		return
	}
	if h.n == 0 || rtt < h.best {
		h.best = rtt
	}
	if rtt > h.worst {
		h.worst = rtt
	}
	h.last = rtt

	f := float64(rtt)
	h.n++
	d := f - h.mean
	h.mean += d / float64(h.n)
	h.m2 += d * (f - h.mean)

	if h.havePrev {
		j := math.Abs(f - float64(h.prev))
		h.jitSum += j
		h.jitCount++
		if j > h.jitMax {
			h.jitMax = j
		}
		h.lastJitter = j
	}
	h.prev = rtt
	h.havePrev = true
}

// Snapshot is the statistics snapshot for the renderers/JSON (all values in milliseconds).
type Snapshot struct {
	Sent  int     `json:"sent"`
	Lost  int     `json:"lost"`
	LossP float64 `json:"loss_pct"`

	LastMS float64 `json:"last_ms"`
	AvgMS  float64 `json:"avg_ms"`
	BestMS float64 `json:"best_ms"`
	WrstMS float64 `json:"worst_ms"`
	StDev  float64 `json:"stdev_ms"`

	JitterMS    float64 `json:"jitter_last_ms"`
	AvgJitterMS float64 `json:"jitter_avg_ms"`
	MaxJitterMS float64 `json:"jitter_max_ms"`
}

// Snapshot returns the current aggregates.
func (h *Hop) Snapshot() Snapshot {
	s := Snapshot{Sent: h.sent, Lost: h.lost}
	if h.sent > 0 {
		s.LossP = 100 * float64(h.lost) / float64(h.sent)
	}
	if h.n > 0 {
		s.LastMS = ms(h.last)
		s.BestMS = ms(h.best)
		s.WrstMS = ms(h.worst)
		s.AvgMS = ms(time.Duration(h.mean))
		if h.n > 1 {
			s.StDev = math.Sqrt(h.m2/float64(h.n-1)) / 1e6
		}
	}
	if h.jitCount > 0 {
		s.JitterMS = h.lastJitter / 1e6
		s.AvgJitterMS = h.jitSum / float64(h.jitCount) / 1e6
		s.MaxJitterMS = h.jitMax / 1e6
	}
	return s
}

// Counters returns the number of probes sent and lost.
func (h *Hop) Counters() (sent, lost int) { return h.sent, h.lost }

// HasData reports whether there is at least one successful reply.
func (h *Hop) HasData() bool { return h.n > 0 }

func ms(d time.Duration) float64 { return float64(d) / 1e6 }
