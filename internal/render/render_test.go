package render

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"wtr/internal/probe"
	"wtr/internal/stats"
	"wtr/internal/trace"
)

func sampleView() trace.View {
	mk := func(ttl int, addr, name string, rtts []time.Duration, lost int) trace.HopView {
		var h stats.Hop
		for _, r := range rtts {
			h.Add(r, true)
		}
		for i := 0; i < lost; i++ {
			h.Add(0, false)
		}
		hv := trace.HopView{
			TTL:   ttl,
			Snap:  h.Snapshot(),
			Addrs: []netip.Addr{netip.MustParseAddr(addr)},
			Names: []string{name},
		}
		if name == "" && len(rtts) == 0 {
			hv.Pending = true
		}
		return hv
	}
	return trace.View{
		Target:     netip.MustParseAddr("93.184.216.34"),
		TargetName: "example.com",
		Family:     probe.Family4,
		Iface:      "Ethernet",
		IfIndex:    12,
		Cycle:      3,
		Reached:    true,
		Started:    time.Now().Add(-3 * time.Second),
		Elapsed:    3 * time.Second,
		Hops: []trace.HopView{
			mk(1, "192.168.1.1", "router.lan", []time.Duration{time.Millisecond, 2 * time.Millisecond}, 0),
			mk(2, "10.10.0.1", "", []time.Duration{9 * time.Millisecond}, 1),
			mk(3, "93.184.216.34", "example.com", []time.Duration{25 * time.Millisecond}, 0),
		},
	}
}

func TestFrameLayout(t *testing.T) {
	v := sampleView()
	frame := Frame(v, 110, 24, Options{ShowNames: true})

	for _, want := range []string{"%Loss", "Sent", "StDev", "example.com", "192.168.1.1", "H   "} {
		if !strings.Contains(frame, want) {
			t.Errorf("frame is missing %q:\n%s", want, frame)
		}
	}
	lines := strings.Split(strings.TrimRight(frame, "\n"), "\n")
	// 2 header lines + column titles + 3 hops + hint.
	if len(lines) != 7 {
		t.Errorf("%d lines, want 7:\n%s", len(lines), frame)
	}
	for i, l := range lines {
		if n := len([]rune(l)); n > 110 {
			t.Errorf("line %d is wider than the window: %d > 110 (%q)", i, n, l)
		}
	}
	// Without a name only the bare address must be shown.
	bare := Frame(v, 110, 24, Options{})
	if strings.Contains(bare, "router.lan") {
		t.Error("ShowNames=false but the host name leaked into the output")
	}
}

// TestFrameNarrowWindowNotBroken — in a narrow window the columns must not drift apart
// and the lines must not exceed the terminal width.
func TestFrameNarrowWindowNotBroken(t *testing.T) {
	v := sampleView()
	frame := Frame(v, 60, 24, Options{ShowNames: true})
	for i, l := range strings.Split(strings.TrimRight(frame, "\n"), "\n") {
		if n := len([]rune(l)); n > 60 {
			t.Errorf("line %d is %d wide > 60: %q", i, n, l)
		}
	}
}

// TestFrameScrolling — more hops than fit on screen: the extra ones collapse into "…".
func TestFrameScrolling(t *testing.T) {
	v := sampleView()
	v.Hops = append(v.Hops, mkHops(4, 40)...)
	frame := Frame(v, 120, 10, Options{})
	if !strings.Contains(frame, "more hops") {
		t.Errorf("no marker about the hidden hops:\n%s", frame)
	}
	if strings.Contains(frame, "39.") {
		t.Error("all hops were printed into a 10-line window")
	}
}

func mkHops(from, n int) []trace.HopView {
	out := make([]trace.HopView, 0, n)
	for i := 0; i < n; i++ {
		var h stats.Hop
		h.Add(time.Duration(from+i)*time.Millisecond, true)
		out = append(out, trace.HopView{
			TTL:   from + i,
			Snap:  h.Snapshot(),
			Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")},
			Names: []string{""},
		})
	}
	return out
}

func TestReportFormat(t *testing.T) {
	v := sampleView()
	rep := Report(v, Options{ShowNames: true})
	if !strings.HasPrefix(rep, "Start: ") {
		t.Errorf("the report must start with the Start: line, got %q", firstLine(rep))
	}
	if !strings.Contains(rep, "HOSTS:") {
		t.Error("no HOSTS: line")
	}
	for _, want := range []string{"  1.|-- ", "  3.|-- ", "|-- example.com"} {
		if !strings.Contains(rep, want) {
			t.Errorf("the report is missing %q:\n%s", want, rep)
		}
	}
	// mtr-compatible loss prefix: hop2 — 1 loss out of 2 = 50.0%.
	if !strings.Contains(rep, "50.0%") {
		t.Errorf("no 50.0%% loss for hop 2:\n%s", rep)
	}
	if !strings.Contains(Report(v, Options{ShowNames: true, Wide: true}), "HOSTS:") {
		t.Error("--wide must print the report too")
	}
}

func TestJSONSchema(t *testing.T) {
	v := sampleView()
	v.StaleDropped = 2
	data, err := JSON(v, true)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc["schema"] != "wtr/1" || doc["backend"] != "iphlpapi" {
		t.Errorf("metadata: %v / %v", doc["schema"], doc["backend"])
	}
	if doc["reached_target"] != true {
		t.Error("reached_target must be true")
	}
	tgt, ok := doc["target"].(map[string]any)
	if !ok || tgt["addr"] != "93.184.216.34" || tgt["family"] != "ipv4" || tgt["name"] != "example.com" {
		t.Errorf("target = %v", doc["target"])
	}
	hops, ok := doc["hops"].([]any)
	if !ok || len(hops) != 3 {
		t.Fatalf("hops = %v", doc["hops"])
	}
	h2 := hops[1].(map[string]any)
	st := h2["stats"].(map[string]any)
	if st["sent"].(float64) != 2 || st["lost"].(float64) != 1 || st["loss_pct"] != 50.0 {
		t.Errorf("stats of hop 2: %v", st)
	}
	if h2["status_name"] == "" {
		t.Error("status_name must be filled in")
	}
	if doc["stale_dropped"].(float64) != 2 {
		t.Errorf("stale_dropped = %v", doc["stale_dropped"])
	}
}

func TestJSONNoDNSNames(t *testing.T) {
	v := sampleView()
	v.Hops[0].Names = []string{""}
	data, err := JSON(v, false)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !strings.Contains(string(data), `"addrs":["192.168.1.1"]`) {
		t.Errorf("compact JSON:\n%s", data)
	}
}

func TestFrameASNColumn(t *testing.T) {
	v := sampleView()
	v.Hops[0].Asns = []string{"AS12345"}

	on := Frame(v, 120, 24, Options{ShowNames: true, ShowASN: true})
	if !strings.Contains(on, "AS") || !strings.Contains(on, "AS12345") {
		t.Errorf("no AS column or AS12345 value:\n%s", on)
	}
	if !strings.Contains(on, "?") {
		t.Errorf("hops without ASN must show '?':\n%s", on)
	}
	if !strings.Contains(on, "a — ASN") {
		t.Error("the hint about key a must appear when ASN is enabled")
	}

	off := Frame(v, 120, 24, Options{ShowNames: true})
	if strings.Contains(off, "AS12345") {
		t.Error("ShowASN=false but ASN got into the table")
	}
	if !strings.Contains(off, "--aslookup") {
		t.Error("without ASN the hint must say how to switch it on")
	}
	for i, l := range strings.Split(strings.TrimRight(on, "\n"), "\n") {
		if n := len([]rune(l)); n > 120 {
			t.Errorf("line %d with the AS column is wider than the window: %d > 120", i, n)
		}
	}
}

func TestFrameJitterColumns(t *testing.T) {
	v := sampleView()
	f := Frame(v, 130, 24, Options{ShowNames: true, Jitter: true})
	for _, want := range []string{"Jit", "AvgJ", "MxJ"} {
		if !strings.Contains(f, want) {
			t.Errorf("no %s column:\n%s", want, f)
		}
	}
	if strings.Contains(f, "StDev") {
		t.Error("with jitter enabled there must be no StDev column")
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
