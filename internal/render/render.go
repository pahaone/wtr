// Package render turns a traceroute snapshot into output: the interactive table,
// an mtr --report style report and JSON.
package render

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"wtr/internal/probe"
	"wtr/internal/stats"
	"wtr/internal/trace"
)

// Options controls what the tables show.
type Options struct {
	ShowNames bool
	ShowASN   bool
	Jitter    bool // show Jit/AvgJ/MxJ instead of StDev
	Wide      bool
}

// colSpec is the header and the width of a numeric table column.
type colSpec struct {
	head string
	w    int
}

// asnCell is the AS column cell: "?" means the ASN was not requested or has not been
// resolved yet (ASN data is collected only when running with --aslookup).
func asnCell(h trace.HopView) string {
	if len(h.Asns) > 0 && h.Asns[0] != "" {
		return h.Asns[0]
	}
	return "?"
}

// hostCell builds the "Host" cell: name (address) + error flags.
func hostCell(h trace.HopView, o Options) string {
	var b strings.Builder
	addr := netip.Addr{}
	if len(h.Addrs) > 0 {
		addr = h.Addrs[0]
	}
	name := ""
	if len(h.Names) > 0 {
		name = h.Names[0]
	}
	switch {
	case !addr.IsValid():
		b.WriteString("???")
	case o.ShowNames && name != "":
		fmt.Fprintf(&b, "%s (%s)", name, addr)
	default:
		b.WriteString(addr.String())
	}
	if len(h.Addrs) > 1 {
		fmt.Fprintf(&b, " +%d", len(h.Addrs)-1)
	}
	for _, f := range h.Flags {
		fmt.Fprintf(&b, " %s", f)
	}
	return b.String()
}

// Frame draws one frame of the interactive mode: only the line contents, without cursor
// control (the caller handles that). Blank lines are not padded up to rows.
func Frame(v trace.View, cols, rows int, o Options) string {
	if cols < 40 {
		cols = 40
	}
	var b strings.Builder

	// Header.
	host := v.Target.String()
	if v.TargetName != "" && o.ShowNames {
		host = fmt.Sprintf("%s (%s)", v.TargetName, v.Target)
	}
	sent, lost := 0, 0
	for _, h := range v.Hops {
		sent += h.Snap.Sent
		lost += h.Snap.Lost
	}
	title := fmt.Sprintf("wtr · windows traceroute (iphlpapi)   %s", time.Now().Format("02 Jan 2006 15:04:05"))
	sub := fmt.Sprintf("%s  via %s (if %d)", host, orNone(v.Iface), v.IfIndex)
	right := fmt.Sprintf("cycle=%d sent=%d lost=%d", v.Cycle, sent, lost)
	fmt.Fprintf(&b, "%-*s\n", cols, truncate(title, cols))
	if len(sub)+len(right)+1 <= cols {
		fmt.Fprintf(&b, "%s%s\n", sub, strings.Repeat(" ", cols-len(sub)-len(right)))
	} else {
		fmt.Fprintf(&b, "%s\n", truncate(sub, cols))
	}

	// Numeric columns.
	numCols := []colSpec{
		{"%Loss", 6}, {"Drop", 5}, {"Sent", 5}, {"Last", 7}, {"Avg", 7}, {"Best", 7}, {"Wrst", 7},
	}
	if o.ShowASN {
		// Like in mtr: AS goes right after the host.
		numCols = append([]colSpec{{"AS", 11}}, numCols...)
	}
	if o.Jitter {
		numCols = append(numCols, colSpec{"Jit", 6}, colSpec{"AvgJ", 6}, colSpec{"MxJ", 6})
	} else {
		numCols = append(numCols, colSpec{"StDev", 7})
	}
	hostW := cols - 4 // "H   "
	for _, c := range numCols {
		hostW -= c.w + 1
	}
	if hostW < 12 {
		hostW = 12
	}

	var head strings.Builder
	head.WriteString("H   ")
	fmt.Fprintf(&head, "%-*s", hostW, "Host")
	for _, c := range numCols {
		fmt.Fprintf(&head, " %*s", c.w, c.head)
	}
	fmt.Fprintf(&b, "%s\n", truncate(head.String(), cols))

	// Hop rows: as many as fit into the window.
	avail := rows - 4 // header(2) + column titles(1) + hint(1)
	if avail < 1 {
		avail = 1
	}
	shown := v.Hops
	truncated := false
	if len(shown) > avail {
		shown = shown[:avail]
		truncated = true
	}
	for _, h := range shown {
		var row strings.Builder
		fmt.Fprintf(&row, "%-2d  ", h.TTL)
		fmt.Fprintf(&row, "%-*s", hostW, truncate(hostCell(h, o), hostW))
		s := h.Snap
		cells := make([]string, 0, len(numCols))
		if o.ShowASN {
			cells = append(cells, asnCell(h))
		}
		cells = append(cells,
			fmt.Sprintf("%.1f", s.LossP),
			fmt.Sprintf("%d", s.Lost),
			fmt.Sprintf("%d", s.Sent),
			rttCell(s.LastMS, h.Pending),
			rttCell(s.AvgMS, h.Pending),
			rttCell(s.BestMS, h.Pending),
			rttCell(s.WrstMS, h.Pending),
		)
		if o.Jitter {
			cells = append(cells, devCell(s.JitterMS, h.Pending), devCell(s.AvgJitterMS, h.Pending), devCell(s.MaxJitterMS, h.Pending))
		} else {
			cells = append(cells, devCell(s.StDev, h.Pending))
		}
		for i, c := range cells {
			fmt.Fprintf(&row, " %*s", numCols[i].w, c)
		}
		fmt.Fprintf(&b, "%s\n", truncate(row.String(), cols))
	}
	if truncated {
		fmt.Fprintf(&b, "     … %d more hops (widen the window or lower --max-hops)\n", len(v.Hops)-avail)
	}

	hint := "Keys: q — exit · n — names · a — ASN · j — jitter"
	if !o.ShowASN {
		hint = "Keys: q — exit · n — names · j — jitter (ASN: start with --aslookup)"
	}
	fmt.Fprintf(&b, "%s\n", truncate(hint, cols))
	return b.String()
}

// rttCell is the RTT cell: "-" when there were no replies, "<0.1" for sub-millisecond
// values (QPC distinguishes microseconds, while one digit after the point would hide LAN RTT).
func rttCell(v float64, pending bool) string {
	switch {
	case pending || v <= 0:
		return "-"
	case v < 0.1:
		return "<0.1"
	default:
		return fmt.Sprintf("%.1f", v)
	}
}

// devCell is the StDev/jitter cell: zero is legitimate here, so "-" only appears when there is no data.
func devCell(v float64, pending bool) string {
	if pending {
		return "-"
	}
	return fmt.Sprintf("%.1f", v)
}

func orNone(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

// truncate cuts a string by runes, leaving room for "…" (does it account for ANSI? — no,
// no control sequences are generated here).
func truncate(s string, w int) string {
	if w <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	if w == 1 {
		return "…"
	}
	return string(r[:w-1]) + "…"
}

// Report prints the result in mtr --report style.
func Report(v trace.View, o Options) string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "local"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Start: %s\n", v.Started.Format(time.RFC3339))
	head := fmt.Sprintf("HOSTS: %-24s", truncate(hostname, 24))
	cols := []colSpec{
		{"Loss%", 7}, {"Snt", 5}, {"Last", 6}, {"Avg", 6}, {"Best", 6}, {"Wrst", 6}, {"StDev", 6},
	}
	if o.Jitter {
		cols = append(cols, colSpec{"Jit", 6}, colSpec{"AvgJ", 6}, colSpec{"MxJ", 6})
	}
	hostW := 40
	if o.Wide {
		hostW = 60
	}
	for _, c := range cols {
		head += fmt.Sprintf("%*s", c.w, c.head)
	}
	fmt.Fprintf(&b, "%s\n", head)

	for _, h := range v.Hops {
		cell := truncate(hostCell(h, o), hostW)
		fmt.Fprintf(&b, "%3d.|-- %-*s", h.TTL, hostW+2, cell)
		s := h.Snap
		vals := []string{
			fmt.Sprintf("%.1f%%", s.LossP),
			fmt.Sprintf("%d", s.Sent),
			rttCell(s.LastMS, h.Pending),
			rttCell(s.AvgMS, h.Pending),
			rttCell(s.BestMS, h.Pending),
			rttCell(s.WrstMS, h.Pending),
			devCell(s.StDev, h.Pending),
		}
		if o.Jitter {
			vals = append(vals, devCell(s.JitterMS, h.Pending), devCell(s.AvgJitterMS, h.Pending), devCell(s.MaxJitterMS, h.Pending))
		}
		for i, val := range vals {
			fmt.Fprintf(&b, "%*s", cols[i].w, val)
		}
		fmt.Fprintln(&b)
	}
	return b.String()
}

// --- JSON -------------------------------------------------------------

type jsonHop struct {
	TTL        int            `json:"ttl"`
	Addrs      []string       `json:"addrs"`
	Names      []string       `json:"names"`
	ASNs       []string       `json:"asns,omitempty"`
	Flags      []string       `json:"flags,omitempty"`
	Status     uint32         `json:"status"`
	StatusName string         `json:"status_name"`
	Pending    bool           `json:"pending"`
	Stats      stats.Snapshot `json:"stats"`
}

type jsonDoc struct {
	Schema   string    `json:"schema"`
	Program  string    `json:"program"`
	Backend  string    `json:"backend"`
	Start    time.Time `json:"start"`
	Duration float64   `json:"duration_ms"`
	Cycles   int       `json:"cycles"`
	Reached  bool      `json:"reached_target"`
	Target   struct {
		Name string `json:"name,omitempty"`
		Addr string `json:"addr"`
		Fam  string `json:"family"`
	} `json:"target"`
	Iface struct {
		Name  string `json:"name,omitempty"`
		Index uint32 `json:"index,omitempty"`
	} `json:"interface,omitempty"`
	Hops         []jsonHop `json:"hops"`
	StaleDropped int64     `json:"stale_dropped,omitempty"`
}

// JSON serialises the snapshot (indent — human-readable output).
func JSON(v trace.View, indent bool) ([]byte, error) {
	doc := jsonDoc{
		Schema:       "wtr/1",
		Program:      "wtr",
		Backend:      "iphlpapi",
		Start:        v.Started,
		Duration:     float64(v.Elapsed) / 1e6,
		Cycles:       v.Cycle,
		Reached:      v.Reached,
		StaleDropped: v.StaleDropped,
	}
	doc.Target.Name = v.TargetName
	doc.Target.Addr = v.Target.String()
	doc.Target.Fam = probe.Family(v.Family).String()
	doc.Iface.Name = v.Iface
	doc.Iface.Index = v.IfIndex
	for _, h := range v.Hops {
		jh := jsonHop{
			TTL:        h.TTL,
			Addrs:      make([]string, 0, len(h.Addrs)),
			Names:      h.Names,
			ASNs:       h.Asns,
			Flags:      h.Flags,
			Status:     h.Status,
			StatusName: probe.StatusName(h.Status),
			Pending:    h.Pending,
			Stats:      h.Snap,
		}
		for _, a := range h.Addrs {
			jh.Addrs = append(jh.Addrs, a.String())
		}
		doc.Hops = append(doc.Hops, jh)
	}
	if indent {
		return json.MarshalIndent(doc, "", "  ")
	}
	return json.Marshal(doc)
}
