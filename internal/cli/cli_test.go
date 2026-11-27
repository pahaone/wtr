package cli

import (
	"flag"
	"net/netip"
	"testing"
	"time"

	"wtr/internal/probe"
)

func TestNormalizeDNSServer(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"8.8.8.8", "8.8.8.8:53", false},
		{"8.8.8.8:5353", "8.8.8.8:5353", false},
		{"  1.1.1.1  ", "1.1.1.1:53", false},
		{"dns.example.com", "dns.example.com:53", false},
		{"dns.example.com:5353", "dns.example.com:5353", false},
		{"::1", "[::1]:53", false},
		{"2606:4700:4700::1111", "[2606:4700:4700::1111]:53", false},
		{"[::1]:53", "[::1]:53", false},
		{"8.8.8.8:notaport", "", true},
		{"bad host name", "", true},
	}
	for _, c := range cases {
		got, err := normalizeDNSServer(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("normalizeDNSServer(%q): ошибка %v, хотим ошибку=%v", c.in, err, c.wantErr)
			continue
		}
		if err == nil && got != c.want {
			t.Errorf("normalizeDNSServer(%q) = %q, хотим %q", c.in, got, c.want)
		}
	}
}

func TestParseArgsDefaults(t *testing.T) {
	opt, ro, m, target, err := parseArgs([]string{"example.com"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if target != "example.com" || m != modeInteractive {
		t.Errorf("target=%q mode=%d, хотим example.com и интерактив", target, m)
	}
	if opt.MaxHops != 30 || opt.QueriesPerHop != 1 || opt.PayloadSize != 56 {
		t.Errorf("hop/queries/payload = %d/%d/%d", opt.MaxHops, opt.QueriesPerHop, opt.PayloadSize)
	}
	if opt.Interval != time.Second || opt.Timeout != 5*time.Second {
		t.Errorf("interval/timeout = %v/%v", opt.Interval, opt.Timeout)
	}
	if opt.Gap <= 0 {
		t.Error("Gap должен задаваться: без микропаузы роутеры режут ICMP по rate-limit'у")
	}
	if opt.Cycles != 0 {
		t.Errorf("в TUI циклы должны быть бесконечными, получили %d", opt.Cycles)
	}
	if opt.Workers < 1 || opt.Workers > 24 {
		t.Errorf("Workers=%d вне диапазона", opt.Workers)
	}
	if !ro.ShowNames || ro.ShowASN || ro.Jitter {
		t.Errorf("настройки вывода по умолчанию: %+v", ro)
	}
}

func TestParseArgsReportMode(t *testing.T) {
	opt, _, m, target, err := parseArgs([]string{"-r", "-c", "5", "-i", "200ms", "-t", "1s", "8.8.8.8"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if m != modeReport || target != "8.8.8.8" {
		t.Errorf("mode=%d target=%q", m, target)
	}
	if opt.Cycles != 5 || opt.Interval != 200*time.Millisecond || opt.Timeout != time.Second {
		t.Errorf("cycles/interval/timeout = %d/%v/%v", opt.Cycles, opt.Interval, opt.Timeout)
	}
}

// Without -c, report mode must run 10 cycles, like mtr --report.
func TestParseArgsReportDefaultCycles(t *testing.T) {
	opt, _, _, _, err := parseArgs([]string{"--report", "1.1.1.1"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if opt.Cycles != 10 {
		t.Errorf("Cycles=%d, хотим 10", opt.Cycles)
	}
}

func TestParseArgsJSONAndToggles(t *testing.T) {
	_, ro, m, _, err := parseArgs([]string{"--json", "-j", "-w", "-a", "-n", "1.1.1.1"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if m != modeJSON {
		t.Errorf("mode=%d, хотим JSON", m)
	}
	if !ro.Jitter || !ro.Wide || !ro.ShowASN {
		t.Errorf("флаги не применены: %+v", ro)
	}
	if ro.ShowNames {
		t.Error("-n должен отключать обратные имена")
	}
}

func TestParseArgsFamilyAndBind(t *testing.T) {
	opt, _, _, _, err := parseArgs([]string{"-4", "-B", "192.168.1.10", "8.8.8.8"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if opt.Family != probe.Family4 {
		t.Errorf("Family=%v, хотим ipv4", opt.Family)
	}
	if opt.Src != netip.MustParseAddr("192.168.1.10") {
		t.Errorf("Src=%s", opt.Src)
	}
	if _, _, _, _, err := parseArgs([]string{"-6", "google.com"}); err != nil {
		t.Errorf("-6: %v", err)
	}
	if _, _, _, _, err := parseArgs([]string{"-4", "-6", "8.8.8.8"}); err == nil {
		t.Error("-4 и -6 должны конфликтовать")
	}
}

func TestParseArgsDNSServerNormalized(t *testing.T) {
	opt, _, _, _, err := parseArgs([]string{"-S", "8.8.8.8", "8.8.8.8"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if opt.DNSServer != "8.8.8.8:53" {
		t.Errorf("DNSServer=%q, хотим 8.8.8.8:53", opt.DNSServer)
	}
	if _, _, _, _, err := parseArgs([]string{"-S", "плохой сервер", "8.8.8.8"}); err == nil {
		t.Error("некорректный --dns-server должен быть ошибкой")
	}
}

func TestParseArgsValidation(t *testing.T) {
	bad := [][]string{
		{"-m", "0", "8.8.8.8"},
		{"-m", "65", "8.8.8.8"},
		{"-q", "0", "8.8.8.8"},
		{"-q", "17", "8.8.8.8"},
		{"-p", "5", "8.8.8.8"},
		{"-c", "-1", "8.8.8.8"},
		{"-B", "не-ip", "8.8.8.8"},
		{"-I", "ТакогоИнтерфейсаНет12345", "8.8.8.8"},
		{"-z", "99", "8.8.8.8"},
		{"8.8.8.8", "лишнее"},
	}
	for _, args := range bad {
		if _, _, _, _, err := parseArgs(args); err == nil || err == flag.ErrHelp {
			t.Errorf("parseArgs(%v): ошибка не получена (%v)", args, err)
		}
	}
}

// Timeout and interval below a sensible minimum are clamped instead of breaking probing.
func TestParseArgsClampsTimings(t *testing.T) {
	opt, _, _, _, err := parseArgs([]string{"-i", "1ms", "-t", "1us", "8.8.8.8"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if opt.Interval < 100*time.Millisecond || opt.Timeout < 100*time.Millisecond {
		t.Errorf("после зажима: interval=%v timeout=%v", opt.Interval, opt.Timeout)
	}
}

func TestParseArgsVersionIsHelp(t *testing.T) {
	if _, _, _, _, err := parseArgs([]string{"--version"}); err != flag.ErrHelp {
		t.Errorf("--version должен завершаться как справка, получили %v", err)
	}
}
