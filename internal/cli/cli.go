// Package cli parses command-line arguments (mtr/tracert compatible) and drives
// the run mode: interactive table, report or JSON.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"wtr/internal/console"
	"wtr/internal/dnsx"
	"wtr/internal/probe"
	"wtr/internal/render"
	"wtr/internal/trace"
)

// Version is the program version.
const Version = "0.1.0"

type mode int

const (
	modeInteractive mode = iota
	modeReport
	modeJSON
)

// Run is the CLI entry point. It returns the process exit code.
func Run(args []string) int {
	opts, ropts, m, target, err := parseArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "wtr: %v\n", err)
		return 2
	}

	con, err := console.Open()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wtr: консоль недоступна: %v\n", err)
		return 1
	}
	defer con.Restore()

	// Without a TTY the interactive mode makes no sense — switch to a report (like mtr).
	if m == modeInteractive && !con.IsTTY() {
		m = modeReport
		if opts.Cycles == 0 {
			opts.Cycles = 10
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The resolver lives on its own context: cancelling ctx (Ctrl+C or the end of the
	// cycles) must not abort DNS queries that are already running, otherwise the final
	// report would come out without names and ASNs.
	resCtx, resStop := context.WithCancel(context.Background())
	defer resStop()

	var res trace.Resolver
	var dns *dnsx.Resolver
	if ropts.ShowNames || ropts.ShowASN {
		dns = dnsx.New(resCtx, dnsx.Config{
			Workers:       4,
			ASNLookup:     ropts.ShowASN,
			LookupTimeout: 3 * time.Second,
			Server:        opts.DNSServer,
		})
		res = dns
	}

	opts.Target = target
	eng, err := trace.New(ctx, opts, res)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wtr: %v\n", err)
		return 1
	}
	defer eng.Close()

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		if err := eng.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "wtr: %v\n", err)
		}
	}()

	switch m {
	case modeInteractive:
		return interactive(ctx, eng, con, ropts, runDone)
	case modeJSON:
		<-runDone
		flushDNS(dns)
		data, err := render.JSON(eng.Snapshot(), true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wtr: json: %v\n", err)
			return 1
		}
		fmt.Println(string(data))
		return 0
	default:
		<-runDone
		flushDNS(dns)
		fmt.Print(render.Report(eng.Snapshot(), ropts))
		return 0
	}
}

// normalizeDNSServer turns the --dns-server value into host:port form: the standard
// port 53 is implied (as in dig/nslookup) and IPv6 addresses are wrapped in brackets.
// Without this, "-S 8.8.8.8" silently turned into a stream of failed connections and
// an empty name column in the report.
func normalizeDNSServer(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if h, p, err := net.SplitHostPort(s); err == nil && h != "" {
		port, cerr := strconv.Atoi(p)
		if cerr != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("неверный --dns-server %q: порт должен быть числом 1..65535", s)
		}
		return s, nil
	}
	if ip, err := netip.ParseAddr(s); err == nil {
		if ip.Is6() {
			return "[" + ip.String() + "]:53", nil
		}
		return ip.String() + ":53", nil
	}
	if !strings.Contains(s, ":") && !strings.ContainsAny(s, " \t") {
		return s + ":53", nil
	}
	return "", fmt.Errorf("неверный --dns-server %q: ожидается host или host:port", s)
}

// flushDNS waits for the reverse-name and ASN queues to drain before the final result
// is printed. Otherwise the report is cut off in the middle of the DNS queue and shows
// bare addresses where a name simply did not arrive in time. Time-bounded: a hanging
// DNS server must not turn `mtr -r` into an endless wait.
func flushDNS(r *dnsx.Resolver) {
	if r == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		r.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
	}
}

func interactive(ctx context.Context, eng *trace.Engine, con *console.Console, o render.Options, done <-chan struct{}) int {
	con.RawInput()
	keys := con.Keys(ctx)
	out := os.Stdout

	fmt.Fprint(out, "\x1b[2J\x1b[H\x1b[?25l") // clear the screen, hide the cursor
	defer fmt.Fprint(out, "\x1b[?25h\n")

	draw := func() {
		cols, rows := con.Size()
		fmt.Fprintf(out, "\x1b[H%s", render.Frame(eng.Snapshot(), cols, rows, o))
	}
	draw()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			draw()
			return 0
		case <-ctx.Done():
			draw()
			return 0
		case k := <-keys:
			switch k {
			case 'q', 'Q':
				return 0
			case 'n', 'N':
				o.ShowNames = !o.ShowNames
				draw()
			case 'a', 'A':
				o.ShowASN = !o.ShowASN // the ASN column appears only if the run started with --aslookup
				draw()
			case 'j', 'J':
				o.Jitter = !o.Jitter
				draw()
			}
		case <-ticker.C:
			draw()
		}
	}
}

func parseArgs(args []string) (trace.Options, render.Options, mode, string, error) {
	var (
		fam4, fam6      bool
		report, jsonOut bool
		noDNS           bool
		asLookup        bool
		jitter          bool
		wide            bool
		cycles          int
		maxHops         int
		queries         int
		payload         int
		handles         int
		interval        time.Duration
		timeout         time.Duration
		src             string
		iface           string
		dnsServer       string
		showVersion     bool
	)

	fs := flag.NewFlagSet("wtr", flag.ContinueOnError)
	fs.Usage = func() { usage(fs.Output()) }
	fs.BoolVar(&fam4, "4", false, "")
	fs.BoolVar(&fam6, "6", false, "")
	fs.BoolVar(&report, "r", false, "")
	fs.BoolVar(&report, "report", false, "")
	fs.BoolVar(&jsonOut, "json", false, "")
	fs.BoolVar(&noDNS, "n", false, "")
	fs.BoolVar(&noDNS, "no-dns", false, "")
	fs.BoolVar(&asLookup, "a", false, "")
	fs.BoolVar(&asLookup, "aslookup", false, "")
	fs.BoolVar(&jitter, "j", false, "")
	fs.BoolVar(&jitter, "jitter", false, "")
	fs.BoolVar(&wide, "w", false, "")
	fs.BoolVar(&wide, "wide", false, "")
	fs.IntVar(&cycles, "c", 0, "")
	fs.IntVar(&cycles, "cycles", 0, "")
	fs.IntVar(&maxHops, "m", 30, "")
	fs.IntVar(&maxHops, "max-hops", 30, "")
	fs.IntVar(&queries, "q", 1, "")
	fs.IntVar(&queries, "queries", 1, "")
	fs.IntVar(&payload, "p", 56, "")
	fs.IntVar(&payload, "psize", 56, "")
	fs.IntVar(&handles, "z", 0, "")
	fs.DurationVar(&interval, "i", time.Second, "")
	fs.DurationVar(&interval, "interval", time.Second, "")
	fs.DurationVar(&timeout, "t", 5*time.Second, "")
	fs.DurationVar(&timeout, "timeout", 5*time.Second, "")
	fs.StringVar(&src, "B", "", "")
	fs.StringVar(&src, "bind", "", "")
	fs.StringVar(&iface, "I", "", "")
	fs.StringVar(&iface, "interface", "", "")
	fs.StringVar(&dnsServer, "S", "", "")
	fs.StringVar(&dnsServer, "dns-server", "", "")
	fs.BoolVar(&showVersion, "version", false, "")

	if err := fs.Parse(args); err != nil {
		return trace.Options{}, render.Options{}, 0, "", err // flag has already printed the error/help text
	}
	if showVersion {
		fmt.Printf("wtr %s (Windows iphlpapi backend)\n", Version)
		return trace.Options{}, render.Options{}, 0, "", flag.ErrHelp
	}
	rest := fs.Args()
	if len(rest) == 0 {
		usage(os.Stderr)
		return trace.Options{}, render.Options{}, 0, "", errors.New("не указана цель (IP или домен)")
	}
	if len(rest) > 1 {
		return trace.Options{}, render.Options{}, 0, "", fmt.Errorf("лишние аргументы: %s", strings.Join(rest[1:], " "))
	}
	target := rest[0]

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	opt := trace.Options{
		MaxHops:       maxHops,
		Cycles:        cycles,
		QueriesPerHop: queries,
		PayloadSize:   payload,
		Interval:      interval,
		Timeout:       timeout,
		Gap:           2 * time.Millisecond, // micro-stagger of TTL probe sends inside a cycle
		DNSServer:     dnsServer,
	}
	switch {
	case fam4 && fam6:
		return opt, render.Options{}, 0, "", errors.New("-4 и -6 взаимоисключающие")
	case fam4:
		opt.Family = probe.Family4
	case fam6:
		opt.Family = probe.Family6
	}
	if src != "" {
		a, err := netip.ParseAddr(src)
		if err != nil {
			return opt, render.Options{}, 0, "", fmt.Errorf("неверный --bind %q: %w", src, err)
		}
		opt.Src = a
	}
	if iface != "" {
		idx, err := probe.InterfaceByFlag(iface)
		if err != nil {
			return opt, render.Options{}, 0, "", err
		}
		opt.IfIndex = idx
	}

	m := modeInteractive
	if report {
		m = modeReport
	}
	if jsonOut {
		m = modeJSON
	}
	if m != modeInteractive && !set["cycles"] && !set["c"] {
		opt.Cycles = 10 // same default as mtr --report
	}

	ro := render.Options{ShowNames: !noDNS, ShowASN: asLookup, Jitter: jitter, Wide: wide}

	// Range validation.
	if opt.MaxHops < 1 || opt.MaxHops > 64 {
		return opt, ro, m, target, fmt.Errorf("--max-hops/-m должен быть 1..64 (получено %d)", opt.MaxHops)
	}
	if opt.Cycles < 0 {
		return opt, ro, m, target, errors.New("--cycles/-c не может быть отрицательным")
	}
	if opt.QueriesPerHop < 1 || opt.QueriesPerHop > 16 {
		return opt, ro, m, target, fmt.Errorf("--queries/-q должен быть 1..16 (получено %d)", opt.QueriesPerHop)
	}
	if opt.PayloadSize < 14 || opt.PayloadSize > 65000 {
		return opt, ro, m, target, fmt.Errorf("-p/--psize должен быть 14..65000 байт (минимум — маркер зонда)")
	}
	ds, err := normalizeDNSServer(dnsServer)
	if err != nil {
		return opt, ro, m, target, err
	}
	opt.DNSServer = ds
	if opt.Interval < 100*time.Millisecond {
		opt.Interval = 100 * time.Millisecond
	}
	if opt.Timeout < 100*time.Millisecond {
		opt.Timeout = 100 * time.Millisecond
	}
	switch {
	case handles > 64:
		return opt, ro, m, target, errors.New("-z не может быть больше 64 ICMP-хендлов")
	case handles > 0:
		opt.Workers = handles
	default:
		// There must be enough handles for every TTL of one cycle, but without excess.
		opt.Workers = opt.MaxHops * opt.QueriesPerHop
		if opt.Workers > 24 {
			opt.Workers = 24
		}
	}
	return opt, ro, m, target, nil
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `wtr %s — трассировка маршрута для Windows без прав администратора
(бэкенд: iphlpapi IcmpSendEcho2/Icmp6SendEcho2, как у tracert.exe)

Использование: wtr [опции] <цель>

Режимы:
  (по умолчанию)     интерактивная таблица; выход — q или Ctrl+C
  -r, --report       итоговая таблица после завершения (10 циклов по умолчанию)
      --json         машинночитаемый вывод после завершения

Опции:
  -4, -6             только IPv4 / только IPv6
  -c, --cycles N     число циклов (0 = бесконечно; в TUI по умолчанию бесконечно)
  -i, --interval DUR интервал между циклами (по умолчанию 1s, минимум 100ms)
  -t, --timeout DUR  таймаут ответа на зонд (по умолчанию 5s)
  -m, --max-hops N   максимум хопов / TTL (по умолчанию 30)
  -q, --queries N    зондов на хоп за цикл (1..16)
  -p, --psize N      размер payload в байтах (14..65000)
  -z N               число параллельных ICMP-хендлов (по умолчанию = max-hops*queries, до 24)
  -B, --bind ADDR    исходный адрес зондов
  -I, --interface X  интерфейс: индекс или имя ("Ethernet", "Wi-Fi")
  -n, --no-dns       не резолвить обратные имена
  -a, --aslookup     запрашивать ASN через Team Cymru (DNS)
  -S, --dns-server H DNS-сервер для обратных имён (host:port)
  -j, --jitter       колонки джиттера вместо StDev
  -w, --wide         широкая колонка хостов в отчёте
      --version      версия
  -h, --help         эта справка

Клавиши в интерактивном режиме: q — выход, n — имена, a — ASN, j — джиттер.

Примеры:
  wtr example.com
  wtr -r -c 20 -i 500ms 8.8.8.8
  wtr --json -6 -a google.com
`, Version)
}
