# wtr (windows traceroute) — a traceroute for Windows that needs no administrator rights

[Русская версия](README_ru.md)

A [`mtr`](https://github.com/traviscross/mtr) clone for Windows: an interactive table of
loss and RTT per hop, plus report and JSON modes. It works **without administrator** rights
and without third-party drivers — on the same APIs as the system `tracert.exe`.

```
wtr · windows traceroute (iphlpapi)   27 Nov 2026 12:11:23
1.1.1.1  via Ethernet (if 17)
H   Host                                            AS  %Loss  Drop  Sent   Last    Avg
1   192.168.1.254                                    ?    0.0     0     2    0.4     0.4
2   ???                                              ?  100.0     2     2       -       -
3   178.218.106.76                             AS49350    0.0     0     2    1.9     1.9
4   vas-cr12-eth-trunk29.4014.kna.mts-intern... AS8359    0.0     0     2    1.9     3.5
5   push-cr11-eth-trunk1.khb.mts-internet.net   AS8359    0.0     0     2    6.9     7.3
Keys: q — exit · n — names · a — ASN · j — jitter
```

## Build

Go 1.21+ and Windows 10/11 are required (the only dependency is `golang.org/x/sys`).

```powershell
go build -o wtr.exe .\cmd\wtr
go test .\cmd\... .\internal\...   # unit tests, no network access needed
```

## Quick start

```powershell
.\wtr.exe example.com                    # interactive table, q to quit
.\wtr.exe -r -c 20 -i 500ms 8.8.8.8      # final report (mtr --report)
.\wtr.exe --json 1.1.1.1                 # machine-readable output
.\wtr.exe -r -c 5 -a -S 8.8.8.8 8.8.8.8  # with ASN (Team Cymru) via an external DNS
.\wtr.exe -6 google.com                  # IPv6 only
.\wtr.exe -r 192.168.1.254 | tee lan.txt # switches to the report on its own without a TTY
```

## Modes

| Mode | How to run | What it does |
|---|---|---|
| Interactive | default | redraws the table, keys `q` `n` `a` `j` |
| Report | `-r`, `--report` | a single table after all cycles (10 by default) |
| JSON | `--json` | a `wtr/1` document after all cycles |

When standard output is not a console (a redirect, `| tee`), the interactive mode makes no
sense — the program switches to the report on its own, exactly like `mtr` does.

## Flags

| Flag | Meaning |
|---|---|
| `-4`, `-6` | IPv4 only / IPv6 only (mutually exclusive) |
| `-c`, `--cycles N` | number of cycles; `0` = infinite (the default in the TUI), the report defaults to 10 |
| `-i`, `--interval DUR` | interval between cycles (default `1s`, minimum `100ms`) |
| `-t`, `--timeout DUR` | per-probe reply timeout (default `5s`, minimum `100ms`) |
| `-m`, `--max-hops N` | maximum TTL (default 30, range 1..64) |
| `-q`, `--queries N` | probes per hop per cycle (1..16) |
| `-p`, `--psize N` | payload size (14..65000 bytes) |
| `-z N` | parallel ICMP handles (default `max-hops*queries`, no more than 24; ceiling 64) |
| `-B`, `--bind ADDR` | source address of the probes |
| `-I`, `--interface X` | interface: an index (`17`) or a name (`Ethernet`, `Wi-Fi`) |
| `-n`, `--no-dns` | do not resolve reverse names (DNS is not started at all) |
| `-a`, `--aslookup` | request the ASN via Team Cymru (TXT queries) |
| `-S`, `--dns-server H` | DNS server for names and ASN; port `53` is appended when omitted |
| `-j`, `--jitter` | `Jit`/`AvgJ`/`MxJ` columns instead of `StDev` |
| `-w`, `--wide` | wide host column in the report (60 instead of 40) |
| `--version`, `-h`, `--help` | version, help |

Keys in the TUI: `q` — quit, `n` — show/hide names, `a` — the `AS` column
(ASN values are collected only when started with `-a`), `j` — jitter.

Exit codes: `0` — success (including `--help`/`--version`), `1` — execution error
(no route, handle could not be opened), `2` — an error in the arguments.

Note: the program's runtime messages (help, errors, hints) are always in English, like
this documentation; [README_ru.md](README_ru.md) is only its translation.

## How it works without administrator rights

The only backend is `iphlpapi.dll`: `IcmpSendEcho2` (IPv4) and `Icmp6SendEcho2`
(IPv6). They work from an ordinary user account, unlike raw sockets
(`SOCK_RAW` + `IPPROTO_ICMP`), which require administrator rights.

The empirically verified details the implementation relies on (pinned by the test
`internal/probe/layout_windows_test.go`):

* `IcmpSendEcho2` **reorders the octets itself** in the `Address` field of the reply
  record: the DWORD is read as little-endian, otherwise `192.168.1.254` turns into
  `254.1.168.192` and router replies get discarded as foreign.
* In the IPv6 buffer the replier's address starts at the 6th byte, while `Status` and
  `RoundTripTime` are read from offsets 28/32; if there is an unrecognised code and 26/30
  holds a known one, the 26/30 variant is taken (see `parseV6StatusRTT`).
* RTT from the API is quantised to 1 ms, so the difference of `QueryPerformanceCounter`
  around the call is used for display instead (`internal/probe/clock_windows.go`).

The other decisions that affect accuracy:

* **Probe marker** (`WTR1` + cycle + TTL + sequence number) in the payload. In iphlpapi
  there is nothing else to match a reply with a request, so "late" replies of a previous
  cycle are rejected and do not spoil the statistics (see the `Drop` column and
  `stale_dropped`).
* **A 2 ms micro-pause** between sending neighbouring TTLs inside a cycle: without it the
  burst of probes provokes ICMP rate-limiting on routers, and the loss on distant hops
  turns out higher than the real one.
* **A separate ICMP handle per worker**: `IcmpSendEcho2` calls are blocking, so parallelism
  is achieved by a set of handles rather than by goroutines on top of a single one.
* **Asynchronous DNS**: the engine only enqueues addresses and reads the cache, so
  resolving does not slow the probing cycle down. Before printing the result the queue is
  awaited (for no longer than 4 s) — otherwise the report comes out with bare addresses.
* **Route length** = the smallest TTL from which the target answered in the current cycle.
  The maximum cannot be used: the target also answers at inflated TTLs, so tracerouting the
  local gateway would show 30 hops instead of one. Hops beyond the target are hidden.
* **ECMP**: when several addresses answer at one TTL, the most frequent one is shown, the
  others are marked with ` +N`.

## Limitations

* **ICMP echo only.** `mtr --tcp/--udp` requires raw sockets, i.e. administrator rights;
  targets that answer only to TCP are invisible to this backend.
* **Silent routers.** Nodes that do not answer ICMP (or answer with rate-limiting) stay as
  `???` with losses — that is a property of the network, not of the implementation.
* **ASN needs a "proper" DNS.** Home routers often refuse TXT queries to
  `origin.asn.cymru.com` (`Query refused`), so `-a` requires a public resolver:
  `-a -S 8.8.8.8`.
* **Private addresses (RFC1918) do not resolve in Team Cymru** — the `AS` column of local
  hops will show `?`.
* **IPv6 is bound to an interface** (the LUID from iphlpapi is needed). If the host has no
  IPv6, `GetBestInterfaceEx` returns `ERROR_NETWORK_UNREACHABLE` and the program honestly
  reports that no route was found.
* RTT is the blocking time of the iphlpapi call; it includes goroutine scheduling. For a
  LAN it is a fraction of a millisecond, but the values are slightly higher than `tracert`'s.
* Not implemented: `--split`/`--csv`, `--grpc`, interface enumeration (`--list`).

## JSON format

```json
{
  "schema": "wtr/1",
  "program": "wtr",
  "backend": "iphlpapi",
  "start": "2026-11-27T12:08:48+10:00",
  "duration_ms": 460.2,
  "cycles": 1,
  "reached_target": true,
  "target": {"name": "dns.google", "addr": "8.8.8.8", "family": "ipv4"},
  "interface": {"name": "Ethernet", "index": 17},
  "hops": [{
    "ttl": 3,
    "addrs": ["178.218.106.76"],
    "names": ["178.218.106.76-static.dsl-online.example.net"],
    "asns": ["AS49350"],
    "flags": ["!H"],
    "status": 11013,
    "status_name": "IP_TTL_EXPIRED_TRANSIT",
    "pending": false,
    "stats": {"sent": 2, "lost": 0, "loss_pct": 0, "last_ms": 1.9, "avg_ms": 1.9,
               "best_ms": 1.7, "worst_ms": 2.1, "stdev_ms": 0.3,
               "jitter_last_ms": 0, "jitter_avg_ms": 0.1, "jitter_max_ms": 0.2}
  }],
  "stale_dropped": 0
}
```

`pending: true` means that this TTL has not received a single reply yet (such a hop is
shown with dashes in the table). `flags` are mtr-style markers: `!H` host unreachable,
`!N` network unreachable, `!X` port unreachable, `!?` another error.

## Project layout

```
cmd/wtr              entry point
internal/cli         argument parsing, mode selection, output loop
internal/trace       engine: growing TTL, workers, aggregation, state snapshots
internal/probe       iphlpapi: handles, struct layouts, status codes
internal/stats       per-hop statistics accumulator (Welford, RFC 3393 jitter)
internal/dnsx        asynchronous PTR and ASN (Team Cymru)
internal/render      TUI table, report, JSON
internal/console     console VT mode, window size, key reading
```

## Tests

```powershell
go test .\cmd\... .\internal\...
```

What is checked without the network: the iphlpapi layouts and byte order, the status codes
and the rejection of "late" replies, the probe marker, the standard deviation formula and
the jitter aggregation, the engine behaviour (reaching the target, cutting off the hops
beyond the target, accounting for losses and stale replies), the argument parsing, the
`--dns-server` normalization, the formatting of the table, the report, the JSON and the
Team Cymru names.

Verified on a live network (Windows 11, ISP MTS): IPv4 to the internet (13 hops to
`8.8.8.8`), the local gateway (1 hop), an unreachable target (`192.0.2.1` — losses without
a false "reached"), the TUI/report/JSON modes, names and ASN via `-S 8.8.8.8`, the switch to
report mode when the output is redirected, the exit codes.

**Not** verified on a live network: IPv6 (the test machine had no connectivity — the
implementation relies on the verified layouts and `Icmp6SendEcho2`), handling of `Ctrl+C` in
the TUI (it does not reproduce in a non-interactive session), `--bind` on multi-homed
machines.

The `-race` flag requires `cgo` (`CGO_ENABLED=1` and a C compiler); without it concurrency
is held by the engine mutexes and is checked by the engine tests.

