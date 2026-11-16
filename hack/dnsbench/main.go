// Command dnsbench measures what attaching dns-auditor costs CoreDNS.
//
//	dnsbench load  -server 127.0.0.1:1053 -qps 750 -duration 30s -pid <coredns pid>
//	dnsbench stuck -addr 127.0.0.1:16000      # dnstap sink that handshakes, then never reads
//
// load sends a fixed-rate mix of queries shaped like a real ndots:5 cluster
// (mostly NXDOMAIN search-list expansions, some answered names), records
// latency and failures, samples the target process CPU and RSS from /proc,
// and prints one JSON line.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dnsbench load|stuck [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "load":
		err = load(os.Args[2:])
	case "stuck":
		err = stuck(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dnsbench:", err)
		os.Exit(1)
	}
}

type result struct {
	QPS          int     `json:"qps_target"`
	Achieved     float64 `json:"qps_achieved"`
	Sent         int     `json:"sent"`
	OK           int     `json:"ok"`
	Timeouts     int     `json:"timeouts"`
	Errors       int     `json:"errors"`
	ServFail     int     `json:"servfail"`
	P50ms        float64 `json:"p50_ms"`
	P99ms        float64 `json:"p99_ms"`
	P999ms       float64 `json:"p999_ms"`
	MaxMs        float64 `json:"max_ms"`
	CPUPercent   float64 `json:"target_cpu_percent"`
	RSSMaxMiB    float64 `json:"target_rss_max_mib"`
	RSSEndMiB    float64 `json:"target_rss_end_mib"`
	DurationSecs float64 `json:"duration_s"`
}

var namespaces = []string{"shop", "billing", "payments", "notify", "ops"}

// query returns a name shaped like real traffic: ~75% search-list NXDOMAIN,
// the rest answered.
func query(r *rand.Rand) string {
	ns := namespaces[r.IntN(len(namespaces))]
	switch r.IntN(8) {
	case 0, 1, 2:
		return fmt.Sprintf("api%d.example.com.%s.svc.cluster.local.", r.IntN(50), ns)
	case 3, 4:
		return fmt.Sprintf("api%d.example.com.svc.cluster.local.", r.IntN(50))
	case 5:
		return fmt.Sprintf("svc%d.%s.svc.cluster.local.", r.IntN(20), ns) // short-name misroute shape
	default:
		return fmt.Sprintf("api%d.example.com.", r.IntN(50))
	}
}

func load(args []string) error {
	fs := flag.NewFlagSet("load", flag.ContinueOnError)
	server := fs.String("server", "127.0.0.1:1053", "DNS server")
	qps := fs.Int("qps", 150, "queries per second")
	dur := fs.Duration("duration", 30*time.Second, "test length")
	timeout := fs.Duration("timeout", 2*time.Second, "per-query timeout")
	pid := fs.Int("pid", 0, "process to sample CPU/RSS for (0 = none)")
	workers := fs.Int("workers", 256, "concurrent senders")
	if err := fs.Parse(args); err != nil {
		return err
	}

	jobs := make(chan time.Time, 4*(*qps))
	var (
		mu  sync.Mutex
		lat []time.Duration
		res = result{QPS: *qps}
		wg  sync.WaitGroup
	)
	for w := range *workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := rand.New(rand.NewPCG(uint64(w), 7))
			c := &dns.Client{Net: "udp", Timeout: *timeout}
			for range jobs {
				m := new(dns.Msg)
				m.SetQuestion(query(r), dns.TypeA)
				start := time.Now()
				in, _, err := c.Exchange(m, *server)
				d := time.Since(start)
				mu.Lock()
				res.Sent++
				switch {
				case err != nil && isTimeout(err):
					res.Timeouts++
				case err != nil:
					res.Errors++
				default:
					res.OK++
					lat = append(lat, d)
					if in.Rcode == dns.RcodeServerFailure {
						res.ServFail++
					}
				}
				mu.Unlock()
			}
		}()
	}

	var cpu0 float64
	if *pid > 0 {
		cpu0 = cpuSeconds(*pid)
	}
	stopSample := make(chan struct{})
	sampled := make(chan float64)
	go func() { // RSS sampler
		max := 0.0
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stopSample:
				sampled <- max
				return
			case <-t.C:
				if *pid > 0 {
					if v := rssMiB(*pid); v > max {
						max = v
					}
				}
			}
		}
	}()

	// Pace by elapsed time, not by ticker period: tickers drop ticks under
	// load (and on WSL), which silently lowers the rate.
	start := time.Now()
	tick := time.NewTicker(time.Millisecond)
	dispatched := 0
	for now := range tick.C {
		el := now.Sub(start)
		if el >= *dur {
			break
		}
		for want := int(el.Seconds() * float64(*qps)); dispatched < want; dispatched++ {
			select {
			case jobs <- now:
			default: // all workers busy: count it instead of slowing the clock
				mu.Lock()
				res.Sent++
				res.Errors++
				mu.Unlock()
			}
		}
	}
	tick.Stop()
	elapsed := time.Since(start)
	close(jobs)
	wg.Wait()
	close(stopSample)
	res.RSSMaxMiB = <-sampled
	if *pid > 0 {
		res.CPUPercent = (cpuSeconds(*pid) - cpu0) / elapsed.Seconds() * 100
		res.RSSEndMiB = rssMiB(*pid)
	}
	res.DurationSecs = elapsed.Seconds()
	res.Achieved = float64(res.Sent) / elapsed.Seconds()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		return float64(lat[int(p*float64(len(lat)-1))].Microseconds()) / 1000
	}
	res.P50ms, res.P99ms, res.P999ms = pct(0.50), pct(0.99), pct(0.999)
	if len(lat) > 0 {
		res.MaxMs = float64(lat[len(lat)-1].Microseconds()) / 1000
	}
	return json.NewEncoder(os.Stdout).Encode(res)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// cpuSeconds reads utime+stime of pid from /proc (Linux, USER_HZ=100).
func cpuSeconds(pid int) float64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+2:])
	u, _ := strconv.ParseFloat(f[11], 64)
	k, _ := strconv.ParseFloat(f[12], 64)
	return (u + k) / 100
}

func rssMiB(pid int) float64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			kb, _ := strconv.ParseFloat(strings.Fields(line)[1], 64)
			return kb / 1024
		}
	}
	return 0
}

// stuck accepts dnstap connections, completes the handshake, then stops
// reading forever: the worst case for the sender.
func stuck(args []string) error {
	fs := flag.NewFlagSet("stuck", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:16000", "listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			_, _ = framestream.NewReader(c, &framestream.ReaderOptions{ContentTypes: [][]byte{dnstap.FSContentType}, Bidirectional: true, Timeout: 10 * time.Second})
			select {} // never read again; keep the connection open
		}()
	}
}
