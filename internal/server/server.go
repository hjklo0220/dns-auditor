// Package server wires the live auditor together:
//
//	CoreDNS --dnstap--> receiver --queue--> pipeline (rule + inventory) --> store
//	                                                                         |
//	                        HTTP: /metrics /findings /healthz /readyz <------+
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"

	"github.com/hjklo0220/dns-auditor/internal/event"
	"github.com/hjklo0220/dns-auditor/internal/inventory"
	"github.com/hjklo0220/dns-auditor/internal/pipeline"
	"github.com/hjklo0220/dns-auditor/internal/rule"
	"github.com/hjklo0220/dns-auditor/internal/sink/metrics"
	"github.com/hjklo0220/dns-auditor/internal/source/dnstap"
	"github.com/hjklo0220/dns-auditor/internal/store"
)

// Config configures Run. Zero values get defaults.
type Config struct {
	Client kubernetes.Interface

	DnstapAddr string // default ":6000"
	HTTPAddr   string // default ":8080"
	// Pre-opened listeners (tests). When set, the matching Addr is ignored.
	DnstapListener net.Listener
	HTTPListener   net.Listener

	ClusterDomain string        // default cluster.local
	TTL           time.Duration // how long a finding stays active; default 15m
	PodGrace      time.Duration // IP attribution after Pod deletion; default 5m
	MaxFindings   int           // default 1000
	QueueSize     int           // events buffered between receiver and pipeline; default 10000

	Log *slog.Logger
}

func (c *Config) defaults() {
	if c.DnstapAddr == "" {
		c.DnstapAddr = ":6000"
	}
	if c.HTTPAddr == "" {
		c.HTTPAddr = ":8080"
	}
	if c.TTL <= 0 {
		c.TTL = 15 * time.Minute
	}
	if c.QueueSize <= 0 {
		c.QueueSize = 10000
	}
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
}

// Finding is the /findings JSON shape.
type Finding struct {
	CallerNamespace string    `json:"caller_namespace"`
	CallerWorkload  string    `json:"caller_workload"`
	CallerIPs       []string  `json:"caller_ips,omitempty"`
	Name            string    `json:"name"`
	UseInstead      string    `json:"use_instead"`
	Count           uint64    `json:"count"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}

// Run serves until ctx is done. It returns nil on a clean shutdown.
func Run(ctx context.Context, cfg Config) error {
	cfg.defaults()
	if cfg.Client == nil {
		return errors.New("server: Kubernetes client is required")
	}
	log := cfg.Log

	dln, err := listen(cfg.DnstapListener, cfg.DnstapAddr)
	if err != nil {
		return fmt.Errorf("dnstap listen: %w", err)
	}
	hln, err := listen(cfg.HTTPListener, cfg.HTTPAddr)
	if err != nil {
		_ = dln.Close()
		return fmt.Errorf("http listen: %w", err)
	}

	inv := inventory.NewLive(inventory.LiveOptions{Grace: cfg.PodGrace})
	st := store.New(store.Options{TTL: cfg.TTL, MaxFindings: cfg.MaxFindings})
	queue := make(chan event.Event, cfg.QueueSize)
	recv := &dnstap.Receiver{Out: queue, Log: log}
	pipe := &pipeline.Pipeline{Classifier: rule.New(cfg.ClusterDomain), Inventory: inv, Store: st}

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		metrics.New(metrics.Sources{Store: st, Categories: pipe.Counts, Dnstap: &recv.Stats, Inventory: inv}),
	)

	var ready atomic.Bool
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "inventory not synced", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /findings", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(findings(st))
	})
	hs := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	g, gctx := errgroup.WithContext(ctx)
	// HTTP first, so /healthz answers while the inventory syncs.
	g.Go(func() error {
		if err := hs.Serve(hln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		<-gctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return hs.Shutdown(sctx)
	})
	g.Go(func() error {
		if err := inv.Start(gctx, cfg.Client, 0); err != nil {
			if gctx.Err() != nil {
				_ = dln.Close()
				return nil
			}
			_ = dln.Close()
			return err
		}
		log.Info("inventory synced")
		// Start receiving only once lookups can attribute callers.
		g.Go(func() error { return recv.Serve(gctx, dln) })
		g.Go(func() error { pipe.Run(gctx, queue); return nil })
		g.Go(func() error { pruneLoop(gctx, st, cfg.TTL); return nil })
		ready.Store(true)
		return nil
	})
	return g.Wait()
}

func listen(ln net.Listener, addr string) (net.Listener, error) {
	if ln != nil {
		return ln, nil
	}
	return net.Listen("tcp", addr)
}

func pruneLoop(ctx context.Context, st *store.Store, ttl time.Duration) {
	t := time.NewTicker(ttl)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			st.Prune()
		}
	}
}

func findings(st *store.Store) []Finding {
	active := st.Active()
	out := make([]Finding, 0, len(active))
	for _, e := range active {
		f := Finding{
			CallerNamespace: e.CallerNamespace, CallerWorkload: e.CallerWorkload, Name: e.Name,
			UseInstead: metrics.Suggestion(e.Suggestions), Count: e.Count, FirstSeen: e.FirstSeen, LastSeen: e.LastSeen,
		}
		for _, ip := range e.CallerIPs {
			f.CallerIPs = append(f.CallerIPs, ip.String())
		}
		out = append(out, f)
	}
	return out
}
