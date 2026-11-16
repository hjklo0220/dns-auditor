package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/hjklo0220/dns-auditor/internal/server"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var cfg server.Config
	fs.StringVar(&cfg.DnstapAddr, "dnstap-addr", ":6000", "listen address for CoreDNS dnstap (Frame Streams over TCP)")
	fs.StringVar(&cfg.HTTPAddr, "http-addr", ":8080", "listen address for /metrics, /findings, /healthz, /readyz")
	fs.StringVar(&cfg.ClusterDomain, "cluster-domain", "cluster.local", "cluster DNS domain")
	fs.DurationVar(&cfg.TTL, "ttl", 0, "how long a finding stays active after its last occurrence (default 15m)")
	fs.DurationVar(&cfg.PodGrace, "pod-grace", 0, "keep attributing a deleted Pod's IP to its workload for this long (default 5m)")
	fs.IntVar(&cfg.MaxFindings, "max-findings", 0, "upper bound on stored findings (default 1000)")
	fs.IntVar(&cfg.QueueSize, "queue-size", 0, "events buffered between receiver and classifier; excess is dropped (default 10000)")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig path (default: in-cluster config, then $KUBECONFIG / ~/.kube/config)")
	kubecontext := fs.String("context", "", "kubeconfig context")
	level := fs.String("log-level", "info", "debug, info, warn or error")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var lv slog.Level
	if err := lv.UnmarshalText([]byte(*level)); err != nil {
		return fmt.Errorf("log-level: %w", err)
	}
	cfg.Log = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))

	rc, err := restConfig(*kubeconfig, *kubecontext)
	if err != nil {
		return err
	}
	rc.UserAgent = "dns-auditor/" + version
	cfg.Client, err = kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg.Log.Info("starting", "version", version, "dnstap", cfg.DnstapAddr, "http", cfg.HTTPAddr)
	return server.Run(ctx, cfg)
}

func restConfig(path, kctx string) (*rest.Config, error) {
	if path == "" && kctx == "" {
		if c, err := rest.InClusterConfig(); err == nil {
			return c, nil
		}
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if path != "" {
		rules.ExplicitPath = path
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: kctx}).ClientConfig()
}
