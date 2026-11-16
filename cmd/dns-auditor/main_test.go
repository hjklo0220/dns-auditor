package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCommands(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"version"}, &out); err != nil || strings.TrimSpace(out.String()) != "dev" {
		t.Fatalf("version: %v %q", err, out.String())
	}
	for _, args := range [][]string{nil, {"bogus"}, {"analyze"}, {"analyze", "-format", "xml", "-coredns-log", "x", "-snapshot", "y"}, {"serve", "-log-level", "loud"}} {
		if err := run(args, &out); err == nil {
			t.Errorf("%v: want error", args)
		}
	}
}

func TestAnalyzeSynthetic(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "synthetic")
	for _, format := range []string{"text", "json"} {
		var out bytes.Buffer
		err := run([]string{"analyze", "-coredns-log", filepath.Join(dir, "coredns.log"), "-snapshot", filepath.Join(dir, "snapshot.json"), "-format", format}, &out)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "payments-api.payments.svc.cluster.local") {
			t.Fatalf("%s output missing suggestion:\n%s", format, out.String())
		}
	}
	var out bytes.Buffer
	if err := run([]string{"analyze", "-coredns-log", filepath.Join(dir, "coredns.log"), "-snapshot", filepath.Join(dir, "snapshot.json")}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "payments/? (10.0.9.9)") || !strings.Contains(out.String(), ":{8080,9090}") {
		t.Fatalf("text output:\n%s", out.String())
	}
}

func TestAnalyzeNoFindingsAndBadFiles(t *testing.T) {
	d := t.TempDir()
	log := filepath.Join(d, "c.log")
	snap := filepath.Join(d, "s.json")
	_ = os.WriteFile(log, []byte(`[INFO] 10.0.0.1:1 - 1 "A IN api.example.com. udp 1 false 512" NXDOMAIN qr 1 0s`+"\n"), 0o644)
	_ = os.WriteFile(snap, []byte(`{"kind":"List","items":[]}`), 0o644)
	var out bytes.Buffer
	if err := run([]string{"analyze", "-coredns-log", log, "-snapshot", snap}, &out); err != nil || !strings.Contains(out.String(), "no misrouted") {
		t.Fatalf("%v %s", err, out.String())
	}
	_ = os.WriteFile(snap, []byte(`not json`), 0o644)
	if err := run([]string{"analyze", "-coredns-log", log, "-snapshot", snap}, &out); err == nil {
		t.Fatal("want snapshot error")
	}
	if err := run([]string{"analyze", "-coredns-log", filepath.Join(d, "missing"), "-snapshot", filepath.Join(d, "missing")}, &out); err == nil {
		t.Fatal("want missing file error")
	}
}

func TestRestConfigFromKubeconfig(t *testing.T) {
	kc := filepath.Join(t.TempDir(), "kubeconfig")
	_ = os.WriteFile(kc, []byte(`apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "https://127.0.0.1:6443"}}]
users: [{name: u, user: {token: t}}]
contexts: [{name: x, context: {cluster: c, user: u}}]
current-context: x
`), 0o600)
	rc, err := restConfig(kc, "x")
	if err != nil || rc.Host != "https://127.0.0.1:6443" {
		t.Fatalf("%v %+v", err, rc)
	}
	if _, err := restConfig(filepath.Join(t.TempDir(), "missing"), ""); err == nil {
		t.Fatal("want error for missing kubeconfig")
	}
}
