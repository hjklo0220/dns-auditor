// Command gensynthetic writes a deterministic, fully synthetic test case to
// testdata/synthetic: CoreDNS log lines, a kubectl snapshot, and the expected
// report.
//
// The expected report is computed here from what was injected, not by running
// the analyzer, so it acts as an independent oracle. The traffic mix mimics a
// real ndots:5 cluster: almost every NXDOMAIN is search-list noise, and only a
// small share are misrouted short-name calls.
//
//	go run ./hack/gensynthetic
package main

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hjklo0220/dns-auditor/internal/report"
	"github.com/hjklo0220/dns-auditor/internal/rule"
)

const outDir = "testdata/synthetic"

var searchSuffixes = func(ns string) []string {
	return []string{ns + ".svc.cluster.local", "svc.cluster.local", "cluster.local", "ec2.internal"}
}

type pod struct{ ns, deploy, hash, ip string }
type svc struct {
	ns, name string
	ports    []int32
}

var (
	namespaces = []string{"shop", "billing", "payments", "notify", "ops", "kube-system"}
	services   = []svc{
		{"billing", "billing", []int32{8080}},
		{"payments", "payments-api", []int32{8080, 9090}},
		{"notify", "mailer", []int32{8080}},
		{"ops", "mailer", []int32{2525}},
		{"shop", "storefront", []int32{8080}},
		{"shop", "cart", []int32{8080}},
	}
	pods = []pod{
		{"shop", "storefront", "5c6d7e8f9", "10.0.1.10"},
		{"shop", "cart", "6d7e8f9a0", "10.0.1.11"},
		{"billing", "billing", "7e8f9a0b1", "10.0.2.10"},
		{"notify", "digest", "8f9a0b1c2", "10.0.3.10"},
	}
	externalNames = []string{"api.example.com", "cdn.example.net", "login.example.org", "s3.amazonaws.com", "telemetry.vendor.io"}
)

type gen struct {
	rnd   *rand.Rand
	lines []string
	cats  map[rule.Category]int
	rows  map[string]*report.Row
	extra int // non-query lines
}

func (g *gen) query(ip, qtype, name, rcode string, cat rule.Category) {
	g.lines = append(g.lines, fmt.Sprintf(`[INFO] %s:%d - %d "%s IN %s. udp 60 false 1232" %s qr,aa,rd 160 0.000%03ds`,
		ip, 30000+g.rnd.IntN(30000), g.rnd.IntN(65535), qtype, name, rcode, g.rnd.IntN(999)))
	g.cats[cat]++
}

// lookup emits what a resolver with ndots:5 sends for one name, for A and
// AAAA, until a candidate answers. answerAt is the index of the first
// candidate that resolves (-1: none resolve).
func (g *gen) lookup(ip, ns, name string, firstCat rule.Category, answerAt int) {
	cands := []string{}
	if strings.Count(name, ".") < 5 {
		for _, s := range searchSuffixes(ns) {
			cands = append(cands, name+"."+s)
		}
	}
	cands = append(cands, name)
	for _, qt := range []string{"A", "AAAA"} {
		for i, c := range cands {
			if i == answerAt {
				g.query(ip, qt, c, "NOERROR", rule.NotNXDomain)
				break
			}
			cat := rule.ClusterSearchNoise
			switch {
			case i == 0:
				cat = firstCat
			case !strings.HasSuffix(c, "cluster.local"):
				cat = rule.External
			}
			g.query(ip, qt, c, "NXDOMAIN", cat)
		}
	}
}

func (g *gen) misroute(p pod, name string, times int) {
	key := p.ns + "|" + p.ns + "/" + p.deploy + "|" + name
	g.addRow(key, report.Row{CallerNamespace: p.ns, CallerWorkload: p.ns + "/" + p.deploy, Name: name}, name, times*2)
	for range times {
		g.lookup(p.ip, p.ns, name, rule.Misroute, -1)
	}
}

func (g *gen) addRow(key string, base report.Row, name string, count int) {
	r, ok := g.rows[key]
	if !ok {
		for _, s := range services {
			if s.name == name {
				base.Suggestions = append(base.Suggestions, rule.Suggestion{Host: s.name + "." + s.ns + ".svc.cluster.local", Ports: s.ports})
			}
		}
		sort.Slice(base.Suggestions, func(i, j int) bool { return base.Suggestions[i].Host < base.Suggestions[j].Host })
		r = &base
		g.rows[key] = r
	}
	r.Count += count
}

func main() {
	g := &gen{rnd: rand.New(rand.NewPCG(20261113, 1)), cats: map[rule.Category]int{}, rows: map[string]*report.Row{}}
	for _, c := range rule.Categories {
		g.cats[c] = 0
	}
	storefront, cart, billing, digest := pods[0], pods[1], pods[2], pods[3]

	// Misrouted short-name calls (the findings).
	g.misroute(storefront, "payments-api", 25) // multi-port suggestion
	g.misroute(billing, "mailer", 20)          // two candidate namespaces
	g.misroute(digest, "billing", 3)

	// A misroute from an IP that is not a known Pod (e.g. Pod already gone).
	g.addRow("payments|unknown|billing", report.Row{CallerNamespace: "payments", CallerWorkload: report.UnknownWorkload, CallerIPs: []string{"10.0.9.9"}, Name: "billing"}, "billing", 4)
	for range 2 {
		g.lookup("10.0.9.9", "payments", "billing", rule.Misroute, -1)
	}

	// Mixed case query from the same caller still counts.
	g.query(storefront.ip, "A", "PAYMENTS-API.Shop.svc.cluster.local", "NXDOMAIN", rule.Misroute)
	g.rows["shop|shop/storefront|payments-api"].Count++

	// Short name that exists nowhere: reported as a category, not a finding.
	for range 4 {
		g.lookup(cart.ip, "shop", "nothere", rule.UnknownShortName, -1)
	}

	// Healthy same-namespace calls: answered on the first candidate.
	for range 100 {
		g.lookup(cart.ip, "shop", "storefront", "", 0)
	}
	// Healthy FQDN calls.
	for range 60 {
		g.query(storefront.ip, "A", "billing.billing.svc.cluster.local", "NOERROR", rule.NotNXDomain)
	}
	// External names: every search candidate fails, then the name resolves.
	for i := range 400 {
		p := pods[i%len(pods)]
		g.lookup(p.ip, p.ns, externalNames[g.rnd.IntN(len(externalNames))], rule.ClusterSearchNoise, 4)
	}
	// Names with a bogus namespace label and SRV-style lookups.
	for range 20 {
		g.query(storefront.ip, "A", "billing.nonexistent.svc.cluster.local", "NXDOMAIN", rule.ClusterSearchNoise)
		g.query(storefront.ip, "A", "_grpclb._tcp.cart.shop.svc.cluster.local", "NXDOMAIN", rule.ClusterSearchNoise)
	}
	// SERVFAIL is never a finding.
	for range 5 {
		g.query(storefront.ip, "A", "billing.shop.svc.cluster.local", "SERVFAIL", rule.NotNXDomain)
	}

	g.rnd.Shuffle(len(g.lines), func(i, j int) { g.lines[i], g.lines[j] = g.lines[j], g.lines[i] })

	// Lines the parser must skip, plus one timestamped line it must accept.
	skip := []string{
		`[INFO] Reloading`,
		`[INFO] plugin/reload: Running configuration SHA512 = 0f00`,
		`[INFO] Reloading complete`,
		`[ERROR] plugin/errors: 2 api.example.com. A: read udp 10.0.0.2:40000->10.0.0.1:53: i/o timeout`,
		`.:53`,
	}
	g.lines = append(skip[:3:3], append(g.lines, skip[3:]...)...)
	g.extra = len(skip)
	g.lines = append(g.lines, `2026-11-13T07:00:00.000000001Z [INFO] 10.0.1.11:40000 - 1 "A IN cart.shop.svc.cluster.local. udp 60 false 1232" NOERROR qr,aa,rd 160 0.0001s`)
	g.cats[rule.NotNXDomain]++

	must(os.MkdirAll(outDir, 0o755))
	must(os.WriteFile(filepath.Join(outDir, "coredns.log"), []byte(strings.Join(g.lines, "\n")+"\n"), 0o644))
	must(writeJSON(filepath.Join(outDir, "snapshot.json"), snapshot()))

	parsed := len(g.lines) - g.extra
	rows := make([]report.Row, 0, len(g.rows))
	for _, r := range g.rows {
		rows = append(rows, *r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].CallerWorkload < rows[j].CallerWorkload
	})
	exp := report.Report{Summary: report.Summary{Lines: len(g.lines), Parsed: parsed, Skipped: g.extra, Categories: g.cats}, Findings: rows}
	must(writeJSON(filepath.Join(outDir, "expected.json"), exp))
	fmt.Printf("wrote %s: %d lines, categories %v, %d findings\n", outDir, len(g.lines), g.cats, len(rows))
}

func snapshot() map[string]any {
	var items []any
	for _, ns := range namespaces {
		items = append(items, map[string]any{"kind": "Namespace", "metadata": map[string]any{"name": ns}})
	}
	for _, s := range services {
		var ports []any
		for _, p := range s.ports {
			ports = append(ports, map[string]any{"port": p, "protocol": "TCP"})
		}
		items = append(items, map[string]any{"kind": "Service", "metadata": map[string]any{"name": s.name, "namespace": s.ns}, "spec": map[string]any{"ports": ports}})
	}
	for _, p := range pods {
		items = append(items, map[string]any{"kind": "Pod",
			"metadata": map[string]any{"name": p.deploy + "-" + p.hash + "-x1y2z", "namespace": p.ns,
				"labels":          map[string]any{"pod-template-hash": p.hash},
				"ownerReferences": []any{map[string]any{"kind": "ReplicaSet", "name": p.deploy + "-" + p.hash, "controller": true}}},
			"status": map[string]any{"podIP": p.ip}})
	}
	return map[string]any{"apiVersion": "v1", "kind": "List", "items": items}
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
