package report

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/hjklo0220/dns-auditor/internal/inventory"
	"github.com/hjklo0220/dns-auditor/internal/rule"
)

func finding(ns, wl, name, ip string) *rule.Finding {
	f := &rule.Finding{CallerNamespace: ns, Name: name, CallerIP: netip.MustParseAddr(ip),
		Suggestions: []rule.Suggestion{{Host: name + ".x.svc.cluster.local", Ports: []int32{80}}}}
	if wl != "" {
		f.Caller = inventory.Workload{Namespace: ns, Kind: "Deployment", Name: wl}
	}
	return f
}

func TestAggregatorGroupsAndSorts(t *testing.T) {
	a := NewAggregator()
	a.Add(rule.External, nil)
	a.Add(rule.ClusterSearchNoise, nil)
	for range 3 {
		a.Add(rule.Misroute, finding("shop", "web", "billing", "10.0.0.1"))
	}
	a.Add(rule.Misroute, finding("shop", "web", "billing", "10.0.0.2")) // same workload, new Pod IP
	a.Add(rule.Misroute, finding("ops", "cron", "mailer", "10.0.0.3"))
	a.Add(rule.Misroute, finding("ops", "", "mailer", "10.0.9.9")) // unknown caller
	a.Add(rule.Misroute, finding("ops", "", "mailer", "10.0.9.8"))
	a.Add(rule.Misroute, finding("ops", "", "mailer", "10.0.9.9"))

	rep := a.Report(10, 9, 1)
	want := Summary{Lines: 10, Parsed: 9, Skipped: 1, Categories: map[rule.Category]int{
		rule.NotNXDomain: 0, rule.External: 1, rule.ClusterSearchNoise: 1, rule.UnknownShortName: 0, rule.Misroute: 8,
	}}
	if !reflect.DeepEqual(rep.Summary, want) {
		t.Fatalf("summary %+v", rep.Summary)
	}
	var got []string
	for _, r := range rep.Findings {
		got = append(got, fmt.Sprintf("%d %s %s %v", r.Count, r.CallerWorkload, r.Name, r.CallerIPs))
	}
	wantRows := []string{
		"4 shop/web billing []",
		"3 unknown mailer [10.0.9.8 10.0.9.9]",
		"1 ops/cron mailer []",
	}
	if !reflect.DeepEqual(got, wantRows) {
		t.Fatalf("rows\n got  %q\n want %q", got, wantRows)
	}
}

func TestUnknownIPListIsBounded(t *testing.T) {
	a := NewAggregator()
	for i := range 50 {
		a.Add(rule.Misroute, finding("ops", "", "mailer", fmt.Sprintf("10.0.1.%d", i)))
	}
	r := a.Report(0, 0, 0).Findings[0]
	if r.Count != 50 || len(r.CallerIPs) != maxIPsPerRow {
		t.Fatalf("count %d ips %d", r.Count, len(r.CallerIPs))
	}
}

func TestReportIsACopy(t *testing.T) {
	a := NewAggregator()
	a.Add(rule.External, nil)
	rep := a.Report(1, 1, 0)
	rep.Summary.Categories[rule.External] = 99
	if a.Report(1, 1, 0).Summary.Categories[rule.External] != 1 {
		t.Fatal("report shares state with aggregator")
	}
}

func TestEqualCountsSortByNamespaceThenWorkloadThenName(t *testing.T) {
	a := NewAggregator()
	a.Add(rule.Misroute, finding("b", "w", "n1", "10.0.0.1"))
	a.Add(rule.Misroute, finding("a", "w2", "n1", "10.0.0.2"))
	a.Add(rule.Misroute, finding("a", "w1", "n2", "10.0.0.3"))
	a.Add(rule.Misroute, finding("a", "w1", "n1", "10.0.0.4"))
	var got []string
	for _, r := range a.Report(0, 0, 0).Findings {
		got = append(got, r.CallerWorkload+" "+r.Name)
	}
	want := []string{"a/w1 n1", "a/w1 n2", "a/w2 n1", "b/w n1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
