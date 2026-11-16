package metrics

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/hjklo0220/dns-auditor/internal/event"
	"github.com/hjklo0220/dns-auditor/internal/inventory"
	"github.com/hjklo0220/dns-auditor/internal/pipeline"
	"github.com/hjklo0220/dns-auditor/internal/rule"
	"github.com/hjklo0220/dns-auditor/internal/source/dnstap"
	"github.com/hjklo0220/dns-auditor/internal/store"
)

type fakeInv struct{}

func (fakeInv) Stats() (int, int, int) { return 3, 2, 1 }

func TestCollector(t *testing.T) {
	now := time.Unix(1763017200, 0)
	st := store.New(store.Options{TTL: time.Minute, Now: func() time.Time { return now }})
	inv := inventory.NewStatic()
	inv.AddNamespace("shop")
	inv.AddService(inventory.Service{Namespace: "billing", Name: "billing", Ports: []inventory.Port{{Port: 8080}}})
	inv.AddPod(netip.MustParseAddr("10.0.0.1"), inventory.Workload{Namespace: "shop", Kind: "Deployment", Name: "web"})
	p := &pipeline.Pipeline{Classifier: rule.New(""), Inventory: inv, Store: st}
	for range 2 {
		p.Handle(event.Event{QName: "billing.shop.svc.cluster.local.", Rcode: "NXDOMAIN", ClientIP: netip.MustParseAddr("10.0.0.1")})
	}
	p.Handle(event.Event{Rcode: "NOERROR"})

	var ds dnstap.Stats
	ds.Active.Store(1)
	ds.Connections.Add(2)
	ds.Frames.Add(10)
	ds.Ignored.Add(4)
	ds.DecodeErrors.Add(1)
	ds.Dropped.Add(5)

	c := New(Sources{Store: st, Categories: p.Counts, Dnstap: &ds, Inventory: fakeInv{}})
	want := `
# HELP dns_auditor_misroute_lookups_total Failed short-name lookups of a Service in another namespace, per caller workload (active findings only).
# TYPE dns_auditor_misroute_lookups_total counter
dns_auditor_misroute_lookups_total{caller_namespace="shop",caller_workload="shop/web",name="billing",suggestion="billing.billing.svc.cluster.local:8080"} 2
# HELP dns_auditor_misroute_last_seen_timestamp_seconds Last time the misrouted lookup was seen (active findings only).
# TYPE dns_auditor_misroute_last_seen_timestamp_seconds gauge
dns_auditor_misroute_last_seen_timestamp_seconds{caller_namespace="shop",caller_workload="shop/web",name="billing",suggestion="billing.billing.svc.cluster.local:8080"} 1.7630172e+09
# HELP dns_auditor_misroute_active Number of active findings.
# TYPE dns_auditor_misroute_active gauge
dns_auditor_misroute_active 1
# HELP dns_auditor_responses_total DNS responses classified, by category.
# TYPE dns_auditor_responses_total counter
dns_auditor_responses_total{category="cluster_search_noise"} 0
dns_auditor_responses_total{category="external"} 0
dns_auditor_responses_total{category="misroute"} 2
dns_auditor_responses_total{category="not_nxdomain"} 1
dns_auditor_responses_total{category="unknown_short_name"} 0
# HELP dns_auditor_dnstap_dropped_total Events dropped because the processing queue was full.
# TYPE dns_auditor_dnstap_dropped_total counter
dns_auditor_dnstap_dropped_total 5
# HELP dns_auditor_inventory_objects Objects tracked by the inventory.
# TYPE dns_auditor_inventory_objects gauge
dns_auditor_inventory_objects{kind="namespace"} 3
dns_auditor_inventory_objects{kind="pod_ip"} 1
dns_auditor_inventory_objects{kind="service_name"} 2
`
	names := []string{"dns_auditor_misroute_lookups_total", "dns_auditor_misroute_last_seen_timestamp_seconds", "dns_auditor_misroute_active",
		"dns_auditor_responses_total", "dns_auditor_dnstap_dropped_total", "dns_auditor_inventory_objects"}
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), names...); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c); n != 2+1+1+5+6+3 {
		t.Fatalf("series %d", n)
	}
	// Registers cleanly (descriptors consistent with metrics).
	if err := prometheus.NewPedanticRegistry().Register(c); err != nil {
		t.Fatal(err)
	}

	// After the TTL the finding disappears from the output.
	now = now.Add(2 * time.Minute)
	if err := testutil.CollectAndCompare(c, strings.NewReader("# HELP dns_auditor_misroute_active Number of active findings.\n# TYPE dns_auditor_misroute_active gauge\ndns_auditor_misroute_active 0\n"),
		"dns_auditor_misroute_lookups_total", "dns_auditor_misroute_active"); err != nil {
		t.Fatal(err)
	}
}

func TestEmptySources(t *testing.T) {
	if n := testutil.CollectAndCount(New(Sources{})); n != 0 {
		t.Fatalf("series %d", n)
	}
}

func TestSuggestion(t *testing.T) {
	got := Suggestion([]rule.Suggestion{{Host: "a.x.svc.cluster.local", Ports: []int32{80, 9090}}, {Host: "a.y.svc.cluster.local"}, {Host: "a.z.svc.cluster.local", Ports: []int32{80}}})
	if got != "a.x.svc.cluster.local:{80,9090} | a.y.svc.cluster.local | a.z.svc.cluster.local:80" {
		t.Fatal(got)
	}
}
