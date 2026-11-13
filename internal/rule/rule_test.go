package rule

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/hjklo0220/dns-auditor/internal/event"
	"github.com/hjklo0220/dns-auditor/internal/inventory"
)

func testInventory() *inventory.Static {
	inv := inventory.NewStatic()
	for _, ns := range []string{"shop", "billing", "payments", "notify", "ops"} {
		inv.AddNamespace(ns)
	}
	inv.AddService(inventory.Service{Namespace: "billing", Name: "billing", Ports: []inventory.Port{{Port: 8080}}})
	inv.AddService(inventory.Service{Namespace: "payments", Name: "payments-api", Ports: []inventory.Port{{Name: "http", Port: 8080}, {Name: "metrics", Port: 9090}}})
	inv.AddService(inventory.Service{Namespace: "notify", Name: "mailer", Ports: []inventory.Port{{Port: 8080}}})
	inv.AddService(inventory.Service{Namespace: "ops", Name: "mailer", Ports: []inventory.Port{{Port: 2525}}})
	inv.AddService(inventory.Service{Namespace: "shop", Name: "storefront", Ports: []inventory.Port{{Port: 8080}}})
	inv.AddService(inventory.Service{Namespace: "shop", Name: "headless", Ports: nil})
	inv.AddPod(netip.MustParseAddr("10.0.1.10"), inventory.Workload{Namespace: "shop", Kind: "Deployment", Name: "storefront"})
	return inv
}

func TestClassify(t *testing.T) {
	inv := testInventory()
	c := New("")
	storefront := netip.MustParseAddr("10.0.1.10")
	stranger := netip.MustParseAddr("10.9.9.9")

	tests := []struct {
		name   string
		qname  string
		rcode  string
		ip     netip.Addr
		want   Category
		wantFn *Finding
	}{
		{"misroute single port", "billing.shop.svc.cluster.local.", "NXDOMAIN", storefront, Misroute, &Finding{
			CallerNamespace: "shop", Caller: inventory.Workload{Namespace: "shop", Kind: "Deployment", Name: "storefront"}, CallerIP: storefront,
			Name: "billing", Suggestions: []Suggestion{{Host: "billing.billing.svc.cluster.local", Ports: []int32{8080}}},
		}},
		{"misroute multi port", "payments-api.shop.svc.cluster.local.", "NXDOMAIN", storefront, Misroute, &Finding{
			CallerNamespace: "shop", Caller: inventory.Workload{Namespace: "shop", Kind: "Deployment", Name: "storefront"}, CallerIP: storefront,
			Name: "payments-api", Suggestions: []Suggestion{{Host: "payments-api.payments.svc.cluster.local", Ports: []int32{8080, 9090}}},
		}},
		{"misroute, same name in two namespaces", "mailer.shop.svc.cluster.local.", "NXDOMAIN", storefront, Misroute, &Finding{
			CallerNamespace: "shop", Caller: inventory.Workload{Namespace: "shop", Kind: "Deployment", Name: "storefront"}, CallerIP: storefront,
			Name: "mailer", Suggestions: []Suggestion{
				{Host: "mailer.notify.svc.cluster.local", Ports: []int32{8080}},
				{Host: "mailer.ops.svc.cluster.local", Ports: []int32{2525}},
			},
		}},
		{"misroute, unknown caller IP", "billing.shop.svc.cluster.local.", "NXDOMAIN", stranger, Misroute, &Finding{
			CallerNamespace: "shop", CallerIP: stranger,
			Name: "billing", Suggestions: []Suggestion{{Host: "billing.billing.svc.cluster.local", Ports: []int32{8080}}},
		}},
		{"misroute, mixed case and no trailing dot", "BILLING.Shop.svc.Cluster.Local", "nxdomain", storefront, Misroute, &Finding{
			CallerNamespace: "shop", Caller: inventory.Workload{Namespace: "shop", Kind: "Deployment", Name: "storefront"}, CallerIP: storefront,
			Name: "billing", Suggestions: []Suggestion{{Host: "billing.billing.svc.cluster.local", Ports: []int32{8080}}},
		}},
		{"NOERROR is never a finding", "billing.billing.svc.cluster.local.", "NOERROR", storefront, NotNXDomain, nil},
		{"SERVFAIL is not NXDOMAIN", "billing.shop.svc.cluster.local.", "SERVFAIL", storefront, NotNXDomain, nil},
		{"external name", "api.example.com.", "NXDOMAIN", storefront, External, nil},
		{"external with node search suffix", "billing.ec2.internal.", "NXDOMAIN", storefront, External, nil},
		{"external name with namespace search suffix", "api.example.com.shop.svc.cluster.local.", "NXDOMAIN", storefront, ClusterSearchNoise, nil},
		{"second search candidate", "billing.svc.cluster.local.", "NXDOMAIN", storefront, ClusterSearchNoise, nil},
		{"third search candidate", "billing.cluster.local.", "NXDOMAIN", storefront, ClusterSearchNoise, nil},
		{"bare cluster domain", "cluster.local.", "NXDOMAIN", storefront, ClusterSearchNoise, nil},
		{"namespace label is not a namespace", "billing.nonexistent.svc.cluster.local.", "NXDOMAIN", storefront, ClusterSearchNoise, nil},
		{"service exists in caller namespace", "storefront.shop.svc.cluster.local.", "NXDOMAIN", storefront, ClusterSearchNoise, nil},
		{"SRV style labels", "_grpclb._tcp.billing.shop.svc.cluster.local.", "NXDOMAIN", storefront, ClusterSearchNoise, nil},
		{"empty service label", ".shop.svc.cluster.local.", "NXDOMAIN", storefront, ClusterSearchNoise, nil},
		{"short name exists nowhere", "nothere.shop.svc.cluster.local.", "NXDOMAIN", storefront, UnknownShortName, nil},
		{"similar suffix is not the cluster domain", "billing.shop.svc.cluster.localhost.", "NXDOMAIN", storefront, External, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, f := c.Classify(event.Event{QName: tt.qname, Rcode: tt.rcode, ClientIP: tt.ip}, inv)
			if got != tt.want {
				t.Fatalf("category = %q, want %q", got, tt.want)
			}
			if !reflect.DeepEqual(f, tt.wantFn) {
				t.Fatalf("finding = %+v\nwant      %+v", f, tt.wantFn)
			}
		})
	}
}

func TestCustomClusterDomain(t *testing.T) {
	inv := testInventory()
	c := New(".Corp.Internal.")
	got, f := c.Classify(event.Event{QName: "billing.shop.svc.corp.internal.", Rcode: "NXDOMAIN"}, inv)
	if got != Misroute || f.Suggestions[0].Host != "billing.billing.svc.corp.internal" {
		t.Fatalf("got %q %+v", got, f)
	}
	if got, _ := c.Classify(event.Event{QName: "billing.shop.svc.cluster.local.", Rcode: "NXDOMAIN"}, inv); got != External {
		t.Fatalf("cluster.local under custom domain = %q, want external", got)
	}
}

func BenchmarkClassifyNoise(b *testing.B) {
	inv := testInventory()
	c := New("")
	ev := event.Event{QName: "api.example.com.shop.svc.cluster.local.", Rcode: "NXDOMAIN"}
	b.ReportAllocs()
	for b.Loop() {
		c.Classify(ev, inv)
	}
}

func BenchmarkClassifyMisroute(b *testing.B) {
	inv := testInventory()
	c := New("")
	ev := event.Event{QName: "billing.shop.svc.cluster.local.", Rcode: "NXDOMAIN", ClientIP: netip.MustParseAddr("10.0.1.10")}
	b.ReportAllocs()
	for b.Loop() {
		c.Classify(ev, inv)
	}
}
