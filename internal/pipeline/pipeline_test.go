package pipeline

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/hjklo0220/dns-auditor/internal/event"
	"github.com/hjklo0220/dns-auditor/internal/inventory"
	"github.com/hjklo0220/dns-auditor/internal/rule"
	"github.com/hjklo0220/dns-auditor/internal/store"
)

func newPipeline() *Pipeline {
	inv := inventory.NewStatic()
	inv.AddNamespace("shop")
	inv.AddService(inventory.Service{Namespace: "billing", Name: "billing", Ports: []inventory.Port{{Port: 8080}}})
	return &Pipeline{Classifier: rule.New(""), Inventory: inv, Store: store.New(store.Options{})}
}

func TestRunUntilClosed(t *testing.T) {
	p := newPipeline()
	in := make(chan event.Event, 4)
	in <- event.Event{QName: "billing.shop.svc.cluster.local.", Rcode: "NXDOMAIN", ClientIP: netip.MustParseAddr("10.0.0.1"), Time: time.Now()}
	in <- event.Event{QName: "api.example.com.", Rcode: "NXDOMAIN"}
	in <- event.Event{Rcode: "NOERROR"}
	close(in)
	p.Run(context.Background(), in)
	c := p.Counts()
	if c[rule.Misroute] != 1 || c[rule.External] != 1 || c[rule.NotNXDomain] != 1 || len(c) != len(rule.Categories) {
		t.Fatalf("counts %v", c)
	}
	if a := p.Store.Active(); len(a) != 1 || a[0].Name != "billing" {
		t.Fatalf("store %+v", a)
	}
}

func TestRunStopsOnContext(t *testing.T) {
	p := newPipeline()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx, make(chan event.Event)); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestIndexPanicsOnUnknownCategory(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("want panic")
		}
	}()
	index("bogus")
}
