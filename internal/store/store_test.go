package store

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/hjklo0220/dns-auditor/internal/inventory"
	"github.com/hjklo0220/dns-auditor/internal/report"
	"github.com/hjklo0220/dns-auditor/internal/rule"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func f(ns, wl, name, ip, host string) *rule.Finding {
	x := &rule.Finding{CallerNamespace: ns, Name: name, CallerIP: netip.MustParseAddr(ip), Suggestions: []rule.Suggestion{{Host: host, Ports: []int32{8080}}}}
	if wl != "" {
		x.Caller = inventory.Workload{Namespace: ns, Kind: "Deployment", Name: wl}
	}
	return x
}

func newStore(ttl time.Duration, max int) (*Store, *clock) {
	c := &clock{t: time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)}
	return New(Options{TTL: ttl, MaxFindings: max, Now: c.now}), c
}

func TestAddAndActive(t *testing.T) {
	s, c := newStore(15*time.Minute, 100)
	s.Add(nil, time.Time{}) // ignored
	for range 3 {
		s.Add(f("shop", "web", "billing", "10.0.0.1", "billing.billing.svc.cluster.local"), time.Time{})
	}
	c.add(time.Minute)
	s.Add(f("shop", "web", "billing", "10.0.0.2", "billing.billing2.svc.cluster.local"), time.Time{}) // suggestion changed
	s.Add(f("ops", "", "mailer", "10.9.9.9", "mailer.notify.svc.cluster.local"), time.Time{})
	s.Add(f("ops", "", "mailer", "10.9.9.9", "mailer.notify.svc.cluster.local"), time.Time{})             // same IP once
	s.Add(f("ops", "", "mailer", "10.9.9.8", "mailer.notify.svc.cluster.local"), c.now().Add(-time.Hour)) // late event: LastSeen keeps max

	a := s.Active()
	if len(a) != 2 {
		t.Fatalf("active %d", len(a))
	}
	web := a[0]
	if web.CallerWorkload != "shop/web" || web.Count != 4 || web.Suggestions[0].Host != "billing.billing2.svc.cluster.local" ||
		!web.FirstSeen.Equal(c.now().Add(-time.Minute)) || !web.LastSeen.Equal(c.now()) || len(web.CallerIPs) != 0 {
		t.Fatalf("web %+v", web)
	}
	m := a[1]
	if m.CallerWorkload != report.UnknownWorkload || m.Count != 3 || len(m.CallerIPs) != 2 || !m.LastSeen.Equal(c.now()) {
		t.Fatalf("mailer %+v", m)
	}
	// Snapshot is a copy.
	a[0].Suggestions[0].Host = "changed"
	if s.Active()[0].Suggestions[0].Host == "changed" {
		t.Fatal("Active shares memory with the store")
	}
}

func TestTTLMakesFixedCallsDisappear(t *testing.T) {
	s, c := newStore(15*time.Minute, 100)
	s.Add(f("shop", "web", "billing", "10.0.0.1", "h"), time.Time{})
	c.add(14 * time.Minute)
	if len(s.Active()) != 1 {
		t.Fatal("gone too early")
	}
	c.add(2 * time.Minute)
	if len(s.Active()) != 0 {
		t.Fatal("still active after TTL")
	}
	if s.Len() != 1 {
		t.Fatal("prune should be lazy")
	}
	s.Prune()
	if s.Len() != 0 {
		t.Fatal("prune did not remove")
	}
}

func TestBoundedSize(t *testing.T) {
	s, c := newStore(15*time.Minute, 3)
	for i := range 3 {
		s.Add(f("ns", fmt.Sprintf("w%d", i), "x", "10.0.0.1", "h"), time.Time{})
		c.add(time.Second)
	}
	s.Add(f("ns", "w0", "x", "10.0.0.1", "h"), time.Time{}) // refresh w0: now w1 is oldest
	c.add(time.Second)
	s.Add(f("ns", "w3", "x", "10.0.0.1", "h"), time.Time{})
	if s.Len() != 3 || s.Evicted() != 1 {
		t.Fatalf("len %d evicted %d", s.Len(), s.Evicted())
	}
	for _, e := range s.Active() {
		if e.CallerWorkload == "ns/w1" {
			t.Fatal("oldest entry was not evicted")
		}
	}
	// Expired entries are reclaimed before anything active is evicted.
	c.add(time.Hour)
	s.Add(f("ns", "w4", "x", "10.0.0.1", "h"), time.Time{})
	if s.Len() != 1 || s.Evicted() != 1 {
		t.Fatalf("len %d evicted %d", s.Len(), s.Evicted())
	}
}

func TestUnknownCallerIPsBounded(t *testing.T) {
	s, _ := newStore(0, 0) // defaults
	for i := range 50 {
		s.Add(f("ops", "", "mailer", fmt.Sprintf("10.0.1.%d", i), "h"), time.Time{})
	}
	if e := s.Active()[0]; len(e.CallerIPs) != maxIPs || e.Count != 50 {
		t.Fatalf("%+v", e)
	}
	if New(Options{}).now == nil {
		t.Fatal("default clock missing")
	}
}

func TestSortTieBreak(t *testing.T) {
	s, _ := newStore(time.Hour, 10)
	s.Add(f("b", "w", "n1", "10.0.0.1", "h"), time.Time{})
	s.Add(f("a", "w2", "n1", "10.0.0.1", "h"), time.Time{})
	s.Add(f("a", "w1", "n2", "10.0.0.1", "h"), time.Time{})
	s.Add(f("a", "w1", "n1", "10.0.0.1", "h"), time.Time{})
	var got []string
	for _, e := range s.Active() {
		got = append(got, e.CallerWorkload+" "+e.Name)
	}
	want := "[a/w1 n1 a/w1 n2 a/w2 n1 b/w n1]"
	if fmt.Sprint(got) != want {
		t.Fatalf("got %v", got)
	}
}

func TestConcurrentUse(t *testing.T) {
	s, _ := newStore(time.Hour, 50)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 500 {
				s.Add(f("ns", fmt.Sprintf("w%d", (g*500+i)%80), "x", "10.0.0.1", "h"), time.Time{})
				if i%50 == 0 {
					_ = s.Active()
					s.Prune()
				}
			}
		}()
	}
	wg.Wait()
	if s.Len() > 50 {
		t.Fatalf("store exceeded bound: %d", s.Len())
	}
}
