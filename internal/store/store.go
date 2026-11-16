// Package store keeps the current findings of the live auditor.
//
// A finding stays "active" while it keeps happening: once a caller stops
// making the bad lookup (because it was fixed) for longer than the TTL, the
// finding disappears from the snapshot. The number of findings is bounded so
// a misbehaving client cannot blow up memory or metric cardinality.
package store

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/hjklo0220/dns-auditor/internal/report"
	"github.com/hjklo0220/dns-auditor/internal/rule"
)

// Key identifies a finding.
type Key struct {
	CallerNamespace string
	CallerWorkload  string // "ns/name" or report.UnknownWorkload
	Name            string
}

// Entry is one finding.
type Entry struct {
	Key
	Suggestions []rule.Suggestion
	Count       uint64
	FirstSeen   time.Time
	LastSeen    time.Time
	CallerIPs   []netip.Addr // only for unknown callers, bounded
}

// Options configures a Store.
type Options struct {
	TTL         time.Duration // default 15m
	MaxFindings int           // default 1000
	Now         func() time.Time
}

const maxIPs = 10

// Store is safe for concurrent use.
type Store struct {
	ttl time.Duration
	max int
	now func() time.Time

	mu      sync.Mutex
	m       map[Key]*Entry
	evicted uint64
}

// New returns an empty Store.
func New(o Options) *Store {
	if o.TTL <= 0 {
		o.TTL = 15 * time.Minute
	}
	if o.MaxFindings <= 0 {
		o.MaxFindings = 1000
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Store{ttl: o.TTL, max: o.MaxFindings, now: o.Now, m: map[Key]*Entry{}}
}

// Add records one occurrence of f. at is when it happened; zero means now.
func (s *Store) Add(f *rule.Finding, at time.Time) {
	if f == nil {
		return
	}
	if now := s.now(); at.IsZero() || at.After(now) {
		at = now // a future time would keep the finding active past its TTL
	}
	wl := report.UnknownWorkload
	if f.Caller.Name != "" {
		wl = f.Caller.String()
	}
	k := Key{CallerNamespace: f.CallerNamespace, CallerWorkload: wl, Name: f.Name}

	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[k]
	if !ok {
		if len(s.m) >= s.max {
			s.pruneLocked()
		}
		if len(s.m) >= s.max {
			s.evictOldestLocked()
		}
		e = &Entry{Key: k, FirstSeen: at}
		s.m[k] = e
	}
	e.Count++
	if at.After(e.LastSeen) {
		e.LastSeen = at
	}
	if at.Before(e.FirstSeen) {
		e.FirstSeen = at
	}
	e.Suggestions = f.Suggestions // the inventory may have changed
	if wl == report.UnknownWorkload && f.CallerIP.IsValid() && len(e.CallerIPs) < maxIPs && !contains(e.CallerIPs, f.CallerIP) {
		e.CallerIPs = append(e.CallerIPs, f.CallerIP)
	}
}

func contains(ips []netip.Addr, ip netip.Addr) bool {
	for _, x := range ips {
		if x == ip {
			return true
		}
	}
	return false
}

func (s *Store) evictOldestLocked() {
	var oldest *Entry
	for _, e := range s.m {
		if oldest == nil || e.LastSeen.Before(oldest.LastSeen) {
			oldest = e
		}
	}
	if oldest != nil {
		delete(s.m, oldest.Key)
		s.evicted++
	}
}

func (s *Store) pruneLocked() {
	cutoff := s.now().Add(-s.ttl)
	for k, e := range s.m {
		if e.LastSeen.Before(cutoff) {
			delete(s.m, k)
		}
	}
}

// Prune drops findings not seen within the TTL.
func (s *Store) Prune() {
	s.mu.Lock()
	s.pruneLocked()
	s.mu.Unlock()
}

// Active returns copies of the findings seen within the TTL, most frequent
// first, then by caller and name.
func (s *Store) Active() []Entry {
	cutoff := s.now().Add(-s.ttl)
	s.mu.Lock()
	out := make([]Entry, 0, len(s.m))
	for _, e := range s.m {
		if !e.LastSeen.Before(cutoff) {
			c := *e
			c.Suggestions = append([]rule.Suggestion(nil), e.Suggestions...)
			c.CallerIPs = append([]netip.Addr(nil), e.CallerIPs...)
			out = append(out, c)
		}
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if a.CallerNamespace != b.CallerNamespace {
			return a.CallerNamespace < b.CallerNamespace
		}
		if a.CallerWorkload != b.CallerWorkload {
			return a.CallerWorkload < b.CallerWorkload
		}
		return a.Name < b.Name
	})
	return out
}

// Evicted is the number of findings dropped because the store was full.
func (s *Store) Evicted() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evicted
}

// Len is the number of stored findings, active or not yet pruned.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}
