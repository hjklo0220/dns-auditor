package inventory

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// Static is an in-memory Lookup built from a snapshot. It is used by the
// analyze command and by tests; the serve command uses an informer-backed
// implementation with the same interface.
type Static struct {
	mu         sync.RWMutex
	namespaces map[string]struct{}
	services   map[string][]Service // keyed by lower-case Service name
	workloads  map[netip.Addr]Workload
}

// NewStatic returns an empty Static inventory.
func NewStatic() *Static {
	return &Static{
		namespaces: map[string]struct{}{},
		services:   map[string][]Service{},
		workloads:  map[netip.Addr]Workload{},
	}
}

// AddNamespace records a namespace.
func (s *Static) AddNamespace(ns string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.namespaces[strings.ToLower(ns)] = struct{}{}
}

// AddService records a Service (and its namespace).
func (s *Static) AddService(svc Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.namespaces[strings.ToLower(svc.Namespace)] = struct{}{}
	key := strings.ToLower(svc.Name)
	list := s.services[key]
	for i, existing := range list {
		if existing.Namespace == svc.Namespace {
			list[i] = svc
			return
		}
	}
	list = append(list, svc)
	sort.Slice(list, func(i, j int) bool { return list[i].Namespace < list[j].Namespace })
	s.services[key] = list
}

// AddPod records the workload that owns a Pod IP.
func (s *Static) AddPod(ip netip.Addr, w Workload) {
	if !ip.IsValid() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workloads[ip.Unmap()] = w
}

// HasNamespace implements Lookup.
func (s *Static) HasNamespace(ns string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.namespaces[strings.ToLower(ns)]
	return ok
}

// ServicesNamed implements Lookup.
func (s *Static) ServicesNamed(name string) []Service {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := s.services[strings.ToLower(name)]
	out := make([]Service, len(list))
	copy(out, list)
	return out
}

// WorkloadForIP implements Lookup.
func (s *Static) WorkloadForIP(ip netip.Addr) (Workload, bool) {
	if !ip.IsValid() {
		return Workload{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	w, ok := s.workloads[ip.Unmap()]
	return w, ok
}
