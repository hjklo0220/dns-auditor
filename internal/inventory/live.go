package inventory

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Live is a Lookup kept up to date by Kubernetes informers.
//
// Pod IPs are remembered for a grace period after the Pod is gone: DNS
// queries from a Pod that was just replaced are still attributed to its
// workload instead of "unknown". A new Pod that gets the same IP takes over
// immediately.
type Live struct {
	grace       time.Duration
	syncTimeout time.Duration
	now         func() time.Time

	mu       sync.RWMutex
	ns       map[string]struct{}
	services map[string]map[string]Service // lower name -> namespace -> Service
	byIP     map[netip.Addr]podEntry
	podIPs   map[types.UID][]netip.Addr
}

type podEntry struct {
	uid         types.UID
	workload    Workload
	terminating bool      // DeletionTimestamp set
	deletedAt   time.Time // zero while the Pod exists
}

// live reports whether e is a Pod that still runs and is not shutting down.
func (e podEntry) live() bool { return e.deletedAt.IsZero() && !e.terminating }

// LiveOptions configures NewLive.
type LiveOptions struct {
	// Grace keeps the IP of a deleted Pod attributed to its workload.
	// Default 5m.
	Grace time.Duration
	// SyncTimeout bounds the initial cache sync. A sync that never finishes
	// (typically missing RBAC for list/watch) becomes an error instead of a
	// hang. Default 2m.
	SyncTimeout time.Duration
	// Now overrides the clock in tests.
	Now func() time.Time
}

// NewLive returns an empty Live inventory. Call Start to fill it.
func NewLive(opt LiveOptions) *Live {
	if opt.Grace <= 0 {
		opt.Grace = 5 * time.Minute
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.SyncTimeout <= 0 {
		opt.SyncTimeout = 2 * time.Minute
	}
	return &Live{
		grace:       opt.Grace,
		syncTimeout: opt.SyncTimeout,
		now:         opt.Now,
		ns:          map[string]struct{}{},
		services:    map[string]map[string]Service{},
		byIP:        map[netip.Addr]podEntry{},
		podIPs:      map[types.UID][]netip.Addr{},
	}
}

// Start registers informers for Namespaces, Services and Pods, starts them,
// and blocks until the caches have synced or ctx is done. The informers keep
// running until ctx is cancelled.
func (l *Live) Start(ctx context.Context, client kubernetes.Interface, resync time.Duration) error {
	f := informers.NewSharedInformerFactoryWithOptions(client, resync, informers.WithTransform(slim))
	handlers := []struct {
		inf cache.SharedIndexInformer
		h   cache.ResourceEventHandlerFuncs
	}{
		{f.Core().V1().Namespaces().Informer(), cache.ResourceEventHandlerFuncs{
			AddFunc:    func(o any) { l.upsertNamespace(o) },
			UpdateFunc: func(_, o any) { l.upsertNamespace(o) },
			DeleteFunc: func(o any) { l.deleteNamespace(o) },
		}},
		{f.Core().V1().Services().Informer(), cache.ResourceEventHandlerFuncs{
			AddFunc:    func(o any) { l.upsertService(o) },
			UpdateFunc: func(_, o any) { l.upsertService(o) },
			DeleteFunc: func(o any) { l.deleteService(o) },
		}},
		{f.Core().V1().Pods().Informer(), cache.ResourceEventHandlerFuncs{
			AddFunc:    func(o any) { l.upsertPod(o) },
			UpdateFunc: func(_, o any) { l.upsertPod(o) },
			DeleteFunc: func(o any) { l.deletePod(o) },
		}},
	}
	var synced []cache.InformerSynced
	for _, x := range handlers {
		reg, err := x.inf.AddEventHandler(x.h)
		if err != nil {
			return fmt.Errorf("add event handler: %w", err)
		}
		synced = append(synced, reg.HasSynced)
	}
	f.Start(ctx.Done())
	syncCtx, cancel := context.WithTimeout(ctx, l.syncTimeout)
	defer cancel()
	if !cache.WaitForCacheSync(syncCtx.Done(), synced...) {
		if ctx.Err() != nil {
			return fmt.Errorf("inventory: caches did not sync: %w", context.Cause(ctx))
		}
		return fmt.Errorf("inventory: caches did not sync within %v (does the service account have list/watch on namespaces, services and pods?)", l.syncTimeout)
	}
	go l.pruneLoop(ctx)
	return nil
}

// slim drops fields we never read so the informer caches stay small.
func slim(obj any) (any, error) {
	if m, ok := obj.(metav1.Object); ok {
		m.SetManagedFields(nil)
		a := m.GetAnnotations()
		if len(a) > 0 {
			m.SetAnnotations(nil)
		}
	}
	if p, ok := obj.(*corev1.Pod); ok {
		p.Spec = corev1.PodSpec{HostNetwork: p.Spec.HostNetwork}
		p.Status = corev1.PodStatus{PodIP: p.Status.PodIP, PodIPs: p.Status.PodIPs, Phase: p.Status.Phase}
	}
	return obj, nil
}

func (l *Live) pruneLoop(ctx context.Context) {
	t := time.NewTicker(l.grace)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.Prune()
		}
	}
}

// Prune forgets deleted Pods whose grace period has passed. Lookups already
// ignore them; this only frees memory.
func (l *Live) Prune() {
	cutoff := l.now().Add(-l.grace)
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, e := range l.byIP {
		if !e.deletedAt.IsZero() && e.deletedAt.Before(cutoff) {
			delete(l.byIP, ip)
		}
	}
}

// unwrap handles the tombstones informers deliver for missed deletes.
func unwrap(o any) any {
	if t, ok := o.(cache.DeletedFinalStateUnknown); ok {
		return t.Obj
	}
	return o
}

func (l *Live) upsertNamespace(o any) {
	n, ok := unwrap(o).(*corev1.Namespace)
	if !ok {
		return
	}
	l.mu.Lock()
	l.ns[strings.ToLower(n.Name)] = struct{}{}
	l.mu.Unlock()
}

func (l *Live) deleteNamespace(o any) {
	n, ok := unwrap(o).(*corev1.Namespace)
	if !ok {
		return
	}
	l.mu.Lock()
	delete(l.ns, strings.ToLower(n.Name))
	l.mu.Unlock()
}

func (l *Live) upsertService(o any) {
	s, ok := unwrap(o).(*corev1.Service)
	if !ok {
		return
	}
	svc := Service{Namespace: s.Namespace, Name: s.Name}
	for _, p := range s.Spec.Ports {
		svc.Ports = append(svc.Ports, Port{Name: p.Name, Port: p.Port, Protocol: string(p.Protocol)})
	}
	key := strings.ToLower(s.Name)
	l.mu.Lock()
	defer l.mu.Unlock()
	m := l.services[key]
	if m == nil {
		m = map[string]Service{}
		l.services[key] = m
	}
	m[s.Namespace] = svc
}

func (l *Live) deleteService(o any) {
	s, ok := unwrap(o).(*corev1.Service)
	if !ok {
		return
	}
	key := strings.ToLower(s.Name)
	l.mu.Lock()
	defer l.mu.Unlock()
	if m := l.services[key]; m != nil {
		delete(m, s.Namespace)
		if len(m) == 0 {
			delete(l.services, key)
		}
	}
}

func podAddrs(p *corev1.Pod) []netip.Addr {
	if p.Spec.HostNetwork {
		return nil // shares the node IP; cannot be attributed to one workload
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, raw := range append([]string{p.Status.PodIP}, ipStrings(p.Status.PodIPs)...) {
		if ip, err := netip.ParseAddr(raw); err == nil && !seen[ip.Unmap()] {
			seen[ip.Unmap()] = true
			out = append(out, ip.Unmap())
		}
	}
	return out
}

func ipStrings(ips []corev1.PodIP) []string {
	out := make([]string, len(ips))
	for i, p := range ips {
		out[i] = p.IP
	}
	return out
}

func (l *Live) upsertPod(o any) {
	p, ok := unwrap(o).(*corev1.Pod)
	if !ok {
		return
	}
	// A finished Pod's IP can be handed to a new Pod; stop claiming it.
	if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
		l.deletePod(p)
		return
	}
	var owners []OwnerRef
	for _, r := range p.OwnerReferences {
		owners = append(owners, OwnerRef{Kind: r.Kind, Name: r.Name, Controller: r.Controller})
	}
	w := WorkloadFromPod(p.Namespace, p.Name, p.Labels, owners)
	ips := podAddrs(p)
	terminating := p.DeletionTimestamp != nil

	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	keep := map[netip.Addr]bool{}
	for _, ip := range ips {
		keep[ip] = true
		// A terminating Pod's late update must not take an IP back from a
		// newer live Pod (events for different Pods are not ordered).
		if cur, ok := l.byIP[ip]; ok && cur.uid != p.UID && cur.live() && terminating {
			continue
		}
		l.byIP[ip] = podEntry{uid: p.UID, workload: w, terminating: terminating}
	}
	for _, old := range l.podIPs[p.UID] { // IPs this Pod no longer has
		if !keep[old] {
			l.markDeletedLocked(old, p.UID, now)
		}
	}
	if len(ips) > 0 {
		l.podIPs[p.UID] = ips
	} else {
		delete(l.podIPs, p.UID)
	}
}

func (l *Live) deletePod(o any) {
	p, ok := unwrap(o).(*corev1.Pod)
	if !ok {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	ips := l.podIPs[p.UID]
	if len(ips) == 0 {
		ips = podAddrs(p)
	}
	for _, ip := range ips {
		l.markDeletedLocked(ip, p.UID, now)
	}
	delete(l.podIPs, p.UID)
}

// markDeletedLocked starts the grace period for ip, but only if it still
// belongs to uid (a newer Pod may already own it).
func (l *Live) markDeletedLocked(ip netip.Addr, uid types.UID, now time.Time) {
	if e, ok := l.byIP[ip]; ok && e.uid == uid && e.deletedAt.IsZero() {
		e.deletedAt = now
		l.byIP[ip] = e
	}
}

// HasNamespace implements Lookup.
func (l *Live) HasNamespace(ns string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.ns[strings.ToLower(ns)]
	return ok
}

// ServicesNamed implements Lookup.
func (l *Live) ServicesNamed(name string) []Service {
	l.mu.RLock()
	m := l.services[strings.ToLower(name)]
	out := make([]Service, 0, len(m))
	for _, s := range m {
		out = append(out, s)
	}
	l.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Namespace < out[j].Namespace })
	return out
}

// WorkloadForIP implements Lookup.
func (l *Live) WorkloadForIP(ip netip.Addr) (Workload, bool) {
	if !ip.IsValid() {
		return Workload{}, false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	e, ok := l.byIP[ip.Unmap()]
	if !ok {
		return Workload{}, false
	}
	if !e.deletedAt.IsZero() && l.now().Sub(e.deletedAt) > l.grace {
		return Workload{}, false
	}
	return e.workload, true
}

// Stats reports cache sizes, for metrics.
func (l *Live) Stats() (namespaces, serviceNames, podIPs int) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.ns), len(l.services), len(l.byIP)
}
