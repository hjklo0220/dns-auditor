package inventory

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func ns(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func svc(namespace, name string, ports ...int32) *corev1.Service {
	s := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	for _, p := range ports {
		s.Spec.Ports = append(s.Spec.Ports, corev1.ServicePort{Port: p, Protocol: corev1.ProtocolTCP})
	}
	return s
}

func pod(namespace, deploy, hash, uid, ip string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace, Name: deploy + "-" + hash + "-" + uid, UID: types.UID(uid),
			Labels:          map[string]string{"pod-template-hash": hash},
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: deploy + "-" + hash, Controller: ptr(true)}},
			ManagedFields:   []metav1.ManagedFieldsEntry{{Manager: "kubelet"}},
			Annotations:     map[string]string{"big": "value"},
		},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "x"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip, PodIPs: []corev1.PodIP{{IP: ip}}},
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func workloadIs(l *Live, ip, want string) func() bool {
	return func() bool {
		w, ok := l.WorkloadForIP(netip.MustParseAddr(ip))
		if want == "" {
			return !ok
		}
		return ok && w.String() == want
	}
}

func startLive(t *testing.T, objs ...runtime.Object) (*Live, *fake.Clientset, *clock) {
	t.Helper()
	client := fake.NewSimpleClientset(objs...)
	c := &clock{t: time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)}
	l := NewLive(LiveOptions{Grace: time.Minute, Now: c.now})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := l.Start(ctx, client, 0); err != nil {
		t.Fatal(err)
	}
	return l, client, c
}

func TestLiveInitialSync(t *testing.T) {
	l, _, _ := startLive(t,
		ns("shop"), ns("billing"),
		svc("billing", "billing", 8080), svc("legacy", "billing", 80),
		pod("shop", "storefront", "abc12", "u1", "10.0.1.10"),
	)
	if !l.HasNamespace("SHOP") || l.HasNamespace("nope") {
		t.Fatal("namespaces")
	}
	got := l.ServicesNamed("Billing")
	if len(got) != 2 || got[0].Namespace != "billing" || got[1].Namespace != "legacy" || got[0].Ports[0].Port != 8080 || got[0].Ports[0].Protocol != "TCP" {
		t.Fatalf("services %+v", got)
	}
	if !workloadIs(l, "10.0.1.10", "shop/storefront")() {
		t.Fatal("pod not indexed")
	}
	if _, ok := l.WorkloadForIP(netip.Addr{}); ok {
		t.Fatal("zero IP matched")
	}
	if n, s, p := l.Stats(); n != 2 || s != 1 || p != 1 {
		t.Fatalf("stats %d %d %d", n, s, p)
	}
}

func TestLiveFollowsChanges(t *testing.T) {
	l, client, _ := startLive(t, ns("shop"))
	ctx := context.Background()
	core := client.CoreV1()

	if _, err := core.Services("billing").Create(ctx, svc("billing", "billing", 8080), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := core.Namespaces().Create(ctx, ns("billing"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "service add", func() bool { return len(l.ServicesNamed("billing")) == 1 && l.HasNamespace("billing") })

	s := svc("billing", "billing", 9090)
	if _, err := core.Services("billing").Update(ctx, s, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "service update", func() bool {
		g := l.ServicesNamed("billing")
		return len(g) == 1 && g[0].Ports[0].Port == 9090
	})

	if err := core.Services("billing").Delete(ctx, "billing", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "service delete", func() bool { return len(l.ServicesNamed("billing")) == 0 })

	if err := core.Namespaces().Delete(ctx, "billing", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "namespace delete", func() bool { return !l.HasNamespace("billing") })
}

func TestLivePodGraceAndIPReuse(t *testing.T) {
	l, client, c := startLive(t, pod("shop", "storefront", "abc12", "u1", "10.0.1.10"))
	ctx := context.Background()
	pods := client.CoreV1().Pods("shop")

	// Deleted Pod: still attributed during the grace period, then forgotten.
	if err := pods.Delete(ctx, "storefront-abc12-u1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "delete observed", func() bool {
		l.mu.RLock()
		defer l.mu.RUnlock()
		return !l.byIP[netip.MustParseAddr("10.0.1.10")].deletedAt.IsZero()
	})
	if !workloadIs(l, "10.0.1.10", "shop/storefront")() {
		t.Fatal("lost workload inside grace period")
	}
	c.add(2 * time.Minute)
	if !workloadIs(l, "10.0.1.10", "")() {
		t.Fatal("still attributed after grace period")
	}
	l.Prune()
	if _, _, p := l.Stats(); p != 0 {
		t.Fatalf("prune left %d entries", p)
	}

	// IP reuse: a new Pod takes the IP immediately, and the old Pod's late
	// delete must not mark the new owner as deleted.
	if _, err := pods.Create(ctx, pod("shop", "cart", "def34", "u2", "10.0.1.20"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "cart", workloadIs(l, "10.0.1.20", "shop/cart"))
	if err := pods.Delete(ctx, "cart-def34-u2", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := pods.Create(ctx, pod("shop", "checkout", "aa11", "u3", "10.0.1.20"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "reuse", workloadIs(l, "10.0.1.20", "shop/checkout"))
	l.deletePod(pod("shop", "cart", "def34", "u2", "10.0.1.20")) // replayed late delete
	c.add(2 * time.Minute)
	if !workloadIs(l, "10.0.1.20", "shop/checkout")() {
		t.Fatal("late delete of old Pod evicted the new owner")
	}
}

func TestLivePodUpdates(t *testing.T) {
	l, client, c := startLive(t, pod("shop", "storefront", "abc12", "u1", "10.0.1.10"))
	ctx := context.Background()
	pods := client.CoreV1().Pods("shop")

	// IP change: old IP enters grace, new IP is attributed.
	p := pod("shop", "storefront", "abc12", "u1", "10.0.1.11")
	if _, err := pods.Update(ctx, p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "new ip", workloadIs(l, "10.0.1.11", "shop/storefront"))
	c.add(2 * time.Minute)
	if !workloadIs(l, "10.0.1.10", "")() {
		t.Fatal("old IP still attributed after grace")
	}

	// Finished Pod releases its IP.
	p = pod("shop", "storefront", "abc12", "u1", "10.0.1.11")
	p.Status.Phase = corev1.PodSucceeded
	if _, err := pods.Update(ctx, p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "finished pod marked", func() bool {
		l.mu.RLock()
		defer l.mu.RUnlock()
		return !l.byIP[netip.MustParseAddr("10.0.1.11")].deletedAt.IsZero()
	})

	// Host-network Pods are never indexed.
	h := pod("kube-system", "agent", "zz99", "u9", "10.0.0.5")
	h.Spec.HostNetwork = true
	if _, err := client.CoreV1().Pods("kube-system").Create(ctx, h, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if !workloadIs(l, "10.0.0.5", "")() {
		t.Fatal("hostNetwork pod indexed")
	}
}

func TestTombstonesAndWrongTypes(t *testing.T) {
	l := NewLive(LiveOptions{})
	l.upsertNamespace(ns("shop"))
	l.upsertService(svc("shop", "web", 80))
	l.upsertPod(pod("shop", "web", "h1", "u1", "10.0.0.1"))

	l.deleteNamespace(cache.DeletedFinalStateUnknown{Key: "shop", Obj: ns("shop")})
	l.deleteService(cache.DeletedFinalStateUnknown{Key: "shop/web", Obj: svc("shop", "web")})
	l.deletePod(cache.DeletedFinalStateUnknown{Key: "shop/web", Obj: pod("shop", "web", "h1", "u1", "10.0.0.1")})
	if l.HasNamespace("shop") || len(l.ServicesNamed("web")) != 0 {
		t.Fatal("tombstones not applied")
	}
	if _, ok := l.WorkloadForIP(netip.MustParseAddr("10.0.0.1")); !ok {
		t.Fatal("tombstoned pod should still be in grace")
	}
	for _, f := range []func(any){l.upsertNamespace, l.deleteNamespace, l.upsertService, l.deleteService, l.upsertPod, l.deletePod} {
		f("not an object") // must be ignored, not panic
	}
	l.deleteService(svc("other", "missing")) // unknown service: no-op
}

func TestSlimDropsUnusedFields(t *testing.T) {
	p := pod("shop", "web", "h1", "u1", "10.0.0.1")
	o, err := slim(p)
	if err != nil {
		t.Fatal(err)
	}
	s := o.(*corev1.Pod)
	if s.ManagedFields != nil || s.Annotations != nil || len(s.Spec.Containers) != 0 || s.Status.PodIP != "10.0.0.1" || s.Labels["pod-template-hash"] != "h1" {
		t.Fatalf("slim kept the wrong fields: %+v", s)
	}
	if _, err := slim("not an object"); err != nil {
		t.Fatal(err)
	}
}

func TestStartFailsWhenContextDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := NewLive(LiveOptions{}).Start(ctx, fake.NewSimpleClientset(), 0)
	if err == nil {
		t.Fatal("want error when context is already cancelled")
	}
}

func TestPruneLoopStops(t *testing.T) {
	l := NewLive(LiveOptions{Grace: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.pruneLoop(ctx); close(done) }()
	time.Sleep(30 * time.Millisecond) // at least one tick
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pruneLoop did not stop")
	}
}
