package server

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	dnstapproto "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
	"github.com/miekg/dns"
	"go.uber.org/goleak"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func nxFrame(t *testing.T, name, ip string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.Response, m.Rcode = true, dns.RcodeNameError
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	typ, mt := dnstapproto.Dnstap_MESSAGE, dnstapproto.Message_CLIENT_RESPONSE
	b, err := proto.Marshal(&dnstapproto.Dnstap{Type: &typ, Message: &dnstapproto.Message{Type: &mt, QueryAddress: netip.MustParseAddr(ip).AsSlice(), ResponseMessage: wire}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServeEndToEnd(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "shop"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "billing"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "billing", Name: "billing"}, Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}}},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web-abc12-x", UID: types.UID("u1"), Labels: map[string]string{"pod-template-hash": "abc12"},
				OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "web-abc12"}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.1.10"},
		},
	)
	dln, _ := net.Listen("tcp", "127.0.0.1:0")
	hln, _ := net.Listen("tcp", "127.0.0.1:0")
	base := "http://" + hln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{Client: client, DnstapListener: dln, HTTPListener: hln, TTL: time.Minute})
	}()

	if code, _ := get(t, base+"/healthz"); code != 200 {
		waitFor(t, "healthz", func() bool { c, _ := get(t, base+"/healthz"); return c == 200 })
	}
	waitFor(t, "readyz", func() bool { c, _ := get(t, base+"/readyz"); return c == 200 })

	c, err := net.Dial("tcp", dln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	w, err := framestream.NewWriter(c, &framestream.WriterOptions{ContentTypes: [][]byte{dnstapproto.FSContentType}, Bidirectional: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := w.WriteFrame(nxFrame(t, "billing.shop.svc.cluster.local.", "10.0.1.10")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	var got []Finding
	waitFor(t, "finding", func() bool {
		_, body := get(t, base+"/findings")
		got = nil
		_ = json.Unmarshal([]byte(body), &got)
		return len(got) == 1 && got[0].Count == 3
	})
	f := got[0]
	if f.CallerWorkload != "shop/web" || f.Name != "billing" || f.UseInstead != "billing.billing.svc.cluster.local:8080" {
		t.Fatalf("finding %+v", f)
	}

	_, m := get(t, base+"/metrics")
	for _, want := range []string{
		`dns_auditor_misroute_lookups_total{caller_namespace="shop",caller_workload="shop/web",name="billing",suggestion="billing.billing.svc.cluster.local:8080"} 3`,
		`dns_auditor_responses_total{category="misroute"} 3`,
		`dns_auditor_dnstap_connections_active 1`,
		`dns_auditor_inventory_objects{kind="pod_ip"} 1`,
		`go_goroutines`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %q", want)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestReadyzBeforeSync(t *testing.T) {
	// A context cancelled before the inventory syncs: Run must still return cleanly.
	hln, _ := net.Listen("tcp", "127.0.0.1:0")
	dln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, Config{Client: fake.NewSimpleClientset(), DnstapListener: dln, HTTPListener: hln}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigErrors(t *testing.T) {
	if err := Run(context.Background(), Config{}); err == nil {
		t.Fatal("want error without client")
	}
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = busy.Close() }()
	if err := Run(context.Background(), Config{Client: fake.NewSimpleClientset(), DnstapAddr: busy.Addr().String()}); err == nil {
		t.Fatal("want dnstap listen error")
	}
	dln, _ := net.Listen("tcp", "127.0.0.1:0")
	if err := Run(context.Background(), Config{Client: fake.NewSimpleClientset(), DnstapListener: dln, HTTPAddr: busy.Addr().String()}); err == nil {
		t.Fatal("want http listen error")
	}
}

func TestDefaults(t *testing.T) {
	var c Config
	c.defaults()
	if c.DnstapAddr != ":6000" || c.HTTPAddr != ":8080" || c.TTL != 15*time.Minute || c.QueueSize != 10000 || c.Log == nil {
		t.Fatalf("%+v", c)
	}
}
