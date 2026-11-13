package dnstap

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
	"github.com/miekg/dns"
	"go.uber.org/goleak"
	"google.golang.org/protobuf/proto"

	"github.com/hjklo0220/dns-auditor/internal/event"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func wireMsg(t testing.TB, name string, qtype uint16, rcode int) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.Response = true
	m.Rcode = rcode
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func frame(t testing.TB, mt dnstap.Message_Type, ip string, wire []byte) []byte {
	t.Helper()
	typ := dnstap.Dnstap_MESSAGE
	addr := netip.MustParseAddr(ip).AsSlice()
	sec, nsec := uint64(1763017200), uint32(5)
	d := &dnstap.Dnstap{Type: &typ, Message: &dnstap.Message{
		Type: &mt, QueryAddress: addr, ResponseMessage: wire,
		ResponseTimeSec: &sec, ResponseTimeNsec: &nsec,
	}}
	b, err := proto.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecode(t *testing.T) {
	nx := frame(t, dnstap.Message_CLIENT_RESPONSE, "10.0.1.10", wireMsg(t, "billing.shop.svc.cluster.local.", dns.TypeA, dns.RcodeNameError))
	ev, ok, err := Decode(nx)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	want := event.Event{Time: time.Unix(1763017200, 5).UTC(), ClientIP: netip.MustParseAddr("10.0.1.10"), QName: "billing.shop.svc.cluster.local.", QType: "A", Rcode: "NXDOMAIN"}
	if ev != want {
		t.Fatalf("got %+v\nwant %+v", ev, want)
	}

	// Non-NXDOMAIN: rcode only, no full parse.
	ok6 := frame(t, dnstap.Message_CLIENT_RESPONSE, "fd00::1", wireMsg(t, "x.", dns.TypeAAAA, dns.RcodeSuccess))
	ev, ok, err = Decode(ok6)
	if err != nil || !ok || ev.Rcode != "NOERROR" || ev.QName != "" || ev.ClientIP != netip.MustParseAddr("fd00::1") {
		t.Fatalf("noerror: %+v ok=%v err=%v", ev, ok, err)
	}

	// IPv4-mapped client address is unmapped.
	mapped := netip.MustParseAddr("::ffff:10.0.1.10").AsSlice()
	mt := dnstap.Message_CLIENT_RESPONSE
	typ := dnstap.Dnstap_MESSAGE
	b, _ := proto.Marshal(&dnstap.Dnstap{Type: &typ, Message: &dnstap.Message{Type: &mt, QueryAddress: mapped, ResponseMessage: wireMsg(t, "x.", dns.TypeA, dns.RcodeServerFailure)}})
	if ev, ok, err = Decode(b); err != nil || !ok || ev.ClientIP != netip.MustParseAddr("10.0.1.10") || ev.Rcode != "SERVFAIL" || !ev.Time.IsZero() {
		t.Fatalf("mapped: %+v ok=%v err=%v", ev, ok, err)
	}

	// Unknown rcode and qtype get numeric names.
	w := wireMsg(t, "x.", 65280, dns.RcodeNameError)
	w[3] = w[3]&0xF0 | 0x0C // rcode 12 is unassigned (11 is DSOTYPENI)
	if ev, _, err = Decode(frame(t, dnstap.Message_CLIENT_RESPONSE, "10.0.0.1", w)); err != nil || ev.Rcode != "RCODE12" || ev.QName != "" {
		t.Fatalf("unknown rcode: %+v err=%v", ev, err)
	}
	if ev, _, err = Decode(frame(t, dnstap.Message_CLIENT_RESPONSE, "10.0.0.1", wireMsg(t, "x.", 65280, dns.RcodeNameError))); err != nil || ev.QType != "TYPE65280" {
		t.Fatalf("unknown qtype: %+v err=%v", ev, err)
	}
}

func TestDecodeIgnoredAndErrors(t *testing.T) {
	q := frame(t, dnstap.Message_CLIENT_QUERY, "10.0.0.1", wireMsg(t, "x.", dns.TypeA, 0))
	if _, ok, err := Decode(q); ok || err != nil {
		t.Fatalf("client query should be ignored: ok=%v err=%v", ok, err)
	}
	if _, ok, err := Decode(frame(t, dnstap.Message_RESOLVER_RESPONSE, "10.0.0.1", wireMsg(t, "x.", dns.TypeA, 0))); ok || err != nil {
		t.Fatal("resolver response should be ignored")
	}
	other := dnstap.Dnstap_Type(99) // valid frame of an unknown top-level type
	ob, _ := proto.Marshal(&dnstap.Dnstap{Type: &other})
	if _, ok, err := Decode(ob); ok || err != nil {
		t.Fatalf("unknown top-level type: ok=%v err=%v", ok, err)
	}
	bad := [][]byte{
		nil, // proto2 required field "type" missing
		{0xff, 0xff, 0xff},
		frame(t, dnstap.Message_CLIENT_RESPONSE, "10.0.0.1", nil),
		frame(t, dnstap.Message_CLIENT_RESPONSE, "10.0.0.1", []byte{1, 2, 3}),
	}
	trunc := wireMsg(t, "billing.shop.svc.cluster.local.", dns.TypeA, dns.RcodeNameError)
	bad = append(bad, frame(t, dnstap.Message_CLIENT_RESPONSE, "10.0.0.1", trunc[:15]))
	noQ := wireMsg(t, "x.", dns.TypeA, dns.RcodeNameError)
	noQ[5] = 0 // QDCOUNT = 0
	bad = append(bad, frame(t, dnstap.Message_CLIENT_RESPONSE, "10.0.0.1", noQ[:12]))
	for i, b := range bad {
		if _, ok, err := Decode(b); ok || err == nil {
			t.Fatalf("case %d: want error, ok=%v err=%v", i, ok, err)
		}
	}
}

// sender opens a bidirectional Frame Streams connection like CoreDNS does.
func sender(t *testing.T, addr string) (*framestream.Writer, net.Conn) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	w, err := framestream.NewWriter(c, &framestream.WriterOptions{ContentTypes: [][]byte{dnstap.FSContentType}, Bidirectional: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return w, c
}

func serve(t *testing.T, out chan event.Event) (*Receiver, string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &Receiver{Out: out}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, ln) }()
	return r, ln.Addr().String(), func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not stop")
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestReceiverEndToEnd(t *testing.T) {
	out := make(chan event.Event, 100)
	r, addr, stop := serve(t, out)
	defer stop()

	w1, c1 := sender(t, addr)
	w2, c2 := sender(t, addr)
	nx := frame(t, dnstap.Message_CLIENT_RESPONSE, "10.0.1.10", wireMsg(t, "billing.shop.svc.cluster.local.", dns.TypeA, dns.RcodeNameError))
	for _, w := range []*framestream.Writer{w1, w2} {
		for _, f := range [][]byte{nx, frame(t, dnstap.Message_CLIENT_QUERY, "10.0.1.10", nil), {0xff, 0xff}} {
			if _, err := w.WriteFrame(f); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "frames", func() bool { return r.Stats.Frames.Load() == 6 })
	if got := len(out); got != 2 {
		t.Fatalf("events %d", got)
	}
	if e := <-out; e.QName != "billing.shop.svc.cluster.local." || e.Rcode != "NXDOMAIN" {
		t.Fatalf("event %+v", e)
	}
	s := &r.Stats
	if s.Connections.Load() != 2 || s.Active.Load() != 2 || s.Responses.Load() != 2 || s.Ignored.Load() != 2 || s.DecodeErrors.Load() != 2 || s.Dropped.Load() != 0 {
		t.Fatalf("stats conn=%d active=%d resp=%d ign=%d err=%d drop=%d", s.Connections.Load(), s.Active.Load(), s.Responses.Load(), s.Ignored.Load(), s.DecodeErrors.Load(), s.Dropped.Load())
	}

	// Clean close from one sender (STOP/FINISH handshake) ends that connection only.
	if err := w1.Close(); err != nil {
		t.Fatal(err)
	}
	_ = c1.Close()
	waitFor(t, "one connection closed", func() bool { return r.Stats.Active.Load() == 1 })
	_ = c2.Close()
	waitFor(t, "all connections closed", func() bool { return r.Stats.Active.Load() == 0 })
}

// The receiver must keep reading at full speed when nobody consumes events:
// the sender never blocks and the excess is counted as dropped.
func TestReceiverNeverBlocksSender(t *testing.T) {
	out := make(chan event.Event, 10) // never drained
	r, addr, stop := serve(t, out)
	defer stop()

	w, c := sender(t, addr)
	defer func() { _ = c.Close() }()
	nx := frame(t, dnstap.Message_CLIENT_RESPONSE, "10.0.1.10", wireMsg(t, "billing.shop.svc.cluster.local.", dns.TypeA, dns.RcodeNameError))
	const n = 20000
	start := time.Now()
	for range n {
		if _, err := w.WriteFrame(nx); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "all frames read", func() bool { return r.Stats.Frames.Load() == n })
	elapsed := time.Since(start)
	if got := r.Stats.Dropped.Load(); got != n-10 {
		t.Fatalf("dropped %d, want %d", got, n-10)
	}
	t.Logf("%d frames in %v (%.0f frames/s), %d dropped", n, elapsed, float64(n)/elapsed.Seconds(), r.Stats.Dropped.Load())
}

func TestReceiverRejectsWrongContentType(t *testing.T) {
	r, addr, stop := serve(t, make(chan event.Event, 1))
	defer stop()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, err = framestream.NewWriter(c, &framestream.WriterOptions{ContentTypes: [][]byte{[]byte("protobuf:other")}, Bidirectional: true, Timeout: 2 * time.Second})
	if err == nil {
		t.Fatal("want handshake failure for wrong content type")
	}
	waitFor(t, "connection dropped", func() bool { return r.Stats.Active.Load() == 0 && r.Stats.Connections.Load() == 1 })
}

func TestReceiverHandshakeTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &Receiver{Out: make(chan event.Event, 1), HandshakeTimeout: 50 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, ln) }()
	c, err := net.Dial("tcp", ln.Addr().String()) // connect but never handshake
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	waitFor(t, "silent connection timed out", func() bool { return r.Stats.Connections.Load() == 1 && r.Stats.Active.Load() == 0 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestServeReturnsAcceptError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close() // Accept fails immediately, ctx still alive
	r := &Receiver{Out: make(chan event.Event, 1)}
	if err := r.Serve(context.Background(), ln); err == nil {
		t.Fatal("want accept error")
	}
}

func TestServeClosesOpenConnectionsOnShutdown(t *testing.T) {
	r, addr, stop := serve(t, make(chan event.Event, 1))
	_, c := sender(t, addr) // handshake done, then idle
	defer func() { _ = c.Close() }()
	waitFor(t, "connected", func() bool { return r.Stats.Active.Load() == 1 })
	stop() // must not hang on the idle connection
	if r.Stats.Active.Load() != 0 {
		t.Fatal("connection left open")
	}
}

func BenchmarkDecodeNXDOMAIN(b *testing.B) {
	f := frame(b, dnstap.Message_CLIENT_RESPONSE, "10.0.1.10", wireMsg(b, "billing.shop.svc.cluster.local.", dns.TypeA, dns.RcodeNameError))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := Decode(f); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeNOERROR(b *testing.B) {
	f := frame(b, dnstap.Message_CLIENT_RESPONSE, "10.0.1.10", wireMsg(b, "api.example.com.", dns.TypeA, dns.RcodeSuccess))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := Decode(f); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(frame(f, dnstap.Message_CLIENT_RESPONSE, "10.0.1.10", wireMsg(f, "billing.shop.svc.cluster.local.", dns.TypeA, dns.RcodeNameError)))
	f.Add(frame(f, dnstap.Message_CLIENT_RESPONSE, "fd00::1", wireMsg(f, "x.", dns.TypeAAAA, dns.RcodeSuccess)))
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(t *testing.T, b []byte) {
		ev, ok, err := Decode(b)
		if ok && (err != nil || ev.Rcode == "") {
			t.Fatalf("accepted frame with empty rcode or error: %+v %v", ev, err)
		}
		if ok && ev.Rcode == "NXDOMAIN" && ev.QName == "" {
			t.Fatalf("NXDOMAIN without question: %+v", ev)
		}
	})
}
