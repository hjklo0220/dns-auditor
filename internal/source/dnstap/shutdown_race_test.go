package dnstap

import (
	"context"
	"net"
	"testing"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
	"github.com/hjklo0220/dns-auditor/internal/event"
)

type slowLn struct {
	net.Listener
	ctx context.Context
}

// Accept returns a real accepted conn, but only after ctx is cancelled
// (models the scheduler delaying the goroutine between Accept and conns[c]=...).
func (l slowLn) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	<-l.ctx.Done()
	time.Sleep(50 * time.Millisecond) // AfterFunc has run by now
	return c, nil
}

// Regression (review #3): a connection accepted while shutdown runs must still be closed.
func TestShutdownRaceAcceptVsCancel(t *testing.T) {
	inner, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	r := &Receiver{Out: make(chan event.Event, 1)}
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, slowLn{inner, ctx}) }()
	c, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	go func() {
		_, _ = framestream.NewWriter(c, &framestream.WriterOptions{ContentTypes: [][]byte{dnstap.FSContentType}, Bidirectional: true})
		// stay connected and idle, like CoreDNS between bursts
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return 3s after cancel: accepted conn was never closed")
	}
}
