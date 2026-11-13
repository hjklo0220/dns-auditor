// Package dnstap receives CoreDNS dnstap streams (Frame Streams over TCP or a
// Unix socket) and turns client responses into events.
//
// The receiver must never slow CoreDNS down. CoreDNS's dnstap plugin already
// drops messages when its own buffer is full, but a slow reader would still
// fill that buffer. So frames are read as fast as the socket delivers them,
// and when the downstream queue is full the event is dropped and counted
// instead of waiting.
//
// CoreDNS configuration (the "full" flag is required: the response code is
// only available in the wire-format message):
//
//	dnstap tcp://dns-auditor.<namespace>.svc.cluster.local:6000 full
package dnstap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"

	"github.com/hjklo0220/dns-auditor/internal/event"
)

// MaxFrameSize bounds one dnstap frame (CoreDNS frames are far smaller).
const MaxFrameSize = 96 * 1024

// Stats are cumulative counters, safe for concurrent reads.
type Stats struct {
	Connections  atomic.Uint64 // accepted connections
	Active       atomic.Int64  // currently open connections
	Frames       atomic.Uint64 // data frames read
	Responses    atomic.Uint64 // client responses turned into events
	Ignored      atomic.Uint64 // frames that are not client responses
	DecodeErrors atomic.Uint64 // frames that could not be decoded
	Dropped      atomic.Uint64 // events dropped because the queue was full
}

// Receiver accepts dnstap connections and emits one event per client response.
type Receiver struct {
	// Out receives events. Sends never block; see Stats.Dropped.
	Out chan<- event.Event
	// HandshakeTimeout bounds the Frame Streams handshake. Default 10s.
	HandshakeTimeout time.Duration
	Log              *slog.Logger

	Stats Stats
}

// Serve accepts connections on ln until ctx is done, then closes ln and all
// open connections and waits for their goroutines to finish.
func (r *Receiver) Serve(ctx context.Context, ln net.Listener) error {
	log := r.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		conns = map[net.Conn]struct{}{}
	)
	stop := context.AfterFunc(ctx, func() {
		_ = ln.Close()
		mu.Lock()
		for c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	})
	defer stop()

	for {
		c, err := ln.Accept()
		if err != nil {
			wg.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("dnstap accept: %w", err)
		}
		mu.Lock()
		conns[c] = struct{}{}
		mu.Unlock()
		r.Stats.Connections.Add(1)
		r.Stats.Active.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer r.Stats.Active.Add(-1)
			defer func() {
				mu.Lock()
				delete(conns, c)
				mu.Unlock()
				_ = c.Close()
			}()
			if err := r.handle(c); err != nil && ctx.Err() == nil {
				log.Warn("dnstap connection ended", "remote", c.RemoteAddr().String(), "err", err)
			}
		}()
	}
}

func (r *Receiver) handle(c net.Conn) error {
	timeout := r.HandshakeTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	fr, err := framestream.NewReader(c, &framestream.ReaderOptions{
		ContentTypes:  [][]byte{dnstap.FSContentType},
		Bidirectional: true,
		Timeout:       timeout,
	})
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	buf := make([]byte, MaxFrameSize)
	for {
		n, err := fr.ReadFrame(buf)
		switch {
		case errors.Is(err, framestream.ErrDataFrameTooLarge):
			r.Stats.DecodeErrors.Add(1)
			continue
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return err
		}
		r.Stats.Frames.Add(1)
		ev, ok, err := Decode(buf[:n])
		switch {
		case err != nil:
			r.Stats.DecodeErrors.Add(1)
		case !ok:
			r.Stats.Ignored.Add(1)
		default:
			r.Stats.Responses.Add(1)
			select {
			case r.Out <- ev:
			default:
				r.Stats.Dropped.Add(1)
			}
		}
	}
}

// Decode turns one dnstap frame into an event. ok is false for frames that
// are valid but not client responses (queries, resolver traffic).
//
// Only the DNS header and question are parsed, which is all the rules need.
func Decode(frame []byte) (ev event.Event, ok bool, err error) {
	var d dnstap.Dnstap
	if err := proto.Unmarshal(frame, &d); err != nil {
		return ev, false, err
	}
	m := d.GetMessage()
	if d.GetType() != dnstap.Dnstap_MESSAGE || m == nil || m.GetType() != dnstap.Message_CLIENT_RESPONSE {
		return ev, false, nil
	}
	wire := m.GetResponseMessage()
	if len(wire) == 0 {
		return ev, false, errors.New("client response without message bytes (is the CoreDNS dnstap plugin set to full?)")
	}
	if len(wire) < 12 {
		return ev, false, errors.New("short DNS message")
	}
	// RCODE is the low 4 bits of header byte 3. Only NXDOMAIN responses can
	// be findings, so everything else skips the full parse.
	rcode := int(wire[3] & 0x0F)
	ev.Rcode = rcodeString(rcode)
	if rcode == dns.RcodeNameError {
		msg := new(dns.Msg)
		if err := msg.Unpack(wire); err != nil {
			return ev, false, fmt.Errorf("unpack: %w", err)
		}
		if len(msg.Question) == 0 {
			return ev, false, errors.New("response without question")
		}
		q := msg.Question[0]
		ev.QName = q.Name
		ev.QType = dns.TypeToString[q.Qtype]
		if ev.QType == "" {
			ev.QType = fmt.Sprintf("TYPE%d", q.Qtype)
		}
	}
	if ip, ok := netip.AddrFromSlice(m.GetQueryAddress()); ok {
		ev.ClientIP = ip.Unmap()
	}
	if s := m.GetResponseTimeSec(); s > 0 {
		ev.Time = time.Unix(int64(s), int64(m.GetResponseTimeNsec())).UTC()
	}
	return ev, true, nil
}

func rcodeString(rc int) string {
	if s, ok := dns.RcodeToString[rc]; ok {
		return s
	}
	return fmt.Sprintf("RCODE%d", rc)
}
