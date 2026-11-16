// Command dnstap-replay turns recorded CoreDNS log lines into dnstap
// CLIENT_RESPONSE frames and sends them to a dns-auditor, like CoreDNS would.
// Useful for smoke tests and for load-testing the receiver.
//
//	go run ./hack/dnstap-replay -addr 127.0.0.1:6000 -rate 0 coredns.log...
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"

	"github.com/hjklo0220/dns-auditor/internal/source/corednslog"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:6000", "dns-auditor dnstap address")
	rate := flag.Int("rate", 0, "frames per second (0 = as fast as possible)")
	loops := flag.Int("loops", 1, "replay the input this many times")
	flag.Parse()
	if err := run(*addr, *rate, *loops, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "dnstap-replay:", err)
		os.Exit(1)
	}
}

func run(addr string, rate, loops int, files []string) error {
	var frames [][]byte
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			ev, ok := corednslog.ParseLine(sc.Text())
			if !ok {
				continue
			}
			b, err := toFrame(ev.QName, ev.QType, ev.Rcode, ev.ClientIP.AsSlice())
			if err != nil {
				return err
			}
			frames = append(frames, b)
		}
		_ = f.Close()
		if err := sc.Err(); err != nil {
			return err
		}
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	w, err := framestream.NewWriter(c, &framestream.WriterOptions{ContentTypes: [][]byte{dnstap.FSContentType}, Bidirectional: true, Timeout: 10 * time.Second})
	if err != nil {
		return err
	}
	var tick <-chan time.Time
	if rate > 0 {
		t := time.NewTicker(time.Second / time.Duration(rate))
		defer t.Stop()
		tick = t.C
	}
	start, sent := time.Now(), 0
	for range loops {
		for _, b := range frames {
			if tick != nil {
				<-tick
			}
			if _, err := w.WriteFrame(b); err != nil {
				return err
			}
			sent++
		}
	}
	if err := w.Close(); err != nil {
		return err
	}
	el := time.Since(start)
	fmt.Printf("sent %d frames in %v (%.0f/s)\n", sent, el.Round(time.Millisecond), float64(sent)/el.Seconds())
	return nil
}

func toFrame(qname, qtype, rcode string, client []byte) ([]byte, error) {
	m := new(dns.Msg)
	t, ok := dns.StringToType[qtype]
	if !ok {
		t = dns.TypeA
	}
	m.SetQuestion(dns.Fqdn(qname), t)
	m.Response = true
	if rc, ok := dns.StringToRcode[rcode]; ok {
		m.Rcode = rc
	}
	wire, err := m.Pack()
	if err != nil {
		return nil, err
	}
	typ, mt := dnstap.Dnstap_MESSAGE, dnstap.Message_CLIENT_RESPONSE
	now := time.Now()
	sec, nsec := uint64(now.Unix()), uint32(now.Nanosecond())
	return proto.Marshal(&dnstap.Dnstap{Type: &typ, Message: &dnstap.Message{
		Type: &mt, QueryAddress: client, ResponseMessage: wire, ResponseTimeSec: &sec, ResponseTimeNsec: &nsec,
	}})
}
