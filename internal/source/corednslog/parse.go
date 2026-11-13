// Package corednslog reads CoreDNS `log` plugin output (the default
// "common" format) into events. It is used by the analyze command and as a
// test input; the long-running source is dnstap.
//
// Accepted line shapes:
//
//	[INFO] 10.0.1.10:41234 - 1234 "A IN billing.shop.svc.cluster.local. udp 55 false 512" NXDOMAIN qr,aa,rd 148 0.0001s
//	2026-11-13T07:12:14.123456789Z [INFO] 10.0.1.10:41234 - 1234 "A IN ..." NXDOMAIN ...   (kubectl logs --timestamps)
//
// Any other line (reload notices, [ERROR] lines, garbage) is skipped.
package corednslog

import (
	"bufio"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/hjklo0220/dns-auditor/internal/event"
)

// Stats counts what Scan saw.
type Stats struct {
	Lines   int `json:"lines"`
	Parsed  int `json:"parsed"`
	Skipped int `json:"skipped"`
}

// Scan parses every line of r and calls fn for each recognized query.
func Scan(r io.Reader, fn func(event.Event)) (Stats, error) {
	var st Stats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		st.Lines++
		ev, ok := ParseLine(sc.Text())
		if !ok {
			st.Skipped++
			continue
		}
		st.Parsed++
		fn(ev)
	}
	return st, sc.Err()
}

// ParseLine parses one log line. It never panics on arbitrary input.
func ParseLine(line string) (event.Event, bool) {
	var ev event.Event
	rest := line
	i := strings.Index(rest, "[INFO] ")
	if i < 0 {
		return ev, false
	}
	if i > 0 {
		if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(rest[:i])); err == nil {
			ev.Time = t
		}
	}
	rest = rest[i+len("[INFO] "):]

	// <remote>:<port> - <id> "<type> <class> <name> <proto> <size> <do> <bufsize>" <rcode> ...
	remote, rest, ok := strings.Cut(rest, " - ")
	if !ok {
		return ev, false
	}
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		ev.ClientIP = ap.Addr().Unmap()
	} else if a, err := netip.ParseAddr(strings.Trim(remote, "[]")); err == nil {
		ev.ClientIP = a.Unmap()
	} else {
		return ev, false
	}
	_, rest, ok = strings.Cut(rest, ` "`) // skip the query id
	if !ok {
		return ev, false
	}
	query, rest, ok := strings.Cut(rest, `" `)
	if !ok {
		return ev, false
	}
	f := strings.Fields(query)
	if len(f) < 3 || f[1] != "IN" {
		return ev, false
	}
	ev.QType, ev.QName = f[0], f[2]
	rc := strings.Fields(rest)
	if len(rc) == 0 {
		return ev, false
	}
	ev.Rcode = rc[0]
	return ev, true
}
