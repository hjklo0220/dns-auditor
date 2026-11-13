package corednslog

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hjklo0220/dns-auditor/internal/event"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		ok   bool
		want event.Event
	}{
		{"default format", `[INFO] 10.0.1.10:41234 - 1234 "A IN billing.shop.svc.cluster.local. udp 55 false 512" NXDOMAIN qr,aa,rd 148 0.000123s`, true,
			event.Event{ClientIP: netip.MustParseAddr("10.0.1.10"), QType: "A", QName: "billing.shop.svc.cluster.local.", Rcode: "NXDOMAIN"}},
		{"kubectl --timestamps prefix", `2026-11-13T07:12:14.123456789Z [INFO] 10.0.1.10:5 - 1 "AAAA IN x.y. udp 1 false 512" NOERROR qr 1 0.1s`, true,
			event.Event{Time: time.Date(2026, 11, 13, 7, 12, 14, 123456789, time.UTC), ClientIP: netip.MustParseAddr("10.0.1.10"), QType: "AAAA", QName: "x.y.", Rcode: "NOERROR"}},
		{"ipv6 client", `[INFO] [fd00::1]:53000 - 7 "A IN x. tcp 1 false 512" NXDOMAIN qr 1 0s`, true,
			event.Event{ClientIP: netip.MustParseAddr("fd00::1"), QType: "A", QName: "x.", Rcode: "NXDOMAIN"}},
		{"ipv4-mapped client is unmapped", `[INFO] [::ffff:10.0.1.10]:1 - 7 "A IN x. udp 1 false 512" NXDOMAIN qr 1 0s`, true,
			event.Event{ClientIP: netip.MustParseAddr("10.0.1.10"), QType: "A", QName: "x.", Rcode: "NXDOMAIN"}},
		{"reload notice", `[INFO] Reloading`, false, event.Event{}},
		{"reload sha", `[INFO] plugin/reload: Running configuration SHA512 = abc`, false, event.Event{}},
		{"error line", `[ERROR] plugin/errors: 2 x. A: read udp 1.2.3.4:5->6.7.8.9:53: i/o timeout`, false, event.Event{}},
		{"bad remote", `[INFO] nothost - 1 "A IN x. udp 1 false 512" NXDOMAIN qr 1 0s`, false, event.Event{}},
		{"not class IN", `[INFO] 10.0.0.1:1 - 1 "A CH x. udp 1 false 512" NXDOMAIN qr 1 0s`, false, event.Event{}},
		{"truncated", `[INFO] 10.0.0.1:1 - 1 "A IN x.`, false, event.Event{}},
		{"no rcode", `[INFO] 10.0.0.1:1 - 1 "A IN x. udp 1 false 512" `, false, event.Event{}},
		{"empty", ``, false, event.Event{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseLine(tt.line)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Fatalf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestScanStats(t *testing.T) {
	in := strings.Join([]string{
		`[INFO] Reloading`,
		`[INFO] 10.0.0.1:1 - 1 "A IN a. udp 1 false 512" NXDOMAIN qr 1 0s`,
		`garbage`,
		`[INFO] 10.0.0.1:1 - 2 "A IN b. udp 1 false 512" NOERROR qr 1 0s`,
	}, "\n")
	var names []string
	st, err := Scan(strings.NewReader(in), func(ev event.Event) { names = append(names, ev.QName) })
	if err != nil {
		t.Fatal(err)
	}
	if st != (Stats{Lines: 4, Parsed: 2, Skipped: 2}) || strings.Join(names, ",") != "a.,b." {
		t.Fatalf("stats %+v names %v", st, names)
	}
}

func FuzzParseLine(f *testing.F) {
	f.Add(`[INFO] 10.0.1.10:41234 - 1234 "A IN billing.shop.svc.cluster.local. udp 55 false 512" NXDOMAIN qr,aa,rd 148 0.000123s`)
	f.Add(`2026-11-13T07:12:14Z [INFO] [fd00::1]:1 - 1 "AAAA IN x. tcp 1 false 512" NOERROR qr 1 0s`)
	f.Add(`[ERROR] plugin/errors: 2 x. A: i/o timeout`)
	f.Fuzz(func(t *testing.T, line string) {
		ev, ok := ParseLine(line)
		if ok && (ev.QName == "" || ev.Rcode == "" || !ev.ClientIP.IsValid()) {
			t.Fatalf("accepted line with empty fields: %q -> %+v", line, ev)
		}
	})
}
