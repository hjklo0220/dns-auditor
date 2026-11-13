// Package event defines the DNS observation passed between pipeline stages.
package event

import (
	"net/netip"
	"time"
)

// Event is one DNS response observed at the cluster resolver.
type Event struct {
	Time     time.Time  // zero when the source has no timestamp
	ClientIP netip.Addr // zero value when unknown
	QName    string     // as received; may include a trailing dot and mixed case
	QType    string     // e.g. "A", "AAAA"
	Rcode    string     // e.g. "NXDOMAIN", "NOERROR"
}
