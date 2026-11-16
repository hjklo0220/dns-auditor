// Package rule decides whether a DNS response reveals a misconfigured
// in-cluster call.
//
// The detected pattern: a Pod in namespace A calls another Service by its
// short name (http://billing). The resolver expands it with the Pod's search
// list, and the first candidate, billing.A.svc.<domain>, returns NXDOMAIN
// because the Service actually lives in namespace B. That exact query name
// tells us both the caller namespace and the wanted Service, and the
// inventory tells us where it really is.
//
// Everything else ndots:5 produces (external names with search suffixes,
// the later search candidates, real typos) is classified as noise.
package rule

import (
	"net/netip"
	"strings"

	"github.com/hjklo0220/dns-auditor/internal/event"
	"github.com/hjklo0220/dns-auditor/internal/inventory"
)

// Category is the outcome of classifying one DNS response.
type Category string

// Categories, in the order they are checked.
const (
	NotNXDomain        Category = "not_nxdomain"         // NOERROR, SERVFAIL, ...
	External           Category = "external"             // not under the cluster domain
	ClusterSearchNoise Category = "cluster_search_noise" // under the cluster domain, not the misroute shape
	UnknownShortName   Category = "unknown_short_name"   // misroute shape, but no such Service anywhere
	Misroute           Category = "misroute"             // short name of a Service in another namespace
)

// Categories lists every category (useful for zero-filled reports).
var Categories = []Category{NotNXDomain, External, ClusterSearchNoise, UnknownShortName, Misroute}

// Suggestion is a fully qualified address the caller should use instead.
type Suggestion struct {
	Host  string  `json:"host"`
	Ports []int32 `json:"ports,omitempty"`
}

// Finding describes one misrouted lookup.
type Finding struct {
	CallerNamespace string
	Caller          inventory.Workload // zero when the client IP is not a known Pod
	CallerIP        netip.Addr
	Name            string // the short name that was looked up (lower case)
	Suggestions     []Suggestion
}

// Classifier holds rule configuration. The zero value is not usable; use New.
type Classifier struct {
	domain    string // e.g. "cluster.local"
	svcSuffix string // e.g. ".svc.cluster.local"
}

// New returns a Classifier for the given cluster domain ("" means cluster.local).
func New(clusterDomain string) Classifier {
	d := strings.Trim(strings.ToLower(clusterDomain), ".")
	if d == "" {
		d = "cluster.local"
	}
	return Classifier{domain: d, svcSuffix: ".svc." + d}
}

// Classify categorizes ev. A Finding is returned only for Misroute.
func (c Classifier) Classify(ev event.Event, inv inventory.Lookup) (Category, *Finding) {
	if !strings.EqualFold(ev.Rcode, "NXDOMAIN") {
		return NotNXDomain, nil
	}
	q := strings.ToLower(strings.TrimSuffix(ev.QName, "."))
	if q != c.domain && !strings.HasSuffix(q, "."+c.domain) {
		return External, nil
	}
	head, ok := strings.CutSuffix(q, c.svcSuffix)
	if !ok {
		return ClusterSearchNoise, nil
	}
	// head must be exactly "<service>.<namespace>".
	name, ns, ok := strings.Cut(head, ".")
	if !ok || name == "" || ns == "" || strings.Contains(ns, ".") {
		return ClusterSearchNoise, nil
	}
	if !inv.HasNamespace(ns) {
		return ClusterSearchNoise, nil
	}
	// The first search-list candidate always carries the caller's own
	// namespace. If the caller is known and lives elsewhere, the name was
	// typed with a namespace (or as an FQDN); that is not this pattern.
	caller, known := inv.WorkloadForIP(ev.ClientIP)
	if known && !strings.EqualFold(caller.Namespace, ns) {
		return ClusterSearchNoise, nil
	}
	var elsewhere []inventory.Service
	for _, s := range inv.ServicesNamed(name) {
		if strings.EqualFold(s.Namespace, ns) {
			// The Service exists in the caller's namespace, so this NXDOMAIN
			// is not the misroute pattern (stale cache, race). Not actionable.
			return ClusterSearchNoise, nil
		}
		elsewhere = append(elsewhere, s)
	}
	if len(elsewhere) == 0 {
		return UnknownShortName, nil
	}
	f := &Finding{CallerNamespace: ns, CallerIP: ev.ClientIP, Name: name}
	if known {
		f.Caller = caller
	}
	for _, s := range elsewhere {
		sg := Suggestion{Host: strings.ToLower(s.Name + "." + s.Namespace + c.svcSuffix)}
		for _, p := range s.Ports {
			sg.Ports = append(sg.Ports, p.Port)
		}
		f.Suggestions = append(f.Suggestions, sg)
	}
	return Misroute, f
}
