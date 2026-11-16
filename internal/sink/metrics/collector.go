// Package metrics exposes the auditor state to Prometheus.
//
// Findings are exported only while active (seen within the store TTL), so a
// call that was fixed drops out of dashboards on its own. Values are read at
// scrape time; nothing here runs on the hot path.
//
// Grafana table, "what to change right now":
//
//	max by (caller_namespace, caller_workload, name, suggestion)
//	  (dns_auditor_misroute_last_seen_timestamp_seconds) * 1000
package metrics

import (
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/hjklo0220/dns-auditor/internal/rule"
	"github.com/hjklo0220/dns-auditor/internal/source/dnstap"
	"github.com/hjklo0220/dns-auditor/internal/store"
)

// InventoryStats reports cache sizes.
type InventoryStats interface {
	Stats() (namespaces, serviceNames, podIPs int)
}

// Sources are read at every scrape. Nil fields are skipped.
type Sources struct {
	Store      *store.Store
	Categories func() map[rule.Category]uint64
	Dnstap     *dnstap.Stats
	Inventory  InventoryStats
}

var findingLabels = []string{"caller_namespace", "caller_workload", "name", "suggestion"}

var (
	descLookups   = prometheus.NewDesc("dns_auditor_misroute_lookups_total", "Failed short-name lookups of a Service in another namespace, per caller workload (active findings only).", findingLabels, nil)
	descLastSeen  = prometheus.NewDesc("dns_auditor_misroute_last_seen_timestamp_seconds", "Last time the misrouted lookup was seen (active findings only).", findingLabels, nil)
	descActive    = prometheus.NewDesc("dns_auditor_misroute_active", "Number of active findings.", nil, nil)
	descEvicted   = prometheus.NewDesc("dns_auditor_store_evicted_total", "Findings dropped because the store was full.", nil, nil)
	descResponses = prometheus.NewDesc("dns_auditor_responses_total", "DNS responses classified, by category.", []string{"category"}, nil)
	descConnAct   = prometheus.NewDesc("dns_auditor_dnstap_connections_active", "Open dnstap connections.", nil, nil)
	descConnTotal = prometheus.NewDesc("dns_auditor_dnstap_connections_total", "Accepted dnstap connections.", nil, nil)
	descFrames    = prometheus.NewDesc("dns_auditor_dnstap_frames_total", "dnstap data frames read.", nil, nil)
	descIgnored   = prometheus.NewDesc("dns_auditor_dnstap_ignored_total", "dnstap frames that are not client responses.", nil, nil)
	descDecodeErr = prometheus.NewDesc("dns_auditor_dnstap_decode_errors_total", "dnstap frames that could not be decoded.", nil, nil)
	descDropped   = prometheus.NewDesc("dns_auditor_dnstap_dropped_total", "Events dropped because the processing queue was full.", nil, nil)
	descRejected  = prometheus.NewDesc("dns_auditor_dnstap_rejected_total", "dnstap connections refused because the connection limit was reached.", nil, nil)
	descAcceptErr = prometheus.NewDesc("dns_auditor_dnstap_accept_errors_total", "Transient dnstap accept failures (retried).", nil, nil)
	descInventory = prometheus.NewDesc("dns_auditor_inventory_objects", "Objects tracked by the inventory.", []string{"kind"}, nil)
)

// Collector implements prometheus.Collector.
type Collector struct{ src Sources }

// New returns a Collector over src.
func New(src Sources) *Collector { return &Collector{src: src} }

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{descLookups, descLastSeen, descActive, descEvicted, descResponses,
		descConnAct, descConnTotal, descFrames, descIgnored, descDecodeErr, descDropped, descRejected, descAcceptErr, descInventory} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	if s := c.src.Store; s != nil {
		active := s.Active()
		for _, e := range active {
			lv := []string{e.CallerNamespace, e.CallerWorkload, e.Name, Suggestion(e.Suggestions)}
			ch <- prometheus.MustNewConstMetric(descLookups, prometheus.CounterValue, float64(e.Count), lv...)
			ch <- prometheus.MustNewConstMetric(descLastSeen, prometheus.GaugeValue, float64(e.LastSeen.UnixNano())/1e9, lv...)
		}
		ch <- prometheus.MustNewConstMetric(descActive, prometheus.GaugeValue, float64(len(active)))
		ch <- prometheus.MustNewConstMetric(descEvicted, prometheus.CounterValue, float64(s.Evicted()))
	}
	if f := c.src.Categories; f != nil {
		counts := f()
		for _, cat := range rule.Categories {
			ch <- prometheus.MustNewConstMetric(descResponses, prometheus.CounterValue, float64(counts[cat]), string(cat))
		}
	}
	if d := c.src.Dnstap; d != nil {
		ch <- prometheus.MustNewConstMetric(descConnAct, prometheus.GaugeValue, float64(d.Active.Load()))
		ch <- prometheus.MustNewConstMetric(descConnTotal, prometheus.CounterValue, float64(d.Connections.Load()))
		ch <- prometheus.MustNewConstMetric(descFrames, prometheus.CounterValue, float64(d.Frames.Load()))
		ch <- prometheus.MustNewConstMetric(descIgnored, prometheus.CounterValue, float64(d.Ignored.Load()))
		ch <- prometheus.MustNewConstMetric(descDecodeErr, prometheus.CounterValue, float64(d.DecodeErrors.Load()))
		ch <- prometheus.MustNewConstMetric(descDropped, prometheus.CounterValue, float64(d.Dropped.Load()))
		ch <- prometheus.MustNewConstMetric(descRejected, prometheus.CounterValue, float64(d.Rejected.Load()))
		ch <- prometheus.MustNewConstMetric(descAcceptErr, prometheus.CounterValue, float64(d.AcceptErrors.Load()))
	}
	if inv := c.src.Inventory; inv != nil {
		n, s, p := inv.Stats()
		ch <- prometheus.MustNewConstMetric(descInventory, prometheus.GaugeValue, float64(n), "namespace")
		ch <- prometheus.MustNewConstMetric(descInventory, prometheus.GaugeValue, float64(s), "service_name")
		ch <- prometheus.MustNewConstMetric(descInventory, prometheus.GaugeValue, float64(p), "pod_ip")
	}
}

// Suggestion renders suggestions as one label value, e.g.
// "billing.billing.svc.cluster.local:8080" or "a.x.svc.cluster.local:{80,9090} | a.y.svc.cluster.local:80".
//
// At most MaxSuggestions are listed, followed by "(+N more)", to keep the
// label short when many namespaces have a Service with the same name.
func Suggestion(s []rule.Suggestion) string {
	n := min(len(s), MaxSuggestions)
	parts := make([]string, 0, n+1)
	for _, sg := range s[:n] {
		parts = append(parts, sg.Host+portSuffix(sg.Ports))
	}
	if extra := len(s) - n; extra > 0 {
		parts = append(parts, fmt.Sprintf("(+%d more)", extra))
	}
	return strings.Join(parts, " | ")
}

// MaxSuggestions bounds the suggestion label.
const MaxSuggestions = 3

func portSuffix(ports []int32) string {
	switch len(ports) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf(":%d", ports[0])
	}
	ps := make([]string, len(ports))
	for i, p := range ports {
		ps[i] = fmt.Sprint(p)
	}
	return ":{" + strings.Join(ps, ",") + "}"
}
