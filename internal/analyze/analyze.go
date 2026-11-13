// Package analyze runs the rule engine over recorded CoreDNS logs.
package analyze

import (
	"io"

	"github.com/hjklo0220/dns-auditor/internal/event"
	"github.com/hjklo0220/dns-auditor/internal/inventory"
	"github.com/hjklo0220/dns-auditor/internal/report"
	"github.com/hjklo0220/dns-auditor/internal/rule"
	"github.com/hjklo0220/dns-auditor/internal/source/corednslog"
)

// Options configures Run.
type Options struct {
	ClusterDomain string // "" means cluster.local
}

// Run classifies every query in logs against inv.
func Run(logs []io.Reader, inv inventory.Lookup, opt Options) (report.Report, error) {
	c := rule.New(opt.ClusterDomain)
	agg := report.NewAggregator()
	var total corednslog.Stats
	for _, r := range logs {
		st, err := corednslog.Scan(r, func(ev event.Event) {
			agg.Add(c.Classify(ev, inv))
		})
		total.Lines += st.Lines
		total.Parsed += st.Parsed
		total.Skipped += st.Skipped
		if err != nil {
			return report.Report{}, err
		}
	}
	return agg.Report(total.Lines, total.Parsed, total.Skipped), nil
}
