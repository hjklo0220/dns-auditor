// Package report aggregates classified events into a stable, sorted report.
package report

import (
	"net/netip"
	"sort"

	"github.com/hjklo0220/dns-auditor/internal/rule"
)

// UnknownWorkload is reported when a client IP is not a known Pod.
const UnknownWorkload = "unknown"

// Row is one (caller workload, wanted name) pair.
type Row struct {
	CallerNamespace string            `json:"caller_namespace"`
	CallerWorkload  string            `json:"caller_workload"` // "ns/name" or "unknown"
	CallerIPs       []string          `json:"caller_ips,omitempty"`
	Name            string            `json:"name"`
	Count           int               `json:"count"`
	Suggestions     []rule.Suggestion `json:"suggestions"`
}

// Summary describes the input and how it was classified.
type Summary struct {
	Lines      int                   `json:"lines"`
	Parsed     int                   `json:"parsed"`
	Skipped    int                   `json:"skipped"`
	Categories map[rule.Category]int `json:"categories"`
}

// Report is the analyze output.
type Report struct {
	Summary  Summary `json:"summary"`
	Findings []Row   `json:"findings"`
}

// maxIPsPerRow bounds the unknown-caller IP list.
const maxIPsPerRow = 10

type key struct{ ns, workload, name string }

type acc struct {
	row Row
	ips map[netip.Addr]struct{}
}

// Aggregator collects classification results. Not safe for concurrent use.
type Aggregator struct {
	cats map[rule.Category]int
	rows map[key]*acc
}

// NewAggregator returns an empty Aggregator.
func NewAggregator() *Aggregator {
	cats := map[rule.Category]int{}
	for _, c := range rule.Categories {
		cats[c] = 0
	}
	return &Aggregator{cats: cats, rows: map[key]*acc{}}
}

// Add records one classification result.
func (a *Aggregator) Add(c rule.Category, f *rule.Finding) {
	a.cats[c]++
	if f == nil {
		return
	}
	wl := UnknownWorkload
	if f.Caller.Name != "" {
		wl = f.Caller.String()
	}
	k := key{f.CallerNamespace, wl, f.Name}
	r, ok := a.rows[k]
	if !ok {
		r = &acc{row: Row{CallerNamespace: f.CallerNamespace, CallerWorkload: wl, Name: f.Name, Suggestions: f.Suggestions}, ips: map[netip.Addr]struct{}{}}
		a.rows[k] = r
	}
	r.row.Count++
	if wl == UnknownWorkload && f.CallerIP.IsValid() && len(r.ips) < maxIPsPerRow {
		r.ips[f.CallerIP] = struct{}{}
	}
}

// Report returns the sorted result. lines/parsed/skipped come from the source.
func (a *Aggregator) Report(lines, parsed, skipped int) Report {
	rows := make([]Row, 0, len(a.rows))
	for _, r := range a.rows {
		row := r.row
		for ip := range r.ips {
			row.CallerIPs = append(row.CallerIPs, ip.String())
		}
		sort.Strings(row.CallerIPs)
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		x, y := rows[i], rows[j]
		if x.Count != y.Count {
			return x.Count > y.Count
		}
		if x.CallerNamespace != y.CallerNamespace {
			return x.CallerNamespace < y.CallerNamespace
		}
		if x.CallerWorkload != y.CallerWorkload {
			return x.CallerWorkload < y.CallerWorkload
		}
		return x.Name < y.Name
	})
	cats := make(map[rule.Category]int, len(a.cats))
	for k, v := range a.cats {
		cats[k] = v
	}
	return Report{
		Summary:  Summary{Lines: lines, Parsed: parsed, Skipped: skipped, Categories: cats},
		Findings: rows,
	}
}
