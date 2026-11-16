// Package pipeline connects a source of events to the rule engine and the
// findings store.
package pipeline

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/hjklo0220/dns-auditor/internal/event"
	"github.com/hjklo0220/dns-auditor/internal/inventory"
	"github.com/hjklo0220/dns-auditor/internal/rule"
	"github.com/hjklo0220/dns-auditor/internal/store"
)

// Pipeline classifies events and records findings. Category counters are safe
// for concurrent reads while Run is active.
type Pipeline struct {
	Classifier rule.Classifier
	Inventory  inventory.Lookup
	Store      *store.Store

	counts [5]atomic.Uint64 // indexed like rule.Categories
}

// Run consumes in until it is closed or ctx is done.
func (p *Pipeline) Run(ctx context.Context, in <-chan event.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-in:
			if !ok {
				return
			}
			p.Handle(ev)
		}
	}
}

// Handle processes one event synchronously.
func (p *Pipeline) Handle(ev event.Event) {
	c, f := p.Classifier.Classify(ev, p.Inventory)
	p.counts[index(c)].Add(1)
	if f != nil {
		// Use the local clock, not the dnstap timestamp: it is compared
		// against the local clock for the TTL, and senders can be skewed.
		p.Store.Add(f, time.Time{})
	}
}

func index(c rule.Category) int {
	for i, x := range rule.Categories {
		if x == c {
			return i
		}
	}
	panic("unknown category " + string(c))
}

// Counts returns the number of responses seen per category.
func (p *Pipeline) Counts() map[rule.Category]uint64 {
	out := make(map[rule.Category]uint64, len(rule.Categories))
	for i, c := range rule.Categories {
		out[c] = p.counts[i].Load()
	}
	return out
}
