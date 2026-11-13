// Package inventory answers "what exists in the cluster" questions for the
// rule engine: which namespaces exist, where a Service name lives, and which
// workload owns a Pod IP.
package inventory

import "net/netip"

// Port is a Service port.
type Port struct {
	Name     string `json:"name,omitempty"`
	Port     int32  `json:"port"`
	Protocol string `json:"protocol,omitempty"`
}

// Service is the subset of a Kubernetes Service the rules need.
type Service struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Ports     []Port `json:"ports,omitempty"`
}

// Workload identifies the controller that owns a Pod (Deployment, StatefulSet, ...).
type Workload struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind,omitempty"`
	Name      string `json:"name"`
}

// String returns "namespace/name".
func (w Workload) String() string { return w.Namespace + "/" + w.Name }

// Lookup is the read-only view the rule engine depends on. Implementations
// must be safe for concurrent use.
type Lookup interface {
	HasNamespace(ns string) bool
	// ServicesNamed returns every Service with the given name, across all
	// namespaces, sorted by namespace.
	ServicesNamed(name string) []Service
	WorkloadForIP(ip netip.Addr) (Workload, bool)
}
