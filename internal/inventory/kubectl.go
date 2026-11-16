package inventory

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// k8sObject decodes only the fields we use from `kubectl get ... -o json`.
type k8sObject struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		Labels          map[string]string `json:"labels"`
		OwnerReferences []OwnerRef        `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		Ports       []Port `json:"ports"`
		HostNetwork bool   `json:"hostNetwork"`
	} `json:"spec"`
	Status struct {
		Phase  string `json:"phase"`
		PodIP  string `json:"podIP"`
		PodIPs []struct {
			IP string `json:"ip"`
		} `json:"podIPs"`
	} `json:"status"`
	Items []json.RawMessage `json:"items"`
}

// LoadKubectlJSON adds Services, Pods and Namespaces from the output of
//
//	kubectl get namespaces,services,pods -A -o json
//
// (a v1 List, possibly nested) to s. Unknown kinds are ignored.
func LoadKubectlJSON(r io.Reader, s *Static) error {
	var root k8sObject
	if err := json.NewDecoder(r).Decode(&root); err != nil {
		return fmt.Errorf("decode snapshot: %w", err)
	}
	return add(root, s)
}

func add(o k8sObject, s *Static) error {
	switch {
	case o.Kind == "List" || strings.HasSuffix(o.Kind, "List"):
		for i, raw := range o.Items {
			var item k8sObject
			if err := json.Unmarshal(raw, &item); err != nil {
				return fmt.Errorf("decode item %d: %w", i, err)
			}
			if err := add(item, s); err != nil {
				return err
			}
		}
	case o.Kind == "Namespace":
		s.AddNamespace(o.Metadata.Name)
	case o.Kind == "Service":
		s.AddService(Service{Namespace: o.Metadata.Namespace, Name: o.Metadata.Name, Ports: o.Spec.Ports})
	case o.Kind == "Pod":
		if o.Spec.HostNetwork {
			return nil // shares the node IP; cannot be attributed to one workload
		}
		if o.Status.Phase == "Succeeded" || o.Status.Phase == "Failed" {
			return nil // finished; its IP may already belong to another Pod
		}
		w := WorkloadFromPod(o.Metadata.Namespace, o.Metadata.Name, o.Metadata.Labels, o.Metadata.OwnerReferences)
		ips := []string{o.Status.PodIP}
		for _, p := range o.Status.PodIPs {
			ips = append(ips, p.IP)
		}
		for _, raw := range ips {
			if ip, err := netip.ParseAddr(raw); err == nil {
				s.AddPod(ip, w)
			}
		}
	}
	return nil
}
