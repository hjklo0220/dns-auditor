package inventory

import "strings"

// OwnerRef is the subset of metav1.OwnerReference needed to name a workload.
type OwnerRef struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Controller *bool  `json:"controller,omitempty"`
}

// WorkloadFromPod derives a stable workload identity from a Pod's owner
// references, so that results survive Pod restarts:
//
//   - ReplicaSet "api-7d9f8c6b5" with label pod-template-hash=7d9f8c6b5 -> Deployment "api"
//     (Argo Rollouts use the same pattern and are reported the same way)
//   - Job "report-29371200" (CronJob style numeric suffix)               -> CronJob "report"
//   - other controllers (StatefulSet, DaemonSet, Job, ...)              -> as is
//   - no owner                                                          -> the Pod itself
func WorkloadFromPod(ns, pod string, labels map[string]string, owners []OwnerRef) Workload {
	owner, ok := controllerOf(owners)
	if !ok {
		return Workload{Namespace: ns, Kind: "Pod", Name: pod}
	}
	switch owner.Kind {
	case "ReplicaSet":
		if h := labels["pod-template-hash"]; h != "" && strings.HasSuffix(owner.Name, "-"+h) {
			return Workload{Namespace: ns, Kind: "Deployment", Name: strings.TrimSuffix(owner.Name, "-"+h)}
		}
	case "Job":
		if base, ok := cutNumericSuffix(owner.Name); ok {
			return Workload{Namespace: ns, Kind: "CronJob", Name: base}
		}
	}
	return Workload{Namespace: ns, Kind: owner.Kind, Name: owner.Name}
}

func controllerOf(owners []OwnerRef) (OwnerRef, bool) {
	for _, o := range owners {
		if o.Controller != nil && *o.Controller {
			return o, true
		}
	}
	if len(owners) > 0 {
		return owners[0], true
	}
	return OwnerRef{}, false
}

// cutNumericSuffix splits "name-12345678" into "name" when the suffix is all
// digits and at least 8 long (CronJob schedules use minutes since epoch).
func cutNumericSuffix(s string) (string, bool) {
	i := strings.LastIndexByte(s, '-')
	if i <= 0 || len(s)-i-1 < 8 {
		return "", false
	}
	for _, r := range s[i+1:] {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	return s[:i], true
}
