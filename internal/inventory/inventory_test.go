package inventory

import (
	"net/netip"
	"strings"
	"testing"
)

func ptr(b bool) *bool { return &b }

func TestWorkloadFromPod(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		owners []OwnerRef
		want   Workload
	}{
		{"deployment via replicaset", map[string]string{"pod-template-hash": "7d9f8c6b5"},
			[]OwnerRef{{Kind: "ReplicaSet", Name: "api-7d9f8c6b5", Controller: ptr(true)}}, Workload{"ns", "Deployment", "api"}},
		{"replicaset without matching hash", map[string]string{"pod-template-hash": "zzz"},
			[]OwnerRef{{Kind: "ReplicaSet", Name: "api-7d9f8c6b5"}}, Workload{"ns", "ReplicaSet", "api-7d9f8c6b5"}},
		{"cronjob via job", nil, []OwnerRef{{Kind: "Job", Name: "report-29371200", Controller: ptr(true)}}, Workload{"ns", "CronJob", "report"}},
		{"plain job", nil, []OwnerRef{{Kind: "Job", Name: "migrate-v2"}}, Workload{"ns", "Job", "migrate-v2"}},
		{"statefulset", nil, []OwnerRef{{Kind: "StatefulSet", Name: "db"}}, Workload{"ns", "StatefulSet", "db"}},
		{"controller wins over first owner", nil,
			[]OwnerRef{{Kind: "Foo", Name: "a"}, {Kind: "DaemonSet", Name: "agent", Controller: ptr(true)}}, Workload{"ns", "DaemonSet", "agent"}},
		{"bare pod", nil, nil, Workload{"ns", "Pod", "pod-x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WorkloadFromPod("ns", "pod-x", tt.labels, tt.owners); got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

const snapshot = `{"kind":"List","items":[
 {"kind":"Namespace","metadata":{"name":"shop"}},
 {"kind":"Namespace","metadata":{"name":"billing"}},
 {"kind":"Service","metadata":{"name":"billing","namespace":"billing"},"spec":{"ports":[{"name":"http","port":8080,"protocol":"TCP"}]}},
 {"kind":"ServiceList","items":[{"kind":"Service","metadata":{"name":"billing","namespace":"legacy"},"spec":{"ports":[{"port":80}]}}]},
 {"kind":"Pod","metadata":{"name":"storefront-7d9f8c6b5-abcde","namespace":"shop","labels":{"pod-template-hash":"7d9f8c6b5"},
   "ownerReferences":[{"kind":"ReplicaSet","name":"storefront-7d9f8c6b5","controller":true}]},
   "status":{"podIP":"10.0.1.10","podIPs":[{"ip":"10.0.1.10"},{"ip":"fd00::10"}]}},
 {"kind":"Pod","metadata":{"name":"node-agent","namespace":"kube-system"},"spec":{"hostNetwork":true},"status":{"podIP":"10.0.0.5"}},
 {"kind":"Pod","metadata":{"name":"zz-batch-1","namespace":"shop","ownerReferences":[{"kind":"Job","name":"zz-batch"}]},"status":{"phase":"Succeeded","podIP":"10.0.1.10"}},
 {"kind":"Pod","metadata":{"name":"zz-batch-2","namespace":"shop"},"status":{"phase":"Failed","podIP":"10.0.1.10"}},
 {"kind":"ConfigMap","metadata":{"name":"ignored","namespace":"shop"}}
]}`

func TestLoadKubectlJSON(t *testing.T) {
	s := NewStatic()
	if err := LoadKubectlJSON(strings.NewReader(snapshot), s); err != nil {
		t.Fatal(err)
	}
	if !s.HasNamespace("shop") || !s.HasNamespace("LEGACY") || s.HasNamespace("nope") {
		t.Fatal("namespaces not loaded")
	}
	svcs := s.ServicesNamed("Billing")
	if len(svcs) != 2 || svcs[0].Namespace != "billing" || svcs[1].Namespace != "legacy" || svcs[0].Ports[0].Port != 8080 {
		t.Fatalf("services = %+v", svcs)
	}
	for _, ip := range []string{"10.0.1.10", "fd00::10"} {
		w, ok := s.WorkloadForIP(netip.MustParseAddr(ip))
		if !ok || w.String() != "shop/storefront" || w.Kind != "Deployment" {
			t.Fatalf("%s -> %+v %v", ip, w, ok)
		}
	}
	if _, ok := s.WorkloadForIP(netip.MustParseAddr("10.0.0.5")); ok {
		t.Fatal("hostNetwork pod must not be indexed")
	}
	if _, ok := s.WorkloadForIP(netip.Addr{}); ok {
		t.Fatal("zero IP must not match")
	}
}

func TestLoadKubectlJSONBadInput(t *testing.T) {
	if err := LoadKubectlJSON(strings.NewReader(`{"kind":"List","items":[1]}`), NewStatic()); err == nil {
		t.Fatal("want error for non-object item")
	}
	if err := LoadKubectlJSON(strings.NewReader(`not json`), NewStatic()); err == nil {
		t.Fatal("want error for invalid json")
	}
}

func TestAddServiceReplacesSameNamespace(t *testing.T) {
	s := NewStatic()
	s.AddService(Service{Namespace: "a", Name: "x", Ports: []Port{{Port: 1}}})
	s.AddService(Service{Namespace: "a", Name: "x", Ports: []Port{{Port: 2}}})
	if got := s.ServicesNamed("x"); len(got) != 1 || got[0].Ports[0].Port != 2 {
		t.Fatalf("got %+v", got)
	}
}
