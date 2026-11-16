# dns-auditor

Find in-cluster calls that use a **short Service name across namespaces**, and
get the address to use instead, live, from CoreDNS.

```
Caller (namespace/workload)  Looked up     Use instead                                          Failed lookups
shop/storefront              payments-api  payments-api.payments.svc.cluster.local:{8080,9090}  51
billing/billing              mailer        mailer.notify.svc.cluster.local:8080 | mailer.ops.svc.cluster.local:2525  40
```

## The problem

`http://billing` only works when the caller runs in the same namespace as the
`billing` Service. After you split one shared namespace into many (a common
migration step), these calls start failing with "unknown host". They usually
fail one at a time, in code paths nobody remembers, and each one turns into a
ticket.

The resolver already tells you exactly which calls are broken. With the
default `ndots:5`, a Pod in namespace `shop` that looks up `billing` first asks
for `billing.shop.svc.cluster.local`, and that query gets `NXDOMAIN`. The query
name contains both the caller namespace and the wanted Service. Matching it
against the Services that do exist gives the fix,
`billing.billing.svc.cluster.local:8080`.

The hard part is the noise. In a real cluster capture of 68,378 failed
responses, 99.8% were harmless search-list expansions. Only 116 (0.17%) were
misrouted calls. They came from two workloads, and the run had zero false
positives.

## How it works

```
CoreDNS --dnstap (async, drops if the receiver is slow)--> dns-auditor
                                                            |- informers: Namespaces, Services, Pods (read-only)
                                                            |- rule: "<name>.<caller-ns>.svc.<domain>" NXDOMAIN
                                                            |        and <name> exists in another namespace
                                                            |- store: findings expire after the TTL (fixed calls disappear)
                                                            '- /metrics  /findings  /healthz  /readyz
```

- **The receiver never slows CoreDNS.** CoreDNS's dnstap plugin is
  non-blocking: it buffers up to 10,000 messages and drops when the buffer is
  full. dns-auditor reads frames as fast as the socket delivers them. When its
  own queue is full it drops and counts, instead of waiting.
- **Callers are workloads, not Pods.** A ReplicaSet maps back to its
  Deployment, and a CronJob's Jobs map to the CronJob. A deleted Pod's IP stays
  attributed for a grace period. A new Pod that reuses the IP takes over
  immediately.
- **Classification.** Each response falls into exactly one category:

| Category | Meaning |
|---|---|
| `not_nxdomain` | anything but NXDOMAIN |
| `external` | not under the cluster domain |
| `cluster_search_noise` | under the cluster domain but not the misroute shape. This includes a nonexistent namespace, a Service that exists in the caller's namespace, and a known caller in a different namespace than the query names |
| `unknown_short_name` | the misroute shape, but no Service with that name exists anywhere (typo, deleted Service) |
| `misroute` | a short name of a Service in another namespace. These are reported with suggestions |

## Install

```sh
kubectl apply -f deploy/kubernetes/dns-auditor.yaml
kubectl apply -f deploy/kubernetes/networkpolicy.yaml      # if your CNI enforces NetworkPolicy
kubectl apply -f deploy/kubernetes/servicemonitor.yaml     # if you run the Prometheus Operator
```

Then add one line to the CoreDNS server block (the `full` flag is required:
the response code is only in the wire-format message):

```
.:53 {
    errors
    dnstap tcp://dns-auditor.dns-auditor.svc.cluster.local:6000 full
    ...
}
```

On EKS, set this through the CoreDNS add-on's `configurationValues` (`corefile`).
If you edit the ConfigMap directly, the add-on can overwrite it.

Import `deploy/grafana/dns-auditor-dashboard.json` for a table that tells each
team what to change. Rows disappear once the fix is deployed.

### Metrics

| Metric | Type | Labels |
|---|---|---|
| `dns_auditor_misroute_lookups_total` | counter | `caller_namespace`, `caller_workload`, `name`, `suggestion` (active findings only) |
| `dns_auditor_misroute_last_seen_timestamp_seconds` | gauge | same |
| `dns_auditor_misroute_active` | gauge | |
| `dns_auditor_responses_total` | counter | `category` |
| `dns_auditor_dnstap_{connections_active,connections_total,frames_total,ignored_total,decode_errors_total,dropped_total,rejected_total,accept_errors_total}` | | |
| `dns_auditor_inventory_objects` | gauge | `kind` |
| `dns_auditor_store_evicted_total` | counter | |

### Flags (`serve`)

`-dnstap-addr :6000`, `-http-addr :8080`, `-ttl 15m`, `-pod-grace 5m`,
`-max-findings 1000`, `-queue-size 10000`, `-cluster-domain cluster.local`,
`-kubeconfig`, `-context`, `-log-level`.

### Security

dnstap frames are not authenticated. Anyone who can reach port 6000 can inject
fake findings, so restrict it to CoreDNS with the NetworkPolicy (or an
equivalent). The service account only needs `get/list/watch` on namespaces,
services and pods.

## Offline mode

No deployment needed: turn on denial logging for a few minutes and analyze.

```sh
# add `log . { class denial }` to the Corefile, wait, then:
kubectl -n kube-system logs -l k8s-app=kube-dns --since=15m --tail=-1 > coredns.log
kubectl get namespaces,services,pods -A -o json > snapshot.json
dns-auditor analyze -coredns-log coredns.log -snapshot snapshot.json [-format json]
```

## Overhead on CoreDNS

Measured with a real CoreDNS 1.14.7 binary (`scripts/bench.sh`, details in
[docs/benchmark.md](docs/benchmark.md)):

- **0 DNS failures in 36 runs**, including with dns-auditor down or stuck. The
  dnstap output is asynchronous.
- **p50 latency unchanged.** p99 differences were within VM noise (at most
  0.2 ms between best runs).
- **CoreDNS CPU +2 / +4 / +6 points of one core at 150 / 750 / 1500 qps.** This
  is the price of `dnstap ... full` itself, and it is the same whether the
  receiver is up, down or stuck.
- **dns-auditor: about 37 MiB RSS, 0 dropped events at 1,500 qps.**

## Limits

- It only sees failures that are **name resolution** failures. It does not
  catch a correct name with a wrong port, or calls that go out through an
  ingress or load balancer domain instead of the Service.
- A call that happens rarely, such as a weekly job, shows up only while it
  happens, and then stays for the TTL.
- Pods with a custom `dnsConfig` search list are classified by the query name
  alone.

## Development

`scripts/check.sh` (or `make check`) is the single pass/fail verdict. It runs
gofmt, vet, golangci-lint, tests with `-race`, a coverage gate (90% per core
package), short fuzz runs of both parsers, and a leak scan of the working tree
and git history. CI runs the same script.

```sh
make check
make quick
make synthetic                          # regenerate testdata/synthetic (independent oracle)
git config core.hooksPath .githooks     # pre-commit: quick check + leak scan
COREDNS=$(which coredns) scripts/bench.sh   # CoreDNS overhead benchmark
go run ./hack/dnstap-replay -addr 127.0.0.1:6000 coredns.log   # replay recorded logs as dnstap
```

Test data:

- `testdata/synthetic/` holds generated logs and a snapshot. `expected.json` is
  computed by the generator from what it injected, not by running the analyzer.
- Real cluster captures are never committed. If `DNS_AUDITOR_PRIVATE` points at
  a directory with `cases/*/{*.log,snapshot.json,expected.json}`, the golden test
  runs those too. `leak-patterns.txt` in that directory adds
  organization-specific patterns to the leak scan.

## License

Apache-2.0
