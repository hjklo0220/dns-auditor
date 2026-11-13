# dns-auditor

Find in-cluster calls that use a **short Service name across namespaces** and
get the address they should use instead.

```
COUNT  CALLER             LOOKED UP     USE INSTEAD
51     shop/storefront    payments-api  payments-api.payments.svc.cluster.local:{8080,9090}
40     billing/billing    mailer        mailer.notify.svc.cluster.local:8080 | mailer.ops.svc.cluster.local:2525
```

## The problem

`http://billing` only works when the caller runs in the same namespace as the
`billing` Service. After splitting one shared namespace into many (a common
migration step), these calls start failing with "unknown host", usually one at
a time, in code paths nobody remembers.

The resolver already tells you exactly which calls are broken. With the default
`ndots:5`, a Pod in namespace `shop` that looks up `billing` first asks for
`billing.shop.svc.cluster.local`, and that query gets `NXDOMAIN`. The query name
contains both the caller namespace and the wanted Service. Matching it against
the Services that do exist gives the fix: `billing.billing.svc.cluster.local:8080`.

The hard part is the noise. In a real cluster capture, 99.8% of `NXDOMAIN`
responses were harmless search-list expansions of external names. Only 0.17%
were misrouted calls. dns-auditor keeps only that shape and reported zero false
positives on that capture.

## Status

| Component | State |
|---|---|
| `analyze`: offline analysis of CoreDNS `log` output | ✅ |
| `serve`: live dnstap receiver, Prometheus `/metrics` | 🚧 planned |
| Pod/Service watch with client-go informers | 🚧 planned |
| CoreDNS overhead benchmark | 🚧 planned |

## Quick start (offline)

1. Turn on denial logging in CoreDNS for a few minutes. Add `log . { class denial }` to the Corefile server block.
2. Collect the logs and a snapshot of the cluster:

```sh
kubectl -n kube-system logs -l k8s-app=kube-dns --since=15m --tail=-1 > coredns.log
kubectl get namespaces,services,pods -A -o json > snapshot.json
```

3. Run the analysis:

```sh
dns-auditor analyze -coredns-log coredns.log -snapshot snapshot.json
dns-auditor analyze -coredns-log coredns.log -snapshot snapshot.json -format json
```

Remove the `log` line again afterwards. Logging every denial on a busy cluster
is expensive, and live mode will use dnstap instead.

## How a response is classified

| Category | Meaning |
|---|---|
| `not_nxdomain` | anything but NXDOMAIN |
| `external` | not under the cluster domain |
| `cluster_search_noise` | under the cluster domain but not `<name>.<namespace>.svc.<domain>`, or the namespace does not exist, or the Service exists in that namespace |
| `unknown_short_name` | the misroute shape, but no Service with that name exists anywhere (typo, deleted Service) |
| `misroute` | a short name of a Service that lives in another namespace (reported, with suggestions) |

Callers are attributed to their workload (Deployment, StatefulSet, CronJob, ...)
rather than to a Pod, so results stay stable across restarts.

## Development

`scripts/check.sh` (or `make check`) is the single pass/fail verdict. It runs
gofmt, vet, golangci-lint, tests with `-race`, a coverage gate, a short fuzz
run, and a leak scan. CI runs the same script.

```sh
make check            # full
make quick            # fmt, vet, tests
make synthetic        # regenerate testdata/synthetic (independent oracle)
git config core.hooksPath .githooks   # pre-commit runs quick check + leak scan
```

Test data:

- `testdata/synthetic/` holds generated logs and a snapshot. `expected.json` is
  computed by the generator from what it injected, not by running the analyzer.
- Real cluster captures are never committed. If `DNS_AUDITOR_PRIVATE` points at
  a directory with `cases/*/{*.log,snapshot.json,expected.json}`, the golden test
  runs those cases too. `leak-patterns.txt` in that directory adds
  organization-specific patterns to the leak scan.

## License

Apache-2.0
