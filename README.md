# dns-auditor

쿠버네티스 클러스터 안에서 **다른 네임스페이스의 Service를 짧은 이름으로 호출해 실패하는 곳**을 CoreDNS에서 실시간으로 찾고, 대신 써야 할 주소를 알려 주는 도구입니다.

```
호출한 곳(ns/워크로드)   찾은 이름       대신 쓸 주소                                          실패 횟수
shop/storefront         payments-api   payments-api.payments.svc.cluster.local:{8080,9090}   51
billing/billing         mailer         mailer.notify.svc.cluster.local:8080 | mailer.ops.svc.cluster.local:2525   40
```

## 어떤 문제를 푸나

`http://billing`은 호출하는 Pod가 `billing` Service와 **같은 네임스페이스**에 있을 때만 동작합니다. 네임스페이스 하나를 쓰다가 서비스별로 나누면(흔한 마이그레이션 단계) 이런 호출이 "unknown host"로 실패하기 시작합니다. 보통 아무도 기억하지 못하는 코드 경로에서 하나씩 터지고, 그때마다 "안 돼요" 티켓이 됩니다.

필요한 정보는 DNS 서버가 이미 갖고 있습니다. 기본값 `ndots:5`에서 `shop` 네임스페이스의 Pod가 `billing`을 찾으면 맨 먼저 `billing.shop.svc.cluster.local`을 묻고, 이 질의가 `NXDOMAIN`을 받습니다. 질의 이름 안에 **호출한 네임스페이스와 찾는 Service 이름이 둘 다** 들어 있으므로, 실제 Service 목록과 맞춰 보면 고칠 주소(`billing.billing.svc.cluster.local:8080`)까지 나옵니다.

어려운 부분은 잡음입니다. 실제 클러스터에서 10분 동안 모은 실패 응답 68,378건 중 99.8%는 search 목록이 붙으면서 생긴 정상 잡음이었고, 잘못된 호출은 116건(0.17%, 워크로드 2개)뿐이었습니다. 이 도구는 그 패턴만 골라내며, 같은 데이터에서 오탐은 0건이었습니다.

## 동작 방식

```
CoreDNS --dnstap(비동기, 받는 쪽이 느리면 CoreDNS가 버림)--> dns-auditor
                                                           |- informer: Namespace·Service·Pod (읽기 전용)
                                                           |- 판정: "<이름>.<호출 ns>.svc.<도메인>" NXDOMAIN
                                                           |        이고 <이름>이 다른 ns에 실제로 있음
                                                           |- 저장: TTL 동안 안 보이면 사라짐(고치면 화면에서 빠짐)
                                                           '- /metrics  /findings  /healthz  /readyz
```

- **CoreDNS를 느리게 만들지 않습니다.** CoreDNS의 dnstap 출력은 막히지 않습니다(최대 10,000개를 버퍼에 두고 넘치면 버림). dns-auditor도 소켓에서 들어오는 대로 읽고, 내부 큐가 차면 기다리지 않고 버리면서 개수만 셉니다.
- **호출자는 Pod가 아니라 워크로드로 표시합니다.** ReplicaSet은 Deployment로, CronJob이 만든 Job은 CronJob으로 묶습니다. 삭제된 Pod의 IP는 유예 시간 동안 그 워크로드로 계속 인식하고, 같은 IP를 새 Pod가 받으면 바로 새 Pod로 바뀝니다.
- **분류:** 모든 응답은 아래 중 하나로 분류됩니다.

| 분류 | 의미 |
|---|---|
| `not_nxdomain` | NXDOMAIN이 아닌 응답 |
| `external` | 클러스터 도메인 밖의 이름 |
| `cluster_search_noise` | 클러스터 도메인 안이지만 잘못된 호출 모양이 아님(없는 네임스페이스, 호출자 네임스페이스에 Service가 있음, 알려진 호출자와 질의의 네임스페이스가 다름 포함) |
| `unknown_short_name` | 모양은 맞지만 그 이름의 Service가 어디에도 없음(오타, 삭제된 Service) |
| `misroute` | 다른 네임스페이스에 있는 Service를 짧은 이름으로 부름 → 대신 쓸 주소와 함께 보고 |

## 설치

Helm 차트(`charts/dns-auditor`)가 원본입니다.

```sh
# serviceMonitor: Prometheus Operator를 쓰는 경우
# networkPolicy:  CNI가 NetworkPolicy를 적용하는 경우
# dashboard:      Grafana 사이드카로 대시보드 자동 등록
helm upgrade --install dns-auditor charts/dns-auditor -n dns-auditor --create-namespace \
  --set serviceMonitor.enabled=true \
  --set networkPolicy.enabled=true \
  --set dashboard.enabled=true
```

Helm 없이 쓰려면 차트에서 생성한 `deploy/kubernetes/*.yaml`을 `kubectl apply -f`로 적용합니다(`scripts/gen-manifests.sh`가 만들고, 하네스가 차트와 어긋나는지 검사).

CoreDNS 서버 블록에 한 줄을 추가합니다. 응답 코드는 DNS 메시지 원문에만 있어서 `full`이 필요합니다.

```sh
kubectl -n dns-auditor get svc dns-auditor -o jsonpath='{.spec.clusterIP}'   # 예: 10.100.100.55
```

```
.:53 {
    errors
    dnstap tcp://10.100.100.55:6000 full
    ...
}
```

주소는 Service 이름이 아니라 **ClusterIP**로 적으세요. CoreDNS Pod는 보통 `dnsPolicy: Default`(노드의 DNS 사용)라서 `*.svc.cluster.local` 이름을 풀지 못합니다. 재설치해도 주소가 바뀌지 않게 하려면 `service.clusterIP`로 고정하세요.

EKS에서는 CoreDNS 애드온의 `configurationValues`(`corefile`)로 넣으세요. ConfigMap을 직접 고치면 애드온 업데이트 때 덮어써질 수 있습니다.

대시보드(`deploy/grafana/dns-auditor-dashboard.json`)는 워크로드별로 "무엇을 바꿔야 하는지" 표를 보여 주며, 수정이 배포되면 해당 행이 저절로 사라집니다.

이미지는 `ko`로 만듭니다(Docker 불필요).

```sh
VERSION=0.1.0 KO_DOCKER_REPO=<레지스트리>/dns-auditor ko build ./cmd/dns-auditor --bare --tags 0.1.0
```

### 지표

| 지표 | 종류 | 라벨 |
|---|---|---|
| `dns_auditor_misroute_lookups_total` | counter | `caller_namespace`, `caller_workload`, `name`, `suggestion` (활성 탐지만) |
| `dns_auditor_misroute_last_seen_timestamp_seconds` | gauge | 위와 같음 |
| `dns_auditor_misroute_active` | gauge | |
| `dns_auditor_responses_total` | counter | `category` |
| `dns_auditor_dnstap_{connections_active,connections_total,frames_total,ignored_total,decode_errors_total,dropped_total,rejected_total,accept_errors_total}` | | |
| `dns_auditor_inventory_objects` | gauge | `kind` |
| `dns_auditor_store_evicted_total` | counter | |

### 실행 옵션 (`serve`)

`-dnstap-addr :6000`, `-http-addr :8080`, `-ttl 15m`, `-pod-grace 5m`, `-max-findings 1000`, `-queue-size 10000`, `-cluster-domain cluster.local`, `-kubeconfig`, `-context`, `-log-level`.

### 보안

dnstap 프레임에는 인증이 없습니다. 6000 포트에 접근할 수 있으면 가짜 탐지를 넣을 수 있으므로, NetworkPolicy(또는 동등한 방법)로 CoreDNS만 접근하게 제한하세요. 서비스 어카운트에는 namespaces·services·pods의 `get/list/watch` 권한만 필요합니다.

## 오프라인 점검

배포하지 않고도 쓸 수 있습니다. CoreDNS 실패 로그를 몇 분만 켜고 분석합니다.

```sh
# Corefile에 `log . { class denial }` 추가, 몇 분 뒤:
kubectl -n kube-system logs -l k8s-app=kube-dns --since=15m --tail=-1 > coredns.log
kubectl get namespaces,services,pods -A -o json > snapshot.json
dns-auditor analyze -coredns-log coredns.log -snapshot snapshot.json [-format json]
```

## CoreDNS 영향

실제 CoreDNS 1.14.7 바이너리로 측정했습니다(`scripts/bench.sh`, 자세한 내용은 [docs/benchmark.md](docs/benchmark.md)).

- **36회 측정 중 DNS 실패 0건.** dns-auditor가 꺼져 있거나 멈춰 있어도 마찬가지입니다(dnstap 출력이 비동기).
- **p50 지연 변화 없음.** p99 차이는 VM 잡음 범위(각 조건 최선값 기준 0.2ms 이하).
- **CoreDNS CPU는 150 / 750 / 1500 qps에서 코어 1개 기준 +2 / +4 / +6%p.** `dnstap ... full` 자체의 비용이며, 수신기가 정상이든 꺼졌든 멈췄든 같습니다.
- **dns-auditor 자체는 메모리 약 37MiB, 1,500 qps에서 유실 0건.**

## 한계

- **이름 해석 실패만 봅니다.** 이름은 맞는데 포트가 틀린 경우, Service 대신 ingress·로드밸런서 도메인으로 돌아 나가는 호출은 잡지 못합니다.
- 드물게 일어나는 호출(예: 주 1회 배치)은 일어날 때만 보이고, 그 뒤 TTL 동안 남습니다.
- `dnsConfig`로 search 목록을 바꾼 Pod는 질의 이름만으로 판정합니다.

## 개발

`scripts/check.sh`(또는 `make check`)가 "완료" 판정을 하는 유일한 기준입니다. gofmt, vet, golangci-lint, `-race` 테스트, 커버리지 기준(핵심 패키지별 90%), 두 파서의 짧은 fuzz, Helm 차트 lint·렌더링과 생성 매니페스트 drift, 작업 트리와 git 이력 유출 검사를 돌립니다. CI도 같은 스크립트를 실행합니다.

```sh
make check
make quick
make synthetic                          # testdata/synthetic 재생성(독립 정답)
git config core.hooksPath .githooks     # pre-commit: quick check + 유출 검사
COREDNS=$(which coredns) scripts/bench.sh   # CoreDNS 영향 벤치마크
go run ./hack/dnstap-replay -addr 127.0.0.1:6000 coredns.log   # 기록된 로그를 dnstap으로 재생
```

테스트 데이터:

- `testdata/synthetic/`: 생성기가 만든 로그와 스냅샷. `expected.json`은 분석기를 돌린 결과가 아니라 생성기가 넣은 내용으로 계산한 정답입니다.
- 실제 클러스터 캡처는 커밋하지 않습니다. `DNS_AUDITOR_PRIVATE`가 `cases/*/{*.log,snapshot.json,expected.json}`을 가진 폴더를 가리키면 golden 테스트가 그 사례도 함께 돌립니다. 그 폴더의 `leak-patterns.txt`는 유출 검사에 조직 고유 패턴을 추가합니다.
