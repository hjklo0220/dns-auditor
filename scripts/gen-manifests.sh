#!/usr/bin/env bash
# deploy/kubernetes/*.yaml을 Helm 차트에서 만든다(차트가 원본).
#   scripts/gen-manifests.sh          다시 생성
#   scripts/gen-manifests.sh --check  생성 결과와 커밋된 파일이 다르면 실패
set -euo pipefail
cd "$(dirname "$0")/.."
chart=charts/dns-auditor
out=deploy/kubernetes
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
hdr='# 이 파일은 scripts/gen-manifests.sh가 charts/dns-auditor에서 생성한다. 직접 고치지 말 것.'
render() { helm template dns-auditor "$chart" -n dns-auditor "$@"; }

{
  echo "$hdr"
  echo "# 적용 후 CoreDNS Corefile에: dnstap tcp://<이 Service의 ClusterIP>:6000 full"
  printf -- '---\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: dns-auditor\n'
  render | sed '/^# Source:/d'
} > "$tmp/dns-auditor.yaml"
{ echo "$hdr"; render --set networkPolicy.enabled=true --show-only templates/networkpolicy.yaml | sed '/^# Source:/d'; } > "$tmp/networkpolicy.yaml"
{ echo "$hdr"; render --set serviceMonitor.enabled=true --show-only templates/servicemonitor.yaml | sed '/^# Source:/d'; } > "$tmp/servicemonitor.yaml"
cp deploy/grafana/dns-auditor-dashboard.json "$tmp/dashboard.json"

if [[ "${1:-}" == --check ]]; then
  rc=0
  for f in dns-auditor.yaml networkpolicy.yaml servicemonitor.yaml; do
    diff -q "$tmp/$f" "$out/$f" >/dev/null || { echo "drift: $out/$f (scripts/gen-manifests.sh 실행 필요)"; rc=1; }
  done
  diff -q "$tmp/dashboard.json" "$chart/files/dns-auditor-dashboard.json" >/dev/null || { echo "drift: $chart/files/dns-auditor-dashboard.json ≠ deploy/grafana"; rc=1; }
  exit $rc
fi
cp "$tmp"/{dns-auditor,networkpolicy,servicemonitor}.yaml "$out/"
cp "$tmp/dashboard.json" "$chart/files/dns-auditor-dashboard.json"
echo "generated $out/*.yaml from $chart"
