#!/usr/bin/env bash
# CoreDNS overhead benchmark (no Docker/kind needed).
#
# Runs a real CoreDNS binary locally with the `template` plugin answering like
# a cluster resolver (search-list names -> NXDOMAIN), and compares:
#   A  no dnstap                      (baseline)
#   B  dnstap -> dns-auditor          (normal operation)
#   C  dnstap -> nothing listening    (auditor down)
#   D  dnstap -> sink that never reads (auditor stuck)
# at several query rates. Results: docs/results/bench-<date>.json
#
#   COREDNS=/path/to/coredns REPS=3 DUR=20s scripts/bench.sh [qps...]   (default 150 750 1500)
#
# Cases are interleaved (A B C D, A B C D, ...) REPS times so that machine
# noise hits all cases alike; compare medians, not single runs.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/go/bin:$PATH"
COREDNS="${COREDNS:?set COREDNS to a coredns binary}"
DUR="${DUR:-20s}"
REPS="${REPS:-3}"
RATES=("${@:-150 750 1500}"); read -ra RATES <<<"${RATES[*]}"
work=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT
go build -o "$work/dns-auditor" ./cmd/dns-auditor
go build -o "$work/dnsbench" ./hack/dnsbench
mkdir -p docs/results
out="docs/results/bench-$(date +%F).json"
: > "$out.tmp"

corefile() { # $1 = dnstap line or empty
  cat > "$work/Corefile" <<EOF
.:1053 {
    errors
    $1
    template IN ANY svc.cluster.local cluster.local {
        rcode NXDOMAIN
    }
    template IN A example.com {
        answer "{{ .Name }} 60 IN A 10.0.0.1"
    }
    template IN AAAA example.com {
        rcode NOERROR
    }
    prometheus 127.0.0.1:19153
    cache 30
}
EOF
}

# A static inventory for the auditor: it needs a Kubernetes API, so B uses a
# local kubeconfig only if one is given; otherwise the receiver path is the
# same and the inventory is empty (every finding is "unknown short name").
start_auditor() {
  "$work/dns-auditor" serve -dnstap-addr 127.0.0.1:16000 -http-addr 127.0.0.1:18080 ${KUBECTX:+-context "$KUBECTX"} -log-level error &
  echo $! > "$work/auditor.pid"
  for _ in $(seq 1 60); do curl -sf 127.0.0.1:18080/readyz >/dev/null && return; sleep 1; done
  echo "auditor not ready" >&2; exit 1
}

run_case() { # $1 name, $2 dnstap line
  local name=$1 line=$2 qps cpid apid res
  corefile "$line"
  "$COREDNS" -conf "$work/Corefile" -quiet >> "$work/coredns-$name.log" 2>&1 &
  cpid=$!
  sleep 1
  for qps in "${RATES[@]}"; do
    "$work/dnsbench" load -server 127.0.0.1:1053 -qps 50 -duration 3s >/dev/null # warm up
    res=$("$work/dnsbench" load -server 127.0.0.1:1053 -qps "$qps" -duration "$DUR" -pid "$cpid")
    apid=$(cat "$work/auditor.pid" 2>/dev/null || true)
    local extra='{}'
    if [[ "$name" == B && -n "$apid" ]]; then
      extra=$(python3 - "$apid" <<'PY'
import sys,urllib.request,re
pid=sys.argv[1]
m=urllib.request.urlopen("http://127.0.0.1:18080/metrics").read().decode()
g=lambda k: float(re.search(r'^'+k+r'(?:\{[^}]*\})? ([0-9.e+]+)$',m,re.M).group(1))
rss=[l for l in open(f"/proc/{pid}/status") if l.startswith("VmRSS")][0].split()[1]
print('{"auditor_frames":%d,"auditor_dropped":%d,"auditor_rss_mib":%.1f}'%(g("dns_auditor_dnstap_frames_total"),g("dns_auditor_dnstap_dropped_total"),int(rss)/1024))
PY
)
    fi
    local tapdrop
    tapdrop=$(grep -c 'dropped' "$work/coredns-$name.log" || true)
    python3 -c "import json,sys; r=json.loads(sys.argv[1]); r.update(json.loads(sys.argv[2])); r['case']=sys.argv[3]; r['coredns_drop_log_lines']=int(sys.argv[4]); r['rep']=int(sys.argv[5]); print(json.dumps(r))" "$res" "$extra" "$name" "$tapdrop" "$rep" | tee -a "$out.tmp"
  done
  kill "$cpid"; wait "$cpid" 2>/dev/null || true
}

"$work/dns-auditor" -h >/dev/null 2>&1 || true
for rep in $(seq 1 "$REPS"); do
  run_case A ""
  start_auditor
  run_case B "dnstap tcp://127.0.0.1:16000 full"
  kill "$(cat "$work/auditor.pid")"; rm -f "$work/auditor.pid"; sleep 1
  run_case C "dnstap tcp://127.0.0.1:16000 full"
  "$work/dnsbench" stuck -addr 127.0.0.1:16000 & stuckpid=$!; sleep 1
  run_case D "dnstap tcp://127.0.0.1:16000 full"
  kill "$stuckpid"; wait "$stuckpid" 2>/dev/null || true; sleep 1
done

python3 - "$out.tmp" "$out" "$("$COREDNS" -version | head -1)" "$DUR" <<'PY'
import json,sys,platform,os
rows=[json.loads(l) for l in open(sys.argv[1])]
json.dump({"coredns":sys.argv[3],"duration":sys.argv[4],"host":platform.platform(),"cpus":os.cpu_count(),"rows":rows},open(sys.argv[2],"w"),indent=1)
PY
rm -f "$out.tmp"
echo "wrote $out"
