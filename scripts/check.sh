#!/usr/bin/env bash
# The single verdict for "is this change done?". Exit 0 = pass.
# Used by `make check`, the Claude Code Stop hook, the git pre-commit hook and CI.
#
#   scripts/check.sh            full check
#   scripts/check.sh quick      fmt + vet + tests (no lint, coverage, fuzz)
set -uo pipefail
cd "$(dirname "$0")/.."

export PATH="$HOME/.local/go/bin:$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin:$HOME/go/bin:$PATH"
export DNS_AUDITOR_PRIVATE="${DNS_AUDITOR_PRIVATE:-$(cd .. && pwd)/dns-auditor-private}"
mode="${1:-full}"
COVER_PKGS=(./internal/rule ./internal/source/corednslog ./internal/source/dnstap ./internal/inventory ./internal/report ./internal/store ./internal/pipeline ./internal/sink/metrics)
COVER_MIN=90
FUZZTIME="${FUZZTIME:-10s}"
RESULTS=docs/results
mkdir -p "$RESULTS"

failed=()
step() { # step <name> <command...>
  local name=$1; shift
  if "$@"; then echo "ok   $name"; else echo "FAIL $name"; failed+=("$name"); fi
}

fmt_check() { local out; out=$(gofmt -l .); [[ -z "$out" ]] || { echo "gofmt needed:"; echo "$out"; return 1; }; }

lint() {
  if command -v golangci-lint >/dev/null; then golangci-lint run ./...
  elif [[ -n "${CI:-}" ]]; then echo "golangci-lint missing in CI"; return 1
  else echo "  (golangci-lint not installed, skipped)"; fi
}

tests() {
  local race=""
  if command -v cc >/dev/null; then race=-race
  elif [[ -n "${CI:-}" ]]; then echo "race detector unavailable in CI"; return 1
  else echo "  (-race unavailable: no C compiler)"; fi
  go test $race -count=1 -json ./... | go run ./hack/testsummary -out "$RESULTS/test-latest.json"
}

cover() {
  local ok=0 p pct
  : > "$RESULTS/cover-latest.txt"
  for p in "${COVER_PKGS[@]}"; do
    pct=$(go test -count=1 -cover "$p" | sed -n 's/.*coverage: \([0-9.]*\)%.*/\1/p')
    printf "  %-34s %6s%%\n" "$p" "$pct" | tee -a "$RESULTS/cover-latest.txt"
    awk -v a="${pct:-0}" -v m=$COVER_MIN 'BEGIN{exit !(a+0>=m)}' || ok=1
  done
  return $ok
}

fuzz() {
  go test -run='^$' -fuzz=FuzzParseLine -fuzztime="$FUZZTIME" ./internal/source/corednslog >/dev/null &&
  go test -run='^$' -fuzz=FuzzDecode -fuzztime="$FUZZTIME" ./internal/source/dnstap >/dev/null
}

step fmt   fmt_check
step vet   go vet ./...
step test  tests
if [[ "$mode" != quick ]]; then
  step lint  lint
  step cover cover
  step fuzz  fuzz
  step leak  bash scripts/leak-scan.sh
fi

if ((${#failed[@]})); then
  echo "check: FAIL (${failed[*]})"
  exit 1
fi
echo "check: PASS ($mode)"
