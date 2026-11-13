#!/usr/bin/env bash
# Claude Code Stop: if the repo changed since the last passing check, run the
# quick check; on failure block stopping (exit 2) so the loop continues.
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root" || exit 0
stamp="$(git rev-parse --git-dir 2>/dev/null || echo .)/claude-last-pass"
state=$( { git ls-files -co --exclude-standard -z | xargs -0 sha1sum 2>/dev/null; } | sha1sum | cut -d' ' -f1)
[[ -f "$stamp" && "$(cat "$stamp")" == "$state" ]] && exit 0
if out=$(bash scripts/check.sh quick 2>&1); then
  echo "$state" > "$stamp"
  exit 0
fi
echo "dns-auditor quick check failed; fix before finishing:" >&2
echo "$out" | tail -30 >&2
exit 2
