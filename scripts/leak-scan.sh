#!/usr/bin/env bash
# Fails if files that would be published contain secrets or organization
# specific strings.
#
# Organization patterns are NOT stored in this repository (the list itself
# would leak them). They are read from $DNS_AUDITOR_PRIVATE/leak-patterns.txt,
# one extended regex per line. Without that file only the generic checks run.
set -euo pipefail
cd "$(dirname "$0")/.."
# Default: sibling directory, same as scripts/check.sh.
export DNS_AUDITOR_PRIVATE="${DNS_AUDITOR_PRIVATE:-$(cd .. && pwd)/dns-auditor-private}"

if git rev-parse --git-dir >/dev/null 2>&1; then
  mapfile -t files < <(git ls-files -co --exclude-standard)
else
  mapfile -t files < <(find . -type f -not -path './.git/*')
fi

status=0
generic='AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|xox[abprs]-[0-9A-Za-z-]{10,}|gh[pousr]_[0-9A-Za-z]{36}|glpat-[0-9A-Za-z_-]{20}'
if grep -nIE "$generic" -- "${files[@]}"; then
  echo "leak-scan: generic secret pattern found" >&2
  status=1
fi

patterns="${DNS_AUDITOR_PRIVATE:-}/leak-patterns.txt"
if [[ -n "${DNS_AUDITOR_PRIVATE:-}" && -f "$patterns" ]]; then
  if grep -nIiE -f <(grep -vE '^\s*(#|$)' "$patterns") -- "${files[@]}"; then
    echo "leak-scan: organization pattern found (see $patterns)" >&2
    status=1
  fi
  echo "leak-scan: checked ${#files[@]} files (generic + organization patterns)"
else
  echo "leak-scan: checked ${#files[@]} files (generic only; set DNS_AUDITOR_PRIVATE for organization patterns)"
fi
exit $status
