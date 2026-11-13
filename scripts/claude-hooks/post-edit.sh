#!/usr/bin/env bash
# Claude Code PostToolUse(Edit|Write): fast feedback for Go files in this repo.
# Exit 2 + stderr = shown to Claude so it fixes the problem immediately.
root="$(cd "$(dirname "$0")/../.." && pwd)"
f=$(jq -r '.tool_response.filePath // .tool_input.file_path // empty')
[[ "$f" == "$root"/*.go ]] || exit 0
[[ -f "$f" ]] || exit 0
export PATH="$HOME/.local/go/bin:$PATH"
out=$(gofmt -l "$f" 2>&1)
if [[ -n "$out" ]]; then echo "gofmt needed: $f (run gofmt -w)" >&2; exit 2; fi
pkg="./$(realpath --relative-to="$root" "$(dirname "$f")")"
if ! vet=$(cd "$root" && go vet "$pkg" 2>&1); then echo "go vet $pkg failed:" >&2; echo "$vet" | tail -20 >&2; exit 2; fi
exit 0
