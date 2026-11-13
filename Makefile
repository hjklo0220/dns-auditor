# The verdict lives in scripts/check.sh so that environments without make
# (and the Claude Code hooks) run exactly the same checks.

GO ?= $(shell command -v go 2>/dev/null || echo $(HOME)/.local/go/bin/go)

.PHONY: check quick synthetic build clean

check:
	@bash scripts/check.sh

quick:
	@bash scripts/check.sh quick

synthetic:
	$(GO) run ./hack/gensynthetic

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/dns-auditor ./cmd/dns-auditor

clean:
	rm -rf bin
