# Mirage — build and quality gates.
#
# Everything CI runs is runnable locally with `make check`. The gates are
# deterministic: agents and humans propose code, these gates decide.
#
#   fmt-check  gofmt-clean tree
#   vet        go vet
#   build      go build
#   test       go test -race
#   vectors    golden-vector cross-check (tools/gen_vectors.py)
#   slop       grep gate over code files
#
# The worker targets (worker-build, worker-test) need network access for
# `npm ci`; no Go gate does. Mirage fails closed at boot and open at
# request time (internal/config) — this Makefile follows the same spirit:
# a gate that cannot run cleanly fails, it never passes silently.

GO      ?= go
PYTHON  ?= python3
NPM     ?= npm

# Version stamping for the mirage CLI (cmd/mirage): injected with
# -ldflags -X into the package-level version/commit vars, so `mirage
# version` reports what was built and from where. A build outside git
# (source tarball) falls back to the in-code defaults dev/none.
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT)

# --- slop gate --------------------------------------------------------------
# Word-boundary, case-sensitive grep over code files (*.go, *.ts, *.mjs,
# *.sh and this Makefile) for the classic unfinished-work markers. The
# character classes in the patterns keep this file's own pattern text from
# matching itself. spec/, docs/ and data/ are not code and are never
# scanned (the catalog spec legitimately discusses its template slots).
slop_classic_pattern := \bTO[D]O\b|\bFIX[M]E\b|\bXX[X]\b|\blor[e]m\b
# The decoy-template slot word is the correct domain term ONLY in the
# renderers, where it names {{SEED:...}} / {{TOKEN:...}} catalog slots:
# internal/decoy and the worker's render.ts plus its test. In any other
# code path it is flagged, because nothing else in Mirage renders
# templates.
slop_slot_pattern := \bplaceholde[r]\b
slop_code_files := $(shell find . \( -name .git -o -name node_modules -o -name dist -o -name .wrangler \) -prune -o -type f \( -name '*.go' -o -name '*.ts' -o -name '*.mjs' -o -name '*.sh' -o -name Makefile \) -print)
slop_slot_exempt := ./internal/decoy/% ./packages/mirage-worker/src/render.ts ./packages/mirage-worker/test/render.test.ts
slop_slot_files := $(filter-out $(slop_slot_exempt),$(slop_code_files))

.PHONY: help fmt fmt-check vet build test vectors worker-build worker-test slop check clean

help: ## Print this target list (default target)
	@printf 'Mirage build and quality gates\n\n'
	@printf 'Usage: make <target>\n\nTargets:\n'
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN { FS = ":.*## " } { printf "  %-16s %s\n", $$1, $$2 }'

fmt: ## gofmt: rewrite every Go file in place
	$(GO)fmt -l -w .

fmt-check: ## gofmt: fail if any Go file is not gofmt-clean
	@out="$$($(GO)fmt -l .)"; if [ -n "$$out" ]; then \
		printf 'files not gofmt-clean:\n%s\n' "$$out" >&2; exit 1; \
	fi

vet: ## Run go vet over every package
	$(GO) vet ./...

build: ## Compile every Go package and the mirage CLI binary (bin/mirage)
	$(GO) build ./...
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/mirage ./cmd/mirage

test: ## Run every test with the race detector
	$(GO) test -race ./...

vectors: ## Regenerate the golden vectors and cross-check both sources
	$(PYTHON) tools/gen_vectors.py

# These two need network access to the npm registry (`npm ci`); none of
# the gates above do.
worker-build: ## Build the Cloudflare Worker (needs network: npm ci)
	cd packages/mirage-worker && $(NPM) ci && $(NPM) run build

worker-test: ## Run the Worker test suite (needs network: npm ci)
	cd packages/mirage-worker && $(NPM) ci && $(NPM) test

slop: ## Grep gate: reject unfinished-work markers in code files
	@if [ -z "$(slop_code_files)" ]; then \
		echo "slop: no code files found" >&2; exit 1; \
	fi; \
	out=$$(grep -nE '$(slop_classic_pattern)' $(slop_code_files)); rc=$$?; \
	if [ $$rc -eq 0 ]; then \
		printf '%s\n' "$$out"; \
		echo "slop: unfinished-work markers found in code files (see above)" >&2; exit 1; \
	elif [ $$rc -gt 1 ]; then \
		echo "slop: grep failed (rc $$rc)" >&2; exit 1; \
	fi; \
	out=$$(grep -nE '$(slop_slot_pattern)' $(slop_slot_files)); rc=$$?; \
	if [ $$rc -eq 0 ]; then \
		printf '%s\n' "$$out"; \
		echo "slop: decoy-template slot word outside the renderers (see above)" >&2; exit 1; \
	elif [ $$rc -gt 1 ]; then \
		echo "slop: grep failed (rc $$rc)" >&2; exit 1; \
	fi; \
	echo "slop: clean ($(words $(slop_code_files)) code files scanned)"

check: fmt-check vet build test vectors slop ## Run every quality gate CI runs
	@echo "check: all gates green"

clean: ## Remove build and test artifacts (never mirage.db or dotfiles)
	$(GO) clean
	rm -rf bin dist packages/mirage-worker/dist
	rm -f coverage.txt
	find . -type f \( -name '*.test' -o -name '*.out' -o -name '*.tsbuildinfo' \) \
		-not -path './.git/*' -not -path '*/node_modules/*' -print -delete
