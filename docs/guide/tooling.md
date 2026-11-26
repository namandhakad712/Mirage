---
layout: doc
title: "Tooling"
description: "Every quality gate and lab in the Mirage repo: the Makefile targets, the golden-vector generator, the fault-injection matrix and the docs-site gates."
category: guide
order: 8
---

Mirage's tooling is deterministic on purpose: agents and humans propose
code, the gates decide. Everything CI runs is runnable locally with
`make check`. No Go gate needs network access; the two worker targets do
(`npm ci`).

## Makefile targets

| Target | What it runs |
| --- | --- |
| `help` | Print the target list (the default target). |
| `fmt` | gofmt, rewriting every Go file in place. |
| `fmt-check` | Fail (exit 1) if any Go file is not gofmt-clean. |
| `vet` | `go vet ./...`. |
| `build` | `go build ./...` — the library core. |
| `test` | `go test -race ./...` — every test under the race detector. |
| `vectors` | `python3 tools/gen_vectors.py` — regenerate the golden vectors and cross-check both sources. |
| `worker-build` | In `packages/mirage-worker`: `npm ci && npm run build` (needs network). |
| `worker-test` | In `packages/mirage-worker`: `npm ci && npm test` (needs network). |
| `slop` | Grep gate over `*.go`, `*.ts`, `*.mjs`, `*.sh` and the Makefile: word-boundary, case-sensitive matches for unfinished-work markers fail the build; the decoy-template slot word is allowed only in the renderers that own it. `spec/`, `docs/` and `data/` are not code and are never scanned. |
| `check` | `fmt-check vet build test vectors slop` — every gate CI runs. |
| `clean` | Remove build and test artifacts; never touches `mirage.db` or dotfiles. |

## The golden-vector generator

`tools/gen_vectors.py` (Python 3, needs PyYAML) is two sources of truth
that cross-check each other: hand-computed expectations written out in each
case's notes, and an independent reference engine implementing
`spec/SIGNALS.md` v1.1.0. Run from the repo root it regenerates
`spec/golden-vectors/vectors.json` and `HAND-COMPUTED.md` — and exits 1,
printing every mismatch, if the two hands disagree. No vector is emitted
that both have not agreed on. The catalog is loaded from the real
`spec/decoy-catalog/catalog.yaml` so the vectors can never drift from it.
See [testing]({{ site.baseurl }}/guide/testing.html) for adding a case.

## The fault-injection lab

`lab/faultinject` proves the fail-open invariants hold when everything
around the decision path is broken. Each scenario builds a real stack —
real rules, real catalog, real engine, queue, gatekeeper, dashboard, config
through the real loader — and injects exactly one fault family, asserting
system behavior (exact verdicts, actions, bounded timings), never just "it
did not crash":

| Scenario | Fault | Proves |
| --- | --- | --- |
| `store-down` | Every store method fails | I1, I3, I10 |
| `queue-flood` | Queue at capacity 100, drainer never started | I3, I10 |
| `connector-dead` | Connector Apply always errors | I1, I5, I10 |
| `connector-hang` | Connector Apply blocks until released | I1, I3, I5 |
| `budget-exhausted` | MaxBansPerMinute 1, two ban-grade attackers | I5, I9, I10 |
| `never-ban` | Ban-grade replay from an owner range | I6, I15 |
| `deadline-overrun` | Decision clock jumps past the budget | I1, I3 |
| `kill-switch` | Boot with the switch on; then a live flip | I9, I10 |
| `dashboard-storm` | 50 concurrent workers, mixed tokens, broken store | I1, I7, I11 |

Run it:

```bash
go run ./lab/faultinject          # the whole matrix, prints the table
go run ./lab/faultinject -list    # names, invariants, descriptions
go run ./lab/faultinject -only store-down,queue-flood -v
go test -race ./lab/faultinject/  # the same scenarios as subtests
```

Exit 0 only when every selected scenario passed; failures are named on
stderr. An unknown `-only` name is a usage error listing the valid names.

## The worker build

`packages/mirage-worker` builds in three steps, failing on the first error:
`scripts/gen-data.mjs` regenerates `src/generated/data.ts` from the shared
repo data files and catalog (deterministic output, no timestamps, so
regeneration produces a diff only if the shared data really changed); then
`tsc --project tsconfig.json` type-checks; then `tsc --project
tsconfig.build.json` emits `dist/` as multi-file ES2022 modules — no
bundler, Cloudflare bundles the ESM graph itself. `npm test` (vitest)
replays the full shared golden-vector corpus plus the cross-engine render
fixture and the handler suite. Never hand-edit the generated snapshot.

## The docs-site gates

Two scripts guard this site. `tools/sync_site_docs.py` keeps the docs/
mirrors of `spec/` and `data/` fresh — run it after changing a spec or a
shared data file, and run it with `--check` in CI to fail when mirrors are
stale. `tools/check_site.py` validates the site itself: front matter on
every page, internal links, navigation entries, and consistency between
`llms.txt` and `docs.json`. Both exit non-zero on any finding; a gate that
cannot run cleanly fails, it never passes silently.

The full test architecture — what each suite pins, and how to extend the
vectors — continues in
[testing]({{ site.baseurl }}/guide/testing.html).
