---
layout: doc
title: "Testing"
description: "How Mirage is tested: golden vectors, the race suite, the pollution suite, the fault matrix, worker parity, and how to add a new vector."
category: guide
order: 10
---

Mirage's test architecture exists to make one claim checkable: two
implementations, written twice, produce identical decisions. Every layer
below pins a piece of that claim, and the
[tooling page]({{ site.baseurl }}/guide/tooling.html) lists the commands.

## Golden vectors

`spec/golden-vectors/vectors.json` is the executable contract: 20 cases,
68 requests, each with hand-computed expectations — signals, verdict,
score, reason code. `spec/golden-vectors/HAND-COMPUTED.md` shows the
arithmetic for every case, written out from `spec/SIGNALS.md` v1.1.0. The
expectations are cross-checked by an independent reference engine inside
`tools/gen_vectors.py`, which refuses to emit on any disagreement (exit 1,
mismatches printed). Both the Go suites (`internal/detect`,
`internal/service`) and the worker suite
(`packages/mirage-worker/test/engine.vectors.test.ts`) replay the same
file; CI fails on any divergence. The vectors use only reserved values —
RFC 5737 client IPs, RFC 2606 hostnames (I14).

## The suites around them

- **Race suite** — `go test -race ./...` covers the engine, queue, store,
  gatekeeper, connectors and service under concurrency.
- **Pollution suite** — `internal/decoy` asserts the web stays clean:
  verified-bot crawls see zero decoy URLs, every decoy response carries the
  noindex set, secret scanners and format validators find no live-valid
  credentials, and bodies stay inert (I12–I14).
- **Fault matrix** — `lab/faultinject` builds real stacks and breaks one
  thing at a time (store, queue, connector, budget, deadline, kill switch,
  dashboard) asserting exact behavior, not survival.
- **Render parity** — `spec/golden-vectors/renders.json` pins the rendered
  body of every catalog entry for two fixed session keys, consumed by both
  `internal/decoy/render_golden_test.go` and the worker's
  `test/render.golden.test.ts`.
- **Worker handler suite** — vitest covers the fail-open paths (engine
  throw, budget overrun), the local action responses, the event ring
  bounds and request translation.

## How to add a vector

The vectors are generated, never hand-edited: `vectors.json` and
`HAND-COMPUTED.md` are both emitted by the generator. To add a case:

1. **Write the case with its hand computation.** In `tools/gen_vectors.py`,
   add a `case(...)` to `CASES`: an id, a reserved client IP
   (192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24), a note that writes
   out the arithmetic per `HAND-COMPUTED.md` style, the requests (the `R`
   helper) and the expectations (the `E` helper). Compute every expectation
   by hand from `spec/SIGNALS.md` — the note is the proof.
2. **Run the cross-check.** `make vectors` runs the generator; if your
   hand computation and the reference engine disagree, it exits 1 and
   names the field. Fix one of them — usually the hand computation —
   before anything else. A case whose auth hint needs a minted honeytoken
   resolves it at generation time, the way the existing cases do.
3. **Run the consumers.** `go test ./internal/detect/` and
   `go test ./internal/service/` must replay the new case green; then
   `cd packages/mirage-worker && npm test` must do the same in TypeScript.
   CI runs all of this via `make check` plus `make worker-test`.
4. **Record canon decisions.** If your case pins a previously ambiguous
   rule, add it to the canon-decisions list the generator writes at the
   end of `HAND-COMPUTED.md`, the way the existing entries do.

If the case exposes a spec disagreement rather than an implementation bug,
the spec changes first — bump `spec_version`, regenerate the vectors, and
let every suite fail until both engines agree again. That spec-first rule
is the discipline that keeps two implementations honest.

The [FAQ]({{ site.baseurl }}/guide/faq.html) answers the questions this
architecture raises most often.
