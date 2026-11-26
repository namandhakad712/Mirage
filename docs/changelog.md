---
layout: doc
title: "Changelog"
description: "Every notable change to Mirage, round by round, following Keep a Changelog."
category: project
order: 2
source: CHANGELOG.md
---
All notable changes to Mirage are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). Dates are UTC.

## [Unreleased]

### Added — 2026-11-26 (build/docs round)

- Build layer: a root `Makefile` with the full gate set — `help` (default),
  `fmt`/`fmt-check`, `vet`, `build`, `test` (`-race`), `vectors` (the
  golden-vector cross-check), `slop` (a word-boundary, case-sensitive grep
  gate over `*.go`, `*.ts`, `*.mjs`, `*.sh` and the `Makefile` itself for
  unfinished-work markers, with the decoy-template slot word allowed only
  in the renderers that own it), `check` (every gate CI runs) and `clean`
  (never touches `mirage.db` or dotfiles). `worker-build`/`worker-test`
  add the worker suite behind an explicit needs-network note.
- CI (`.github/workflows/ci.yml`): two jobs on every push to `main`, every
  pull request and manual dispatch — the `go` job (setup-go from
  `go.mod`, then `make fmt-check vet build test vectors slop`) and the
  `worker` job (setup-node 20 with the npm cache, then `npm ci`, `npm run
  build`, `npm test` in `packages/mirage-worker`).
- `mirage.example.yaml`: the complete annotated config surface of
  `internal/config` — every key with default, bound and rationale, the
  mode table inline, the loopback dashboard-token requirement, and the
  connector blocks with secrets resolved from `*_env` environment
  variables only.
- Deploy guides: `docs/deploy/quickstart.md` (zero to verified build with
  today's honest status), `docs/deploy/nginx.md` (transparent-proxy
  topology, `X-Forwarded-For`/`trusted_proxies` (I6), the deny map,
  the fail-open contract (I1)) and `docs/deploy/cloudflare-worker.md`
  (build, `wrangler.toml`, deploy, secrets, shared-data regeneration,
  fail-open semantics).
- `docs/vendor-notes.md`: the pinned CrowdSec LAPI surface, the Cloudflare
  access-rules API, the webhook receiver contract with the
  `X-Mirage-Signature` (hex HMAC-SHA256 over the raw body) verification
  recipe, and the shared retry envelope.
- Policy files: `SECURITY.md` (private vulnerability reporting, `mrg_`
  honeytoken namespace, reserved hosts/ranges, supported = `main` only),
  `CONTRIBUTING.md` (dev setup, the spec-first rule, render parity, the
  zero-slop rule, commit/branch style, the license split), `CODEOWNERS`
  and a PR checklist template.
- README: architecture overview (packages table), connectors table, CI
  badge, quickstart pointer and an honest status section — server binary
  and Go edge middleware remain in development.

### Fixed — 2026-11-26 (render-parity round)

- `{% raw %}{{SEED:*}}{% endraw %}` derivation is now per-spec-string occurrence-counted:
  the material is `sha256(session_key + ":" + entry_id + ":seed:" +
  spec + ":" + k)` where `k` is the k-th occurrence of that spec in the
  body, so two identical placeholders never collide while the formula
  stays identical across engines. Pinned byte-for-byte by the new
  cross-engine fixture `spec/golden-vectors/renders.json` (every catalog
  entry rendered for two fixed sessions), consumed by BOTH the Go suite
  (`internal/decoy/render_golden_test.go`) and the worker suite
  (`packages/mirage-worker/test/render.golden.test.ts`); CI fails on any
  divergence.
- `{% raw %}{{SEED:N_UPPER}}{% endraw %}` alphabet is 36 chars (A-Z0-9) in both engines —
  the TypeScript renderer previously used 26 letters and produced
  different bytes from Go for the same session (caught by the golden
  fixture, fixed before release).
- `{% raw %}{{SEED:N_HEX}}{% endraw %}` now slices the digest directly (N ≤ 64) and
  `{% raw %}{{SEED:N_B64}}{% endraw %}` is unpadded standard base64 derived from 3N/4 digest
  bytes (N must be a multiple of 4), matching Go exactly.
- Spec canon updated: `spec/DECOY-CATALOG.md` §4 now states the exact
  seed material, the three SEED formats and the golden-fixture pin.

### Added — 2026-11-26 (engine round)

- Decision engine (`internal/detect`): SIGNALS v1.1.0 in code — all 11
  signals, the verdict ladder with the protected-route cap and the
  honeytoken exception, the three gating rules, session state and
  expiry. Golden-vector suite replays all 20 cases / 68 requests with
  20/20 case and 68/68 request parity against the hand-computed
  expectations.
- Decoy data layer (`internal/decoy`): strict catalog loader with
  reserved-value validation, deterministic renderer (seeded
  placeholders, honeytoken minting, noindex set, size cap with UTF-8
  boundary), and the pollution suite (secret-scanner patterns,
  no-real-domain and inert-body checks over the rendered catalog).
- Cloudflare Worker port (`packages/mirage-worker`): zero-runtime-dep
  TypeScript engine (synchronous sha256), fail-open handler honoring
  the adapter protocol (hard deadline, reserved decision), built-in
  data generated from the shared spec files, vitest suite with full
  golden-vector parity.

### Added — 2026-11-26 (core round)

- Go module `github.com/mirage-shield/mirage` and `internal/model`: the
  shared decision types, fail-open semantics, session key
  `sha256(ip)[:32]`, the right-to-left trusted-proxy client-IP walk with
  malformed-hop skipping and peer fallback, never-scored / never-banned
  ranges (loopback, RFC 1918, CGNAT, link-local, TEST-NET), and the
  reason-text sanitizer.
- `internal/config`: strict YAML loading with fail-closed unknown-key
  rejection, all policy thresholds and protected routes, loopback
  dashboard token requirement, mode validation (look | tripwires |
  protect).
- `internal/store`: SQLite (WAL) and in-memory session stores behind one
  interface, versioned schema with safe migration, session state with
  30-minute expiry reset.
- `internal/events`: bounded drop-oldest event queue with a drainable
  snapshot for the dashboard.
- `internal/enforce`: verdict gatekeeper — tag always allowed, throttle
  and ban gated behind the kill switch and per-verdict budgets; budgets
  never fail-open a hard verdict's proof chain (honeytoken_use).
- `internal/connectors`: denyfile (source-suffix lines), webhook with
  HMAC-SHA256 signing and replay guard, CrowdSec LAPI decision pull,
  Cloudflare firewall-rule adapter, all behind one retry envelope
  (bounded attempts, exponential backoff with jitter, 429 Retry-After
  honored); every connector is fail-open by design and tested to be.

- Normative signal specification v1.1.0 (`spec/SIGNALS.md`): 11 signals
  with fixed weights, classes and reason codes; the verdict ladder
  (observe / tag / decoy_route / throttle / ban) with the protected-route
  cap and the honeytoken exception; the three gating rules (curl, UA
  rotation, cookie persistence); session state, expiry and scoring
  semantics; five normative worked examples.
- Adapter protocol v1 (`spec/ADAPTER-PROTOCOL.md`): DecisionRequest /
  Decision / Event shapes, hard deadlines, the reserved fail-open decision,
  and six conformance requirements.
- Decoy catalog spec v1 (`spec/DECOY-CATALOG.md`) plus the catalog itself
  (`spec/decoy-catalog/catalog.yaml`): three personas, six entries,
  inert-body templates, seeded placeholders, honeytoken minting, and the
  pollution suite definition.
- Shared data files used verbatim by every implementation
  (`data/scanner-paths.txt`, `ua-suspicious.txt`, `ua-verified-bots.txt`,
  `reserved-hosts.txt`, `token-formats.md`, `reason-texts.txt`).
- Golden vectors: 20 cases, 68 requests (`spec/golden-vectors/`),
  hand-computed derivations (`HAND-COMPUTED.md`) cross-checked by an
  independent reference engine (`tools/gen_vectors.py`) that refuses to
  emit on any disagreement. Vector canon decisions recorded (ungating set,
  tie-breaks, unknown-path exclusion, decoy serving semantics).
- Spec amendment during vector cross-check: throttle now escalates on the
  request's own score only (history never escalates past tag).

### Added — 2026-11-26 (foundation round)

- Project constitution: fifteen invariants with test hooks
  (`docs/invariants.md`), the charter (`docs/charter.md`) covering scope,
  ethics and the no-pollution rules, the claims policy
  (`docs/claims-policy.md`), and Known Limits written first
  (`docs/known-limits.md`).
- Licensing split: AGPL-3.0 for the Go core, Apache-2.0 for adapters, SDKs
  and the Cloudflare Worker (`LICENSE`, `packages/mirage-worker/LICENSE`).
- Full production design document reproduced for the record
  (`docs/design/MIRAGE-DESIGN.md`).
- Repository skeleton and README.

[Unreleased]: https://github.com/namandhakad712/Mirage/commits/main
