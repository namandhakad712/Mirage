# Changelog

All notable changes to Mirage are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). Dates are UTC.

## [Unreleased]

### Added — 2026-11-26 (specification round)

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
