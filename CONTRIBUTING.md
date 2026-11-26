# Contributing to Mirage

Read [docs/charter.md](docs/charter.md) and [docs/invariants.md](docs/invariants.md)
first. Contributions that add hack-back, web pollution, live credential
formats, indexable decoys or marketing overclaims will be declined by
charter — the invariants (I1–I15) are binding, and changing one requires a
recorded ADR in `docs/adr/`.

## Development setup

- **Go 1.23 or newer** (the module pins `go 1.23.0`; the repo builds with
  the `go1.23.4` toolchain).
- **Node 20 or newer** with npm, for the Cloudflare Worker
  (`packages/mirage-worker` requires `node >=20`).
- **Python 3 with PyYAML**, for the golden-vector generator.
- **GNU make** — every gate is a make target.

```sh
git clone https://github.com/namandhakad712/Mirage.git
cd Mirage
make check          # fmt-check, vet, build, test, vectors, slop
```

`make worker-build` and `make worker-test` add the worker suite; they need
network access for `npm ci`. `make help` lists everything.

## The spec-first rule

The specs are normative, and the golden vectors are the spec made
executable. When a change alters what the engines must decide:

1. **Change the spec first** — `spec/SIGNALS.md`,
   `spec/ADAPTER-PROTOCOL.md` or `spec/DECOY-CATALOG.md`.
2. **Regenerate the golden vectors**: `make vectors`
   (`python3 tools/gen_vectors.py`). The generator holds two independent
   sources of truth — hand-computed expectations (the arithmetic is
   written out per case in `HAND-COMPUTED.md`) and a reference engine
   implemented in the script itself — and it **exits 1 on any
   disagreement**, refusing to emit a vector both hands have not agreed
   on. Commit the regenerated `spec/golden-vectors/vectors.json` and
   `HAND-COMPUTED.md` in the same PR as the spec change.
3. **Only then touch the engines.** The Go engine
   (`internal/detect`) and the TypeScript engine
   (`packages/mirage-worker/src/engine.ts`) must both pass the new
   vectors — `make test` and `make worker-test`.

A PR that changes engine behavior without the spec and vectors coming
first in the same PR does not merge, regardless of how green its tests
are: the vectors are the definition of correct.

### Render parity

Decoy rendering is pinned byte-for-byte across engines by
`spec/golden-vectors/renders.json` — every catalog entry rendered for two
fixed sessions. The fixture is consumed by **both** suites:
`internal/decoy/render_golden_test.go` and
`packages/mirage-worker/test/render.golden.test.ts`. A renderer change
that is not a documented spec change (`spec/DECOY-CATALOG.md` §4) will
break one or both of them; that is the gate working. After changing the
catalog or the renderer, both suites must stay green on the same fixture.

## The zero-slop rule

`make check` is the contract; CI (`.github/workflows/ci.yml`) runs exactly
the same gates on every push and pull request. The gates:

- **fmt-check / vet / build / test** — gofmt-clean, `go vet ./...`,
  `go build ./...`, `go test -race ./...`. Nothing merges red.
- **vectors** — the cross-check above must pass.
- **slop** — a word-boundary, case-sensitive grep over code files
  (`*.go`, `*.ts`, `*.mjs`, `*.sh`, `Makefile`) for the classic
  unfinished-work markers, plus the decoy-template slot word, which is
  legitimate only in the renderers that own it (`internal/decoy/` and the
  worker's `render.ts` and its test). The exact patterns and exemptions
  live in the `slop` target of the `Makefile` — the source of truth for
  what is grepped. `spec/`, `docs/` and `data/` are not code and are not
  scanned.
- **Secrets** — no connector credential is ever inline; only the
  `*_env` variable names live in the config file (I11). A secret in a
  diff is an automatic rejection.

Nothing merges on model confidence or a reviewer's good mood alone:
deterministic gates decide (the design's Build Factory rule, Part V of
`docs/design/MIRAGE-DESIGN.md`).

## Branches and commits

- Branch from `main`, one branch per change: `feat/<topic>`,
  `fix/<topic>`, `spec/<topic>`, `docs/<topic>`, `build/<topic>`.
- Commit subjects use the same prefixes: `feat:`, `fix:`, `spec:`,
  `docs:`, `build:` — e.g. `spec: SIGNALS 1.1.0 — throttle escalates on
  the request's own score only`.
- PRs are squash-merged; the squash subject becomes the commit on
  `main`, so write it in that format.

## License split, and what it means for your contribution

Mirage is two licenses on purpose:

- The **Go core** (everything under the repo root except `packages/`) is
  **AGPL-3.0** — see [LICENSE](LICENSE). Core contributions are licensed
  under AGPL-3.0.
- **Adapters, SDKs and the Cloudflare Worker** (`packages/mirage-worker`,
  and future adapters/SDKs) are **Apache-2.0** — see
  [packages/mirage-worker/LICENSE](packages/mirage-worker/LICENSE), so
  adapters can be embedded anywhere. Worker and adapter contributions
  are licensed under Apache-2.0.

By contributing to a file, you license your contribution under that
file's license. Keep the split clean: code in `packages/` stays Apache-2.0
and self-contained; core logic does not move from `internal/` into
`packages/` to dodge the AGPL — the shared spec and data files are the
designed interface between the two halves.

## Where to start

The lowest-barrier contributions, per the charter:

- **Decoy packs** — YAML only, validated by the catalog suite (no code).
- **Platform recipes** — deployment guides like `docs/deploy/*`, each
  carrying a verified-on date.
- **Translations** and **adapters** through the SDK.

Open an issue or a draft PR before large work, so the spec round can be
agreed first. Security reports do not go through issues — see
[SECURITY.md](SECURITY.md).
