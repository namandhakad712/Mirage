---
layout: doc
title: "Cloudflare Worker"
description: "Build, configure and deploy the zero-dependency worker port, including secrets and shared-data regeneration."
category: deploy
order: 3
---
This is the deployment that runs today: a Cloudflare Worker carrying the
same SIGNALS v1.1.0 detection engine and decoy catalog as the Go core,
in-process, with zero runtime dependencies (the only imports are Mirage's
own modules and a build-time-generated data snapshot). The worker is
Apache-2.0 (`packages/mirage-worker/LICENSE`), so it can travel anywhere
permissive licensing requires.

Every claim below is pinned by code: the build chain in
`packages/mirage-worker/scripts/build.mjs` and `scripts/gen-data.mjs`, the
handler in `src/worker.ts`, and the test suites in
`packages/mirage-worker/test/`.

## Build

```sh
cd packages/mirage-worker
npm ci
npm run build
```

`npm run build` runs three steps, in order, failing on the first error:

1. **`scripts/gen-data.mjs`** — regenerates `src/generated/data.ts` from
   the shared repo data files and the decoy catalog, so the snapshot in
   the bundle can never drift from the spec sources.
2. **`tsc --project tsconfig.json`** — type-checks `src` and `test`
   (`noEmit`).
3. **`tsc --project tsconfig.build.json`** — emits `dist/` as multi-file
   ES2022 modules.

There is deliberately no bundler step: Cloudflare Workers accept multi-file
ESM uploads and `wrangler deploy` bundles the emitted graph itself, so the
honest build is plain `tsc`. The output entry point is `dist/worker.js`
(from `src/worker.ts`).

Run the suite while you are here — it replays the full shared golden-vector
corpus (20 cases / 68 requests) against the same engine, plus the
cross-engine render fixture:

```sh
npm test    # vitest run
```

## Deploy

There is no `wrangler.toml` in the repository — configuration is yours.
Create one in the package directory, next to the built `dist/`:

```toml
# packages/mirage-worker/wrangler.toml
name = "mirage-worker"
main = "dist/worker.js"
compatibility_date = "2026-11-01"

# Production traffic (optional until you are satisfied with the
# workers.dev preview): bind the worker to your zone.
# routes = [
#   { pattern = "example.com/*", zone_name = "example.com" },
# ]
```

`compatibility_date` must not be in the future for the wrangler version
you run. Then, from `packages/mirage-worker`:

```sh
npx wrangler deploy
```

`wrangler` is not a devDependency of the package (it would pull a large
tree into the zero-runtime-dependency guarantee); `npx wrangler deploy`
uses the pinned latest wrangler on demand. You need the Cloudflare
account to allow your user access to the target zone.

## Secrets

The worker needs **no secrets in v1** — the engine is deterministic, the
catalog data rides in the generated snapshot, and enforcement (the
credential-bearing half of Mirage) stays in the Go core. The single
reserved binding is `MIRAGE_TOKENS`, held for a future honeytoken-registry
integration; it is accepted by the handler but has no effect on any
decision today (see the `Env` interface in `src/worker.ts`). When it
becomes meaningful, set it without code changes:

```sh
npx wrangler secret put MIRAGE_TOKENS
```

Secrets belong in the Workers secret store, never in code or in
`wrangler.toml` — the same least-privilege rule the Go core enforces by
resolving every connector credential from the environment (I11).

## Keeping the shared data current

The engine's data — scanner paths, suspicious and verified-bot user-agent
patterns, reserved hosts, and the decoy catalog — is shared verbatim with
the Go core. `scripts/gen-data.mjs` regenerates the snapshot:

```sh
cd packages/mirage-worker
npm run gen
```

Run it from inside the package directory in a full checkout: the script
anchors its input paths at the package root and reads
`../../data/scanner-paths.txt`, `../../data/ua-suspicious.txt`,
`../../data/ua-verified-bots.txt`, `../../data/reserved-hosts.txt` and
`../../spec/decoy-catalog/catalog.yaml` (DECOY-CATALOG.md v1). The output
is deterministic — no timestamps — so regeneration produces spurious diffs
only if the shared data really changed. `npm run build` runs the same
script as its first step, and `make worker-build` from the repo root runs
the full chain. Never hand-edit `src/generated/data.ts`; it is marked
GENERATED, and the parity suites fail if the engines ever disagree.

## How the worker behaves (and fails)

Fail-open is the contract (ADAPTER-PROTOCOL §3, I1), implemented in
`src/worker.ts`:

- **A hard 5 ms decision budget** (`DECISION_DEADLINE_MS`, matching the
  protocol's recommendation). If scoring and acting overrun it, the
  request passes to the origin unmodified.
- **Any internal error — engine throw, deadline overrun, decoy render
  failure — produces the reserved fail-open decision** (verdict `observe`,
  action `pass`, reason code `SIG-000`) and the request still reaches the
  origin unmodified. The origin `fetch` stays outside the error boundary,
  so an origin network error is never mistaken for a Mirage error and
  never retried by Mirage.
- **Local actions only, when a verdict says so:** `decoy_route` serves the
  decoy rendered locally from the in-bundle catalog snapshot — never a
  network fetch, never a redirect (I3, I2, I8); `throttle` answers 429
  with `Retry-After: 30` and `Cache-Control: no-store`; `ban` answers 403
  with `X-Mirage-Ban-Ttl` (seconds) and `no-store`.
- **Stateless across isolates.** Workers share no memory between
  invocations, so durable bans and throttles belong to the Go core; the
  worker's `ban`/`throttle` are per-request local responses. Long-horizon
  session signals are therefore approximate in worker mode — a recorded
  limit in [known-limits.md]({{ site.baseurl }}/known-limits.html).
- **Client identity comes from `CF-Connecting-IP`**, set by the Cloudflare
  platform and unspoofable by clients. Spoofable headers like
  `X-Forwarded-For` are deliberately never scored (I6).
- **A bounded event ring** (10 000 events, oldest dropped) keeps
  conformance with the adapter protocol's event contract in each isolate,
  with `failOpen` and `dropped` counters exposed for ops probes via
  `getEventStats()`.

All of the above is exercised by `npm test`: the handler suite covers the
fail-open paths (engine throw, budget overrun), the local action responses,
the ring bounds and the request translation, and the engine suite replays
the full golden-vector corpus shared with the Go implementation.

## See also

- [quickstart.md]({{ site.baseurl }}/deploy/quickstart.html) — the full from-zero path.
- [vendor-notes.md]({{ site.baseurl }}/vendor-notes.html) — the enforcement side of Mirage
  (CrowdSec, Cloudflare access rules, webhook receivers), which stays
  with the self-hosted core.
- `spec/ADAPTER-PROTOCOL.md` — the normative contract the handler
  implements.
