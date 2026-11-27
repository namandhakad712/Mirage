---
layout: doc
title: "Quickstart"
description: "The shortest honest path to a running Mirage: build, check, configure, watch the first decisions."
category: deploy
order: 1
---
This page is the honest path from a fresh clone to a working Mirage
installation: build, verify, configure, serve, and watch the first
decisions.

## Status: what runs today

**Shipped and tested:** the components listed in this section, each behind
the repo's gates — nothing has been released yet, and the
[changelog]({{ site.baseurl }}/changelog.html) tracks the work under
`[Unreleased]`. The normative specs and golden vectors; the Go core
(config, model, store, events, enforce, connectors); the SIGNALS v1.1.0
detection engine; the decoy data layer; the in-process HTTP edge
middleware (`internal/edge`); the `mirage` CLI — `serve`, `doctor`,
`init`, `posture`, `replay`, `version` (`cmd/mirage`); the
fault-injection lab; and the Cloudflare Worker port. Every gate runs in
CI on every push:
`make check` (fmt, vet, build, race tests, golden-vector cross-check,
slop scan), the worker's npm build + test suite, and the docs-site gates.
Run the Go core in front of an upstream with
`mirage serve --upstream …`, or put the
[Cloudflare Worker]({{ site.baseurl }}/deploy/cloudflare-worker.html) at
the edge — same signals, same vectors, same verdicts.

## What you need

- **git** and **GNU make**.
- **Go 1.23 or newer** — the module pins `go 1.23.0` (see `go.mod`; the
  repo builds with the `go1.23.4` toolchain).
- **Python 3 with PyYAML** — only for the golden-vector gate
  (`tools/gen_vectors.py` imports `yaml`). `pip install pyyaml` if you lack
  it.
- **Node 20 or newer and npm** — only for the worker package
  (`packages/mirage-worker/package.json` requires `node >=20`).

## 1. Get the code

```sh
git clone https://github.com/namandhakad712/Mirage.git
cd Mirage
```

## 2. Verify everything (the same gates CI runs)

```sh
make check
```

That runs, in order: `fmt-check` (gofmt-clean tree), `vet` (`go vet ./...`),
`build` (`go build ./...`), `test` (`go test -race ./...`), `vectors`
(regenerate the golden vectors and cross-check the two independent sources
in `tools/gen_vectors.py`; the generator exits 1 on any disagreement), and
`slop` (the unfinished-work-marker grep gate). `make help` lists every
target. If `make check` is green, you have the same evidence the [CI
workflow](https://github.com/namandhakad712/Mirage/actions/workflows/ci.yml)
produces on main — that is the claim: deterministic gates, not trust.

The build emits `bin/mirage` (via `make build`, with the version and
commit stamped in), the Go core under `internal/`, and the edge
middleware — the full self-hosted surface plus the worker port.

## 3. Create your config and the dashboard token

```sh
./bin/mirage init --config mirage.yaml   # writes a minimal look-mode config
                                         # with a crypto/rand dashboard token
```

Or hand-write it from the annotated surface:

```sh
cp mirage.example.yaml mirage.yaml   # mirage.yaml is gitignored on purpose
openssl rand -hex 32                 # paste into dashboard_token
```

Open `mirage.yaml` and make two decisions:

- **`dashboard_token`** — replace the `CHANGE-ME` marker with the value you
  just generated. The dashboard requires a token **even on loopback** (an
  unauthenticated local endpoint is one `curl` away from a takeover). This
  is the one secret that lives in the config file; connector secrets live
  only in environment variables.
- **`mode`** — start at `look`. The three modes are documented inline in the
  example file: `look` observes and records only, `tripwires` additionally
  serves inert decoys to sessions already scored suspicious, `protect`
  additionally makes enforcement *possible* (it still needs
  `enforcement.enabled: true`, the kill switch off, and the budgets in
  range — I9).

Every key, default, bound and rule in that file mirrors
`internal/config/config.go` exactly; loading is strict (unknown keys and
half-configured connector blocks are boot-time errors), so a typo can never
silently disable a security control.

## 4. Run it (self-hosted)

```sh
./bin/mirage doctor  --config mirage.yaml   # 6 pre-flight checks, exits 1 on any failure
./bin/mirage posture --config mirage.yaml   # mode, budgets, routes, warnings
./bin/mirage serve   --config mirage.yaml --upstream http://127.0.0.1:9000
```

The proxy forwards everything to `--upstream`; with no origin of your
own yet, give it a demo one in a second terminal:

```sh
python3 -m http.server 9000
```

`serve` composes the whole stack — store, engine, catalog, queue,
gatekeeper, connectors — into the edge middleware: benign traffic proxies
through to the upstream, scanner paths are answered with persona decoys
(from `tripwires` mode up), and the token-guarded dashboard listens on
loopback at `--dashboard-addr` (default `127.0.0.1:8090`; non-loopback
binds are refused). A realistic first session:

```sh
curl http://127.0.0.1:8080/            # 200 — the proxy answers with your origin's page
curl http://127.0.0.1:8080/.env        # 404 — whatever your origin answers, mirrored unscored
TOKEN=$(grep dashboard_token mirage.yaml | sed 's/.*: *"\{0,1\}//; s/"\{0,1\} *$//')
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8090/api/events
```

Note that requests from loopback are never scored (I6, I15) — exercise
the decision path from a real address. `mirage replay` re-runs the golden
vectors through the full composed service any time you want proof the
arithmetic still holds.

The reverse-proxy topology in front of `serve` — TLS termination,
`X-Forwarded-For`, `trusted_proxies`, the deny map — is documented in
[nginx.md]({{ site.baseurl }}/deploy/nginx.html).

## 5. Run it at the edge (Cloudflare)

If your site is behind Cloudflare, the worker carries the same detection
engine, the same decoy catalog snapshot and the same golden-vector parity,
in-process, with no runtime dependencies:

```sh
cd packages/mirage-worker
npm ci
npm run build        # refreshes the generated data snapshot, type-checks, emits dist/
npx wrangler deploy  # with your wrangler.toml in place — see the full guide
```

The full walkthrough (wrangler.toml, routes, the reserved
`MIRAGE_TOKENS` binding, how the shared catalog data is regenerated,
fail-open semantics) is in [cloudflare-worker.md]({{ site.baseurl }}/deploy/cloudflare-worker.html).

Both shapes implement one spec and produce identical verdicts on the
shared golden vectors — deploy the worker at the edge, the self-hosted
core at the origin, or both.

## 6. Upgrading modes later

Mode upgrades are a one-line config change; downgrades are deleting that
line. From `look`, move to `tripwires` when you want scouts to be answered
with inert decoys (never to verified bots or ordinary visitors — I12). Move
to `protect` only after reviewing the enforcement limits in
[known-limits.md]({{ site.baseurl }}/known-limits.html): bans are single-address, short and
budget-capped (I5, I15), Tor and VPN exits are tagged rather than banned,
and when a budget is exceeded Mirage drops to observe rather than
over-ban. `enforcement.kill_switch: true` stops all enforcement instantly
from anywhere on the ladder.

## Where to go next

- [nginx.md]({{ site.baseurl }}/deploy/nginx.html) — transparent-proxy integration, the deny map.
- [cloudflare-worker.md]({{ site.baseurl }}/deploy/cloudflare-worker.html) — the edge deployment.
- [reference/cli.md]({{ site.baseurl }}/reference/cli.html) — every subcommand, flag and exit code.
- [vendor-notes.md]({{ site.baseurl }}/vendor-notes.html) — CrowdSec, Cloudflare and the webhook
  receiver contract.
- [SECURITY.md](https://github.com/namandhakad712/Mirage/blob/main/SECURITY.md) — how to report a vulnerability and what
  `mrg_` honeytokens are.
