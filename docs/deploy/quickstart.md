# Quickstart — from zero to Mirage

This page is the honest path from a fresh clone to a working Mirage
installation. Read the status note first: one part of Mirage is deployable
today, one part is still in development, and this page does not pretend
otherwise.

## Status: what runs today

**Shipped and tested:** the normative specs and golden vectors, the Go core
(config, model, store, events, enforce, connectors), the SIGNALS v1.1.0
detection engine, the decoy data layer, and the Cloudflare Worker. **In
development, landing with the server release:** the `mirage` server binary
(`cmd/mirage`) and the Go edge middleware. Until then there is no `mirage
serve` command to document — any command you see for a Mirage CLI anywhere
else is not this project. What you can run today on real traffic is the
[Cloudflare Worker](cloudflare-worker.md); the Go core is a library whose
every package is verified by `make check`.

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

The build emits no binaries yet: every Go package under `internal/` is a
library, compiled and race-tested, and the runnable surface today is the
worker.

## 3. Create your config and the dashboard token

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

## 4. Run it (Cloudflare users: today)

If your site is behind Cloudflare, Mirage is deployable now — the worker
carries the same detection engine, the same decoy catalog snapshot and the
same golden-vector parity, in-process, with no runtime dependencies:

```sh
cd packages/mirage-worker
npm ci
npm run build        # refreshes the generated data snapshot, type-checks, emits dist/
npx wrangler deploy  # with your wrangler.toml in place — see the full guide
```

The full walkthrough (wrangler.toml, routes, the reserved
`MIRAGE_TOKENS` binding, how the shared catalog data is regenerated,
fail-open semantics) is in [cloudflare-worker.md](cloudflare-worker.md).

## 5. Run it (self-hosted: when the server lands)

The `mirage` server binary — the process that reads `mirage.yaml`, serves
the dashboard on `listen`, scores requests and drives the connectors — is
in development and lands with the server release. Your `mirage.yaml` is
already the complete config surface it will read, so nothing you did above
is throwaway. When the binary ships, this section becomes the `serve`
instructions; watch [CHANGELOG.md](../../CHANGELOG.md) for the release.

What you can already do today around the future server:

- Prepare the reverse-proxy side: [nginx.md](nginx.md) documents the
  transparent-proxy topology (TLS termination, `X-Forwarded-For`,
  `trusted_proxies`) and the deny-map include.
- Prepare connectors: [vendor-notes.md](../vendor-notes.md) documents exactly
  what Mirage calls on CrowdSec, Cloudflare and webhook receivers, with
  the retry envelope and the `X-Mirage-Signature` verification recipe.
- Deploy the worker at the edge and add the self-hosted core later — the
  two implement one spec and produce identical verdicts on the shared
  golden vectors.

## 6. Upgrading modes later

Mode upgrades are a one-line config change; downgrades are deleting that
line. From `look`, move to `tripwires` when you want scouts to be answered
with inert decoys (never to verified bots or ordinary visitors — I12). Move
to `protect` only after reviewing the enforcement limits in
[known-limits.md](../known-limits.md): bans are single-address, short and
budget-capped (I5, I15), Tor and VPN exits are tagged rather than banned,
and when a budget is exceeded Mirage drops to observe rather than
over-ban. `enforcement.kill_switch: true` stops all enforcement instantly
from anywhere on the ladder.

## Where to go next

- [nginx.md](nginx.md) — transparent-proxy integration, the deny map.
- [cloudflare-worker.md](cloudflare-worker.md) — the edge deployment that
  runs today.
- [vendor-notes.md](../vendor-notes.md) — CrowdSec, Cloudflare and the webhook
  receiver contract.
- [SECURITY.md](../../SECURITY.md) — how to report a vulnerability and what
  `mrg_` honeytokens are.
