---
layout: doc
title: "About"
description: "What Mirage is, what runs today, and where the repository's honest status line stands — the README, unedited."
category: project
order: 1
source: README.md
---
[![ci](https://github.com/namandhakad712/Mirage/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/namandhakad712/Mirage/actions/workflows/ci.yml)

Open-source tripwires and decoys that show you who is scanning your website and
waste their time — set up in ten minutes, no security background needed.

Mirage detects automated reconnaissance (scanner noise, AI attack agents,
opportunistic crawlers) and answers it with inert decoys. It never breaks the
site it protects, and it never pollutes the public web.

**Start here: [docs/deploy/quickstart.md]({{ site.baseurl }}/deploy/quickstart.html)** — from
zero to a verified build, a config with a generated dashboard token, a
running `mirage serve` proxy, or the Cloudflare Worker at the edge.
**Hosted docs:** https://namandhakad712.github.io/Mirage/ — the whole
guide, the specs, and a machine-readable surface (`/llms.txt`,
`/docs.json`) for AI agents.

## What it is

- **Watch** — see who knocks: decoy hits, scanner paths, tool signatures.
- **Tripwires** — decoy paths (`/.env`, `/.git/config`, fake panels, fake
  source maps) served to suspicious sessions only. Real traffic untouched.
- **Edge scoring** — per-request deterministic scoring inside your own edge
  (Go middleware, or a Cloudflare Worker).
- **Enforce** — short, reversible, budget-capped bans through connectors
  (CrowdSec, Cloudflare, deny-maps), off by default.

Each rung is useful alone and fully reversible. Moving up a rung is a config
change; moving down is deleting one line.

## What it is not

- It does **not** stop an attacker who goes straight for a real vulnerability.
  Decoys catch scouting, not exploits. See [Known limits]({{ site.baseurl }}/known-limits.html).
- No hack-back, ever. Passive deception only.
- No web pollution: decoys are never indexable, never served to verified
  search engines, never contain misinformation or live credentials. See the
  [Charter]({{ site.baseurl }}/charter.html).
- Not a hosted service. Self-hosted, no phone-home, telemetry off by default.

## Architecture

Two implementations, one spec: the Go core and the TypeScript worker must
produce identical verdicts on the shared golden vectors. CI fails on any
divergence.

| Package | One line |
| --- | --- |
| `internal/model` | Shared decision types, session key `sha256(ip)[:32]`, the right-to-left trusted-proxy client-IP walk (I6), never-scored/never-banned ranges, reason-text sanitizer (I7). |
| `internal/config` | Strict YAML site config: fail-closed unknown-key rejection, every policy bound, the loopback dashboard-token requirement (I9, I11). |
| `internal/store` | SQLite (WAL) and in-memory stores behind one interface; versioned schema with safe migration. |
| `internal/events` | Bounded drop-oldest event queue; emission never blocks the hot path (I3). |
| `internal/detect` | The SIGNALS v1.1.0 decision engine: deterministic scoring, verdict ladder, gating rules; the golden-vector parity target. |
| `internal/decoy` | The decoy data layer: strict catalog loader, reserved-value validation, deterministic renderer, pollution suite (I8, I12–I14). |
| `internal/enforce` | The verdict gatekeeper: per-verdict budgets and the global kill switch (I5, I9). |
| `internal/connectors` | Denyfile, webhook, CrowdSec LAPI and Cloudflare adapters behind one retry envelope (backoff + jitter, 429 Retry-After honored). |
| `packages/mirage-worker` | The Cloudflare Worker: TypeScript port of the engine, zero runtime dependencies, in-process and fail-open (Apache-2.0). |

Decisions are made on an in-memory snapshot under a hard deadline — no
network call, disk wait or LLM call in the request path (I3) — and any
internal failure sends the request to the origin unmodified (I1).

## The connectors

Enforcement is opt-in (I9) and delivered by four connectors, each fail-open
by design and fully documented in
[vendor notes]({{ site.baseurl }}/vendor-notes.html) with the exact API surfaces they call:

| Connector | What it does | Config keys |
| --- | --- | --- |
| `denyfile` | Maintains an nginx/Apache-compatible deny map with atomic rewrites. | `connectors.denyfile.path` |
| `webhook` | POSTs ban/unban notices signed with `X-Mirage-Signature` (hex HMAC-SHA256). | `connectors.webhook.url`, `connectors.webhook.secret_env` |
| `crowdsec` | Pushes bans to a local CrowdSec LAPI (alerts + decisions, origin `mirage`). | `connectors.crowdsec.lapi_url`, `connectors.crowdsec.api_key_env` |
| `cloudflare` | Pushes bans as zone IP access rules, `mirage: `-prefixed for ownership. | `connectors.cloudflare.account_id`, `.zone_id`, `.api_token_env` |

No connector credential lives in the config file — only the names of the
environment variables that hold them (I11). The complete annotated surface,
including the mode table and the token rules, is
[mirage.example.yaml](https://github.com/namandhakad712/Mirage/blob/main/mirage.example.yaml).

## The Cloudflare Worker

[`packages/mirage-worker`](https://github.com/namandhakad712/Mirage/tree/main/packages/mirage-worker) is the deployable piece
today: the same detection engine, decoy catalog and golden-vector parity as
the Go core, bundled into a zero-runtime-dependency worker that fails open
by construction. Deploy it with
[docs/deploy/cloudflare-worker.md]({{ site.baseurl }}/deploy/cloudflare-worker.html);
self-hosted users will proxy through the core instead — see
[docs/deploy/nginx.md]({{ site.baseurl }}/deploy/nginx.html) for the transparent-proxy
topology.

## The constitution

Every line of Mirage is checked against fifteen invariants:
[docs/invariants.md]({{ site.baseurl }}/invariants.html). The first three:

1. **Fail-open.** Any internal failure sends traffic to the origin unmodified.
2. **Never in the asset path.** Your pages never depend on Mirage to load.
3. **Hot path is local.** No network call, disk wait or LLM call while
   handling a request.

Plus: protected routes are never decoyed, bans are earned and reversible,
client IPs come only from trusted proxies, attacker data is treated as
hostile input, decoys are inert, enforcement is opt-in with a kill switch,
every action is explainable, and no internet pollution (I12–I15).

## Repository layout

```
Makefile             build and quality gates (make check runs every CI gate)
mirage.example.yaml  the complete annotated config surface
docs/                the hosted documentation site (guide, reference,
                     specs, deploy guides) and the project constitution
spec/                normative specs: signals, adapter protocol, decoy catalog,
                     golden vectors shared by all implementations
data/                shared data files (scanner paths, UA patterns, token formats,
                     reserved hosts, reason texts) used by Go and TypeScript alike
internal/            Go core: model, config, store, events, detect, decoy,
                     edge (HTTP middleware), enforce, connectors
cmd/mirage/          the mirage CLI: init, doctor, posture, replay, serve,
                     version
packages/            mirage-worker — TypeScript Cloudflare Worker (Apache-2.0)
lab/                 fault-injection and adversarial test lab
tools/               vector generator, docs-site sync + integrity gates
```

Two implementations, one spec: the Go core and the TypeScript worker must
produce identical verdicts on the shared golden vectors. CI fails on any
divergence.

## Status

All components shipped and gated; no releases yet (the changelog tracks
only `[Unreleased]`). What exists now:

- The constitution: fifteen invariants, charter, claims policy, known
  limits, ADRs.
- The normative specs (SIGNALS v1.1.0, adapter protocol v1, decoy catalog
  v1), the shared data files, and the golden vectors — 20 cases / 68
  requests, hand-computed and machine cross-checked — plus the
  cross-engine render fixture.
- The Go core: model, config, store, events, enforce and connectors,
  race-tested.
- The decision engine (SIGNALS v1.1.0 in code) and the decoy data layer.
- The Go edge middleware and the `mirage` CLI — `serve` (transparent
  proxy + loopback dashboard), `doctor`, `init`, `posture`, `replay`,
  `version`, with `--json` machine output on the reporting commands.
- The fault-injection lab proving the invariants hold under store, queue,
  connector, budget, deadline and kill-switch faults.
- The Cloudflare Worker — deployable today, response-identical to the Go
  edge on the shared vectors.
- The build layer: Makefile gates, CI (Go + worker + docs), the full
  example config, and the hosted documentation site with its sync and
  integrity tooling.

Version 1.0 is defined by exit criteria, not a date — see
[docs/design/MIRAGE-DESIGN.md]({{ site.baseurl }}/design/MIRAGE-DESIGN.html)
section 12. Watch [CHANGELOG.md](https://github.com/namandhakad712/Mirage/blob/main/CHANGELOG.md) for progress.

## License

- Core (Go): **AGPL-3.0** — see [LICENSE](https://github.com/namandhakad712/Mirage/blob/main/LICENSE).
- Adapters, SDKs and the Cloudflare Worker: **Apache-2.0** — see
  [packages/mirage-worker/LICENSE](https://github.com/namandhakad712/Mirage/blob/main/packages/mirage-worker/LICENSE).

## Security

Found something? Report it privately via GitHub's vulnerability reporting
on this repository — see [SECURITY.md](https://github.com/namandhakad712/Mirage/blob/main/SECURITY.md) for scope, the `mrg_`
honeytoken namespace and what is security-sensitive here. Supported: `main`
only.

## Contributing

Read [docs/charter.md]({{ site.baseurl }}/charter.html) first: contributions that add
hack-back, web poisoning or overclaiming will be declined. Decoy packs (YAML,
no code) and platform recipes are the lowest-barrier ways to help. The dev
setup, the spec-first rule and the quality gates are in
[CONTRIBUTING.md](https://github.com/namandhakad712/Mirage/blob/main/CONTRIBUTING.md).
