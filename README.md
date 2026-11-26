# Mirage

Open-source tripwires and decoys that show you who is scanning your website and
waste their time — set up in ten minutes, no security background needed.

Mirage detects automated reconnaissance (scanner noise, AI attack agents,
opportunistic crawlers) and answers it with inert decoys. It never breaks the
site it protects, and it never pollutes the public web.

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
  Decoys catch scouting, not exploits. See [Known limits](docs/known-limits.md).
- No hack-back, ever. Passive deception only.
- No web pollution: decoys are never indexable, never served to verified
  search engines, never contain misinformation or live credentials. See the
  [Charter](docs/charter.md).
- Not a hosted service. Self-hosted, no phone-home, telemetry off by default.

## The constitution

Every line of Mirage is checked against fifteen invariants:
[docs/invariants.md](docs/invariants.md). The first three:

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
docs/            invariants, charter, claims policy, known limits, design
spec/            normative specs: signals, adapter protocol, decoy catalog,
                 golden vectors shared by all implementations
data/            shared data files (scanner paths, UA patterns, token formats,
                 reserved hosts, reason texts) used by Go and TypeScript alike
internal/        Go core (detection, deception, enforcement, store, service)
cmd/mirage/      CLI: init, doctor, serve, replay, posture
packages/        mirage-worker — TypeScript Cloudflare Worker (Apache-2.0)
lab/             fault-injection and adversarial test lab
tools/           vector generator and other deterministic tooling
```

Two implementations, one spec: the Go core and the TypeScript worker must
produce identical verdicts on the shared golden vectors. CI fails on any
divergence.

## License

- Core (Go): **AGPL-3.0** — see [LICENSE](LICENSE).
- Adapters, SDKs and the Cloudflare Worker: **Apache-2.0** — see
  [packages/mirage-worker/LICENSE](packages/mirage-worker/LICENSE).

## Status

Foundation stage. The constitution, specs and shared data are in; code lands
in staged, gated rounds. Watch [CHANGELOG.md](CHANGELOG.md) for progress.
Version 1.0 is defined by exit criteria, not a date — see
[docs/design/MIRAGE-DESIGN.md](docs/design/MIRAGE-DESIGN.md) section 12.

## Contributing

Read [docs/charter.md](docs/charter.md) first: contributions that add
hack-back, web poisoning or overclaiming will be declined. Decoy packs (YAML,
no code) and platform recipes are the lowest-barrier ways to help.
