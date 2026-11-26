# Mirage Charter — scope, ethics, and what we will never ship

This charter is the contract between Mirage and its users. It is short on
purpose: everything here is enforceable, and everything enforceable is here.

## Scope

Mirage protects public HTTP and HTTPS services. It does not cover SSH,
databases or mail in version 1 (integration with existing SSH honeypots is
possible later). A site entirely behind a login or a private network gains
less — the scouts rarely reach it.

What Mirage does:

- Detects noisy reconnaissance and automated attack-agent scouting.
- Wastes attacker effort with inert, consistent decoys.
- Enforces short, reversible, budget-capped bans when the owner opts in.

What Mirage does not do — and will not do:

- **No hack-back.** No executing code on attacker machines, no counter-
  scanning, no retaliation of any kind. Passive deception only.
- **No web pollution.** Decoys never reach search indexes, archives,
  AI-training crawlers or ordinary visitors (I12). We do not feed garbage to
  content scrapers (I13) — we block, challenge or rate-limit them.
- **No live credentials.** Honeytokens use formats that cannot validate, or
  registered canaries owned by the site owner (I14). A decoy must never
  become someone else's security incident.
- **No overclaiming.** We say "detects scouting and wastes attacker effort".
  We never say "stops attack agents". Decoys do not stop an agent that goes
  straight to a real vulnerability. [Known limits](known-limits.md) is
  written first, not after the first critic.
- **No paywalls on safety features.** The posture check, Watch mode, decoys
  and the dashboard are free forever. Sponsorships and optional paid support
  may come later; safety does not.
- **No phone-home.** Telemetry is off by default and stays off unless the
  owner opts in.

## Decoy marking decision (recorded)

Decoys carry **no public "this is a decoy" marker** — a marker reveals the
trap. Instead we rely on audience gating (decoys are served only to sessions
already scored suspicious), noindex headers, robots.txt disallow, and a
published `security.txt` contact so legitimate researchers can ask to be
allowlisted. See ADR-0001.

## Against the alternatives — honestly

- Hosted router-tied shields: paywalled and closed. Mirage is free and
  self-hostable.
- Vendor "AI labyrinths" aimed at scrapers: they feed generated content to
  crawlers. Mirage targets attack agents and never pollutes the web.
- CrowdSec: shared IP reputation. Mirage integrates with it
  (connector), not competes.
- Proof-of-work bot blockers: complementary; different problem.

"Works with" beats "versus".

## Contribution rules

Contributions that add hack-back, data poisoning, live credential formats,
marketing overclaims, or indexable decoys will be declined by charter.
Lowest-barrier contributions: decoy packs (YAML, no code), platform recipes,
translations, adapters through the SDK.

## Governance

- `docs/invariants.md` — the constitution (I1–I15).
- `docs/adr/` — decision records; invariant changes need one.
- `docs/claims-policy.md` — every claim links to a reproducible test.
- `docs/known-limits.md` — what Mirage cannot do, written first.
- AGPL-3.0 for the core, Apache-2.0 for adapters and SDKs, so adapters can
  be embedded anywhere.
