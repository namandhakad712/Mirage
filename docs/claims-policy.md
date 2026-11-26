# Mirage Claims Policy

Security software earns trust by understating, not overclaiming. This policy
is enforced by review on every change to README, docs and the dashboard copy.

## The rule

**Every performance or detection claim in Mirage's documentation or UI must
link to a reproducible test** — a golden vector, a CI job, a benchmark script
in `tools/`, or a documented measurement with method and date. A claim
without a link is a bug.

## Words we do not use

- "military-grade", "next-generation", "AI-powered defense" (we are
  deterministic and rule-based on purpose)
- "unhackable", "impenetrable", "total protection"
- "stops AI attack agents" — the honest form is "detects scouting and wastes
  attacker effort"
- "zero false positives" — we say what our false-positive review queue does
  instead
- unverifiable percentages ("blocks 99.9% of threats")

## Canonical honest phrasings

| Tempting claim | Honest replacement |
| --- | --- |
| Stops ARTEX-class agents | Detects scouting behavior and wastes attacker effort; a patient attacker who goes straight to a real vulnerability is not stopped by decoys |
| Protects your site | Watches your site; enforcement is opt-in, budget-capped and reversible |
| Invisible to attackers | Raises attacker cost; any fixed decoy set can be fingerprinted over time, so packs rotate and vary per install |
| Never fails | Fails open by design: when Mirage fails, traffic passes to the origin unmodified |

## Evidence

- `spec/golden-vectors/` — hand-computed verdicts; every implementation must
  match them exactly.
- CI (`.github/workflows/ci.yml`) — build, vet, race tests, the vector suite,
  the pollution suite and the slop grep run on every push.
- `docs/known-limits.md` — the counter-claims, written first.

## Dashboard copy rules

The dashboard says "watching", not "protected", unless Protect is actually
on. Every event card explains itself in plain English and links its reason
code. Status is icon plus text, never color alone.

If a claim on the Evidence list fails to reproduce, the claim is removed
first and investigated second.
