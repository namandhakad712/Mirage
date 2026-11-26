---
layout: doc
title: "Known Limits"
description: "Where Mirage does not help — the honest boundary list."
category: project
order: 6
---
Before anyone else says "but it didn't stop X": here is what Mirage cannot
do. This page is a feature, not an apology. It ships with v0.1 and grows only
by adding measured honesty.

## Detection limits

- **Decoys do not stop a determined attacker.** A human or agent that goes
  straight to a real vulnerability — an exposed endpoint, a known CVE — will
  not touch a decoy and will not be slowed down. Decoys catch *scouting*.
- **Patient attackers defeat structure scoring.** Slow, spread-out, rotating
  reconnaissance can stay under every threshold. We tag what we see; we do
  not see everything.
- **Fingerprinting is possible over time.** Any fixed decoy set can be
  learned and skipped. Mitigations — per-install seeded variation, rotating
  packs, persona diversity — raise the cost, they do not remove it.
- **Rule-based means rule-gapped.** The engine is deterministic on purpose
  (explainable, replayable, auditable). It has no imagination. Novel
  reconnaissance patterns need new rules.
- **Timing and TLS-fingerprint signals are planned, not present in the
  initial engine.** v1.1.0 of the signal spec scores request-shape signals
  only. JA3/JA4 mismatch and machine-regular timing arrive later, and only
  where the adapter can see the data.

## Scope limits

- **HTTP and HTTPS only.** No SSH, database or mail protection in v1.
- **A site fully behind a login gains little** — scouts rarely reach it.
- **Closed builders (Shopify, Wix, Squarespace) cannot run Mirage.** Nothing
  can be installed there. These owners get the posture check of their public
  pages and Watch where custom DNS or scripts allow it. We do not pretend
  otherwise.
- **No TLS termination in v1.** Mirage Edge sits behind a TLS-terminating
  proxy (Caddy, nginx, Cloudflare). This keeps our attack surface small.

## Enforcement limits

- **Bans are single-address and short by default** (minutes to hours), never
  a range. Attackers behind rotating infrastructure come back; that is the
  price of never banning an innocent shared address (I15).
- **Tor and VPN exits are tagged, not banned** unless the owner chooses
  otherwise.
- **Ban budgets trade coverage for safety.** When a budget is exceeded the
  site drops to Observe automatically. This can under-enforce during a
  deliberate flood. A bug that bans the world is worse than an attacker who
  returns.

## Operational limits

- **The worker mode is bounded.** Serverless adapters keep state in a small
  store; long-horizon signals (session history across many minutes) are
  approximate there compared to the Go core.
- **Recipes rot.** Platform dashboards change; every recipe carries a
  verified-on date and is flagged for re-verification after 90 days.
- **Agent-written code is held to deterministic gates.** Nothing merges on
  model confidence alone; see the design doc, Part V.

## What we will not add, even if asked

Hack-back, live credential formats, web poisoning, misinformation decoys,
indexable decoys, permanent range bans. Declined by
[charter]({{ site.baseurl }}/charter.html).
