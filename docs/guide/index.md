---
layout: doc
title: "Guide"
description: "The Mirage guide: what it is, how to run it, and the order to read the ten pages that cover detection, decoys, modes and operations."
category: guide
order: 1
---

## What Mirage is

Mirage is an open-source deception layer for public HTTP and HTTPS services:
it detects automated reconnaissance — scanner noise, AI attack agents,
opportunistic crawlers — and answers it with inert decoys that waste the
scout's effort. It never breaks the site it protects: any internal failure
sends traffic to the origin unmodified (I1), and decoys never reach search
indexes, archives or ordinary visitors (I12). Enforcement — short,
reversible, budget-capped bans — is opt-in and off by default (I9).

Everything below is verifiable from the repository: the engine is pinned by
the [invariants]({{ site.baseurl }}/invariants.html) and by golden vectors
that every implementation must reproduce exactly.

## What the guide covers

Ten pages, written for an operator who has never run a honeypot and for an
engineer who wants to audit one. Each page is self-contained; together they
cover the whole system from first request to production runbook.

| Order | Page | What it answers |
| --- | --- | --- |
| 2 | [Getting started]({{ site.baseurl }}/guide/getting-started.html) | From a fresh clone to a running look-mode instance. |
| 3 | [Architecture]({{ site.baseurl }}/guide/architecture.html) | The decision path end-to-end, package by package. |
| 4 | [Signals]({{ site.baseurl }}/guide/signals.html) | The 11 signals, their weights, and the gating rules. |
| 5 | [Verdicts]({{ site.baseurl }}/guide/verdicts.html) | The verdict ladder with worked score arithmetic. |
| 6 | [Decoys]({{ site.baseurl }}/guide/decoys.html) | The catalog: personas, entries, leads, honeytokens. |
| 7 | [Modes]({{ site.baseurl }}/guide/modes.html) | look, tripwires, protect — the operational ladder. |
| 8 | [Tooling]({{ site.baseurl }}/guide/tooling.html) | Every quality gate, lab and generator in the repo. |
| 9 | [Operations]({{ site.baseurl }}/guide/operations.html) | The production runbook: stores, budgets, connectors. |
| 10 | [Testing]({{ site.baseurl }}/guide/testing.html) | The test architecture and how to add a golden vector. |
| 11 | [FAQ]({{ site.baseurl }}/guide/faq.html) | Twelve honest answers, including what Mirage cannot do. |

## Recommended reading order

1. **Operators deploying for the first time:** getting started, then modes,
   then signals. That is enough to run `look` mode and read the dashboard
   with an accurate mental model of what the scores mean.
2. **Engineers auditing or extending:** architecture, signals, verdicts,
   testing. These four pages map every claim to a package, a spec section
   and a test.
3. **Anyone considering enforcement:** modes, operations and the FAQ,
   together with [known limits]({{ site.baseurl }}/known-limits.html) —
   bans are single-address, short and budget-capped on purpose (I5, I15),
   and the honest answer to "does this stop attackers" is "it detects
   scouting and wastes attacker effort".

## Beyond this guide

- [Deploy guides]({{ site.baseurl }}/deploy/quickstart.html) — the
  from-zero path, the nginx transparent-proxy topology, and the Cloudflare
  Worker that runs at the edge.
- [Reference]({{ site.baseurl }}/reference/index.html) — every config key,
  every CLI subcommand, the shared data files and the normative specs.
- [Reading Mirage as an agent]({{ site.baseurl }}/agent/index.html) — the
  machine-readable surface (`/llms.txt`, `/docs.json`, `--json` outputs)
  for programs that consume this documentation.

What Mirage will never do — hack-back, web poisoning, live credentials,
indexable decoys — is recorded in the
[charter]({{ site.baseurl }}/charter.html), not decided case by case.
