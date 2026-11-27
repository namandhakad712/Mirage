---
layout: doc
title: "FAQ"
description: "Twelve honest answers about Mirage: why no ML, WAF replacement, CGNAT handling, false positives, licensing, performance and limits."
category: guide
order: 11
---

These answers follow the
[claims policy]({{ site.baseurl }}/claims-policy.html): every claim links
to something reproducible, and the honest form of "stops attack agents" is
"detects scouting and wastes attacker effort". What Mirage cannot do is
written down first in [known limits]({{ site.baseurl }}/known-limits.html).

## Why is there no machine learning?

Because determinism is the product. A rule-based engine is explainable,
replayable and auditable: every verdict traces to signals, weights and a
reason code, and the same request always scores the same (I10, pinned by
the golden vectors). The cost is stated openly: rule-based means
rule-gapped — novel reconnaissance patterns need new rules.

## Is Mirage a WAF replacement?

No. Decoys catch scouting, not exploits: an attacker who goes straight for
a real vulnerability touches no decoy and is not slowed down. Mirage sits
beside a WAF and answers a different question — who is mapping the site —
and enforcement is opt-in, budget-capped and reversible (I5, I9).

## What about carrier-grade NAT and mobile networks?

Shared and CGNAT ranges (100.64.0.0/10) are never banned, along with
loopback, link-local, private ranges, owner IPs and CDN ranges (I15). Bans
are single-address by design; an attacker behind rotating infrastructure
comes back, which is the accepted price of never banning an innocent
shared address.

## What is the false-positive posture?

Weights are chosen so benign single-fire requests stay under the tag
threshold of 15: `headers_sparse` (10) alone observes, and the three
classic false positives are gated out — `tooling_curl` needs same-request
evidence, `ua_rotation` never fires on rotation alone, and
`no_cookie_persistence` only fires in an otherwise-spotless session.
Verified bots and owner ranges are never scored at all.

## What does the license split mean for me?

The Go core is AGPL-3.0; adapters, SDKs and the Cloudflare Worker are
Apache-2.0, so the edge pieces can be embedded anywhere permissive
licensing requires. Self-hosting Mirage does not require publishing
anything; if you distribute a modified core, AGPL's source obligations
apply — read `LICENSE` and `packages/mirage-worker/LICENSE`, not this FAQ,
before deciding.

## Is this Cloudflare-only?

No. The worker is one adapter; the Go core runs anywhere behind any
TLS-terminating proxy — the [nginx topology]({{ site.baseurl }}/deploy/nginx.html)
is the reference — and both implement one spec with identical verdicts.

## What is the performance envelope?

Decisions run against an in-memory snapshot under a hard 5 ms budget, with
no network call, disk wait or LLM call in the request path (I3). On any
internal failure or budget overrun the request passes to the origin
unscored (I1) — Mirage degrades before it delays.

## Where does my data live?

Locally. Events, sessions and ban records go to the store you configure
(default SQLite in WAL mode); connectors make outbound calls only, and
there is no phone-home — telemetry is off by default and stays off unless
you opt in.

## Can attackers detect Mirage?

Over time, any fixed decoy set can be fingerprinted and skipped — stated
in known limits (community decoy packs are planned after 1.0; none ship
today). Decoys
carry no public "this is a decoy" marker (ADR-0001): safety comes from
audience gating, noindex headers and a published security.txt contact for
legitimate researchers.

## What happens when the store dies?

Traffic continues and decisions stay exact (I1): the `store-down` fault
scenario proves the ladder answers identically with every store method
failing. Event persistence fails loudly in logs; `/healthz` stays 200;
nothing blocks.

## Why 30-minute bans?

Short, reversible, budget-capped bans are the invariant (I5, I15): a
default ban covers a single address for minutes to hours, never a range,
with a recorded reason and a one-click undo. The TTL is configurable
(`enforcement.ban_ttl_ms`), but the shape — earned, short, reversible — is
not negotiable.

## Can I just stay in look mode forever?

Yes. Every rung is useful alone; look mode is a complete product — the
dashboard, the event stream and the reason texts. Moving up is a config
change; moving down is deleting one line.
