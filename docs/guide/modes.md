---
layout: doc
title: "Modes"
description: "The three Mirage modes — look, tripwires, protect — as an operational ladder, with the kill switch, the enforcement opt-in and what each mode does."
category: guide
order: 7
---

Mirage is observe-by-default (I9): enforcement exists only when the owner
turns it on, twice. The three modes are a ladder — each rung is useful
alone, moving up is a one-line config change, and moving down is deleting
that line. The mode never changes what the engine measures; it changes what
Mirage does about it.

## The ladder

**`look`** (default). Observe and record only. Every verdict is capped at
`tag` — the rung is honest about what the adapter may do, so no decoy is
named and no TTL is proposed — and the action is always `pass`. Signals,
scores and reason codes survive the cap: the event keeps the evidence
(I10). No decoy is served, nothing is enforced.

**`tripwires`**. Everything `look` records, plus decoys: a `decoy_route`
verdict keeps its `serve_decoy` action — the decoys ARE the tripwires —
while `throttle` and `ban` verdicts stay recorded with their actions
passing. Real traffic is untouched, and decoys still never reach verified
bots or ordinary visitors (I12).

**`protect`**. Enforcement becomes possible — and only possible. It runs
only when `enforcement.enabled: true` (a separate opt-in; enabling it in
any other mode is a boot-time error), the kill switch is off, and the
budgets are not exhausted. Mode `protect` alone turns nothing on. Without
the opt-in block — or with the kill switch engaged — decisions disarm to
the tripwires action set: decoys still serve, throttle and ban actions
pass.

## What you see versus what Mirage does

| | look | tripwires | protect (not armed) | protect (armed) |
| --- | --- | --- | --- | --- |
| Verdicts recorded | yes, capped at `tag` | all | all | all |
| Decoys served | no | on `decoy_route` | on `decoy_route` | on `decoy_route` |
| Throttle executed | no | no | no | yes |
| Bans executed | no | no | no | yes, budget-capped |
| Connector calls | no | no | no | on ban and reconcile |
| Dashboard | full | full | full | full |

The verdict ladder itself is specified in
[verdicts]({{ site.baseurl }}/guide/verdicts.html) and never changes with
mode.

## The kill switch

`enforcement.kill_switch: true` stops everything at once: no ban or
throttle is executed, no connector is called, the system drops to observe.
It is re-checked on every decision, so flipping it takes effect
immediately — including on renewal: an existing ban stops answering on the
address's next request, rather than after a full TTL. Flip it when anything
looks wrong; investigate afterwards.

## Budgets

Protect mode is budget-capped (I5, I15). Defaults: at most 10 bans per
minute, at most 100 concurrent bans, at most 5% of sessions banned. When a
budget is exceeded, enforcement drops to observe rather than over-ban —
under-enforcing during a deliberate flood is the accepted trade; a bug that
bans the world is worse than an attacker who returns. Never-ban ranges
(owner IPs, loopback, RFC 1918, CGNAT 100.64.0.0/10, link-local) are never
banned whatever the engine says.

## The dashboard token

The dashboard requires a token even on loopback — an unauthenticated local
endpoint is one `curl` away from a full takeover. An empty
`dashboard_token` is a boot-time error, not advice. Generate with
`openssl rand -hex 32`.

## Choosing a rung

Start at `look` and read the dashboard until the event stream makes sense.
Move to `tripwires` when you want scouts answered with inert decoys. Move
to `protect` only after reading [known limits]({{ site.baseurl }}/known-limits.html)
and the [operations runbook]({{ site.baseurl }}/guide/operations.html) —
and with the kill switch within reach. The dashboard copy follows the same
rule as this documentation: it says "watching", not "protected", unless
protect is actually on.
