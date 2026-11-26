---
layout: doc
title: "Verdicts"
description: "The Mirage verdict ladder with exact thresholds, the request-vs-cumulative score arithmetic, the protected-route cap and worked numeric examples."
category: guide
order: 5
---

Every request gets exactly one verdict. The rungs, lowest to highest:

`observe` < `tag` < `decoy_route` < `throttle` < `ban`

The verdict is the highest rung whose condition holds — computed from the
request's own score and class, never from gut feeling, and never from
anything a model guessed.

## The score arithmetic

- `request_score` = sum of the weights of the signals that fired this
  request.
- `request_class` = the highest class among them (`high` if any high-class
  signal fired).
- `cum_before` = the session's cumulative score *before* this request.
- The event records `score` = cumulative *after* this request
  (`cum_before + request_score`).

| Rung | Condition | Action |
| --- | --- | --- |
| `observe` | No rung below holds | `pass` |
| `tag` | `request_score ≥ 15` OR `cum_before ≥ 25` | `pass` |
| `decoy_route` | `request_score ≥ 25` AND class `high` AND the path is decoyable (matches a decoy entry; not protected) | `serve_decoy` |
| `throttle` | `request_score ≥ 40` | adapter-local throttle |
| `ban` | `honeytoken_use` fired, OR (`decoy_lead_follow` fired AND path not protected), OR (`request_score ≥ 60` AND class `high`) | short block, only when enforcement is enabled (I9) |

## What history can and cannot do

Session history can tag; it can never escalate past tag. A clean-looking
request in a dirty session with `cum_before ≥ 25` gets `tag` — recorded,
passed, nothing more. `decoy_route`, `throttle` and `ban` are decided by the
request's own score and class alone. A session cannot be throttled or banned
by accumulation (vector v16: after cumulative 50, a spotless request tags
and passes).

## The protected-route cap (I4)

On a protected route the verdict is capped at `tag` — login, checkout and
API prefixes are never decoyed or throttled by decoy logic. One exception:
`honeytoken_use` survives the cap and produces `ban`. A leaked fake
credential in use is near-certain evidence regardless of route (vector v05:
`POST /api/v1/auth` with the minted bearer token → ban on a protected
path).

## Ban parameters and renewal

A ban covers a single address for 30 minutes (1,800,000 ms), with reason
code = the highest-weight signal of the banning request; a weight tie
resolves to the earliest signal in evaluation order. Bans are always
reversible (I5). While a ban is active (protect mode, enforcement armed),
any request from the address *renews* it: the decision cites the ORIGINAL
reason code and the remaining TTL, with request score 0 and no signals — a
banned address must not earn its way out with clean-looking requests.
Flipping the kill switch disarms renewal within one decision (I9).

## Worked examples

**W1 — scanner path, plain browser.** `GET /.env`, browser UA, 8 headers.
Fires `scanner_path` 25 (high); `decoy_hit` is suppressed. Tag rung holds
(25 ≥ 15); decoy_route holds (25 ≥ 25, high, decoyable); throttle does not
(25 < 40). Verdict: `decoy_route`, recorded score 25 (vector v02).

**Scanner path plus curl — check the gate before you add.** `GET /.env`
with UA `curl/8.5.0` and a full header set. The naive sum is
`scanner_path` 25 + `tooling_curl` 15 = 40, but `tooling_curl` is gated: it
fires only when a signal from the ungating set (signals 1–5) fired earlier
in the same request. `scanner_path` is signal 1 and did fire, so the gate
opens and both count: 25 + 15 = 40, class high. Rungs: tag (40 ≥ 15),
decoy_route would hold on `/.env` (40 ≥ 25, high, decoyable) but throttle
outranks it (40 ≥ 40), ban does not (40 < 60, no near-certain signal).
Verdict: `throttle`. Contrast vector v10 request 1: `GET /products` with
`curl/` and 3 headers fires only `headers_sparse` 10 — `headers_sparse`
does not ungate `tooling_curl` — so the request scores 10 and stays
`observe`. The gate, not the weight table, decides what fires.

**W3 — scanner path plus attack-tool UA.** `GET /.env`, UA `sqlmap/1.8`:
`scanner_path` 25 + `ua_suspicious` 15 = 40 → `throttle` (vector v09,
request 2; cumulative 55 recorded).

**W2 — protected route.** `GET /wp-login.php`, UA `sqlmap/1.8`:
`ua_suspicious` 15 → `tag`; the protected path caps at `tag` anyway.

**Structure-only ceiling.** Seven scripted requests (empty UA, 2 headers,
distinct unknown paths) each score 20 → tag; the eighth distinct unknown
path adds `path_enumeration` 25 → request 45 → `throttle`, never `ban`: no
near-certain signal fired and 45 < 60 (vector v06, W5 — I5 in action). A
ban from a combination requires 60 with high class: vector v17 reaches 70
(`scanner_path` 25 + `path_enumeration` 25 + `headers_sparse` 10 +
`ua_missing` 10) → `ban`.

The signals themselves are specified in
[signals]({{ site.baseurl }}/guide/signals.html); what each mode does with
a verdict is the [modes]({{ site.baseurl }}/guide/modes.html) ladder.
