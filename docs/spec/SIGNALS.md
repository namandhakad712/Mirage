---
layout: doc
title: "Signal Specification"
description: "SIGNALS v1.1.0 — the eleven signals, fixed weights and classes, gating rules, evaluation order and the verdict ladder."
category: spec
order: 1
source: spec/SIGNALS.md
---
Normative. Every implementation (Go core, TypeScript worker) must produce
identical results on `spec/golden-vectors/vectors.json`. CI fails on any
divergence. Changes to this file bump `spec_version` and regenerate vectors.

`spec_version: "1.1.0"`

## 1. Scope and inputs

The engine scores one HTTP request at a time, deterministically, against an
in-memory session snapshot. It never calls the network, disk or an LLM (I3).
Inputs per request:

| Field | Type | Notes |
| --- | --- | --- |
| `method` | string | GET/HEAD/POST/... |
| `path` | string | Raw path including dot segments and query string |
| `client_ip` | string | Socket address or trusted-proxy result (see §2) |
| `user_agent` | string | Header value, may be empty or absent |
| `header_count` | int | Count of ALL request headers, including Host and User-Agent |
| `has_cookie` | bool | A Cookie header is present and non-empty |
| `ts_ms` | int64 | Request time, milliseconds since epoch |
| `auth_hint` | string | Optional: credential material visible to the adapter (query, Authorization header, body keys), matched against known honeytokens |

Adapters that cannot see a field pass the neutral value and the engine
degrades gracefully: signals requiring the field do not fire.

## 2. Client identity

- **Session key** = first 32 hex characters of `sha256(client_ip)`.
  Example: `sha256("203.0.113.7")[:32] = fec52565aa0cf18f57d7cf5b3ac72850`.
- **Client IP** comes from the socket address, or from `X-Forwarded-For` /
  related headers **only** when the immediate peer is a trusted proxy listed
  in config. The chain is walked right-to-left, skipping trusted proxies; the
  first non-trusted address is the client. Untrusted peers' forwarding
  headers are ignored entirely — an attacker must not be able to frame an
  innocent address (I6).
- **Never-scored addresses** (verified in `data/reserved-hosts.txt` and
  config): owner IPs, loopback, CDN and load-balancer ranges, allowlisted
  bots — no dashboard-token exception exists (the token authenticates
  dashboard endpoints, it does not switch scoring back on). Requests from
  them produce verdict `observe` and no session state is recorded.
- **Verified bot hints**: a case-insensitive user-agent substring match
  against `data/ua-verified-bots.txt` marks the request never-scored. The Go
  core additionally supports reverse-DNS plus forward confirmation for
  `Googlebot` when the owner enables it; the hint list is the hot-path gate.

## 3. Path handling

1. Strip the query string (everything from the first `?`).
2. Normalize dot segments: resolve `.` and `..` left to right, popping the
   previous segment. `..` at the root pops nothing — the path is clamped at
   `/` **and** the request is marked `dot_escape` (it signals scanner-style
   path fuzzing).
3. Matching against scanner, decoy and protected lists is exact on the
   normalized path. Catalog loader normalization: a scanner-list entry with a
   trailing slash also matches the entry without it (`/phpmyadmin-old/`
   matches `/phpmyadmin-old`).

## 4. Signals

Weight, class and reason code are fixed. `high` classes can escalate;
`medium` classes alone can never ban (I5).

| # | id | weight | class | reason | fires when |
| --- | --- | --- | --- | --- | --- |
| 1 | `scanner_path` | 25 | high | SIG-101 | Normalized path matches `data/scanner-paths.txt` or `dot_escape` fired |
| 2 | `decoy_hit` | 30 | high | SIG-102 | Normalized path matches a decoy catalog entry. **Suppressed** when `scanner_path` fired the same request (a scanner-list hit is already fully explained) |
| 3 | `decoy_lead_follow` | 40 | high | SIG-103 | Normalized path matches a lead path that exists only inside a decoy response served earlier to this session |
| 4 | `honeytoken_use` | 50 | high | SIG-104 | Any credential material visible in the request matches a honeytoken minted for a decoy served to this session |
| 5 | `path_enumeration` | 25 | high | SIG-105 | ≥ 8 **distinct unknown paths** in the trailing 60 s window. Unknown = not `/`, not a protected route, not a scanner path, not a decoy, not a decoy lead |
| 6 | `ua_suspicious` | 15 | medium | SIG-106 | User-Agent matches `data/ua-suspicious.txt` (case-insensitive substring) |
| 7 | `ua_rotation` | 20 | medium | SIG-107 | ≥ 4 distinct non-empty user agents from the session in the trailing 300 s **AND** at least one other signal fired this request (gated, §6) |
| 8 | `no_cookie_persistence` | 15 | medium | SIG-108 | Request count ≥ 5 for the session, no Cookie header **ever** in the session, session cumulative score was 0 before this request, and **no signal earlier in evaluation order fired** (gated, §6) |
| 9 | `headers_sparse` | 10 | medium | SIG-109 | `header_count < 4`. Fires on every sparse request |
| 10 | `ua_missing` | 10 | medium | SIG-110 | User-Agent header absent or empty string |
| 11 | `tooling_curl` | 15 | medium | SIG-111 | User-Agent matches `curl/` **AND** at least one of `scanner_path`, `decoy_hit`, `decoy_lead_follow`, `honeytoken_use`, `path_enumeration` fired this request earlier in evaluation order (gated, §6) |

Evaluation order is the table order 1→11. A signal later in the order may
read, but never change, the outcome of an earlier one.

## 5. Verdict ladder

Rungs, lowest to highest: `observe` < `tag` < `decoy_route` < `throttle` < `ban`.

Let `request_score` = sum of weights of signals that fired this request.
Let `request_class` = the highest class among them.
Let `cum_before` = session cumulative score before this request.
Let `path_protected` = normalized path is a protected route (I4).

1. **tag**: `request_score ≥ 15` OR `cum_before ≥ 25`.
2. **decoy_route**: `request_score ≥ 25` AND `request_class = high` AND the
   path is decoyable (matches a decoy entry; not protected).
3. **throttle**: `request_score ≥ 40`.
4. **ban**: `honeytoken_use` fired, OR (`decoy_lead_follow` fired AND path is
   not protected), OR (`request_score ≥ 60` AND `request_class = high`).

The verdict is the highest rung whose condition holds.

**Protected-route cap (I4):** on a protected path the verdict is capped at
`tag`, with one exception — `honeytoken_use` survives the cap and produces
`ban` (R3 exception: a leaked fake credential in use is near-certain
evidence regardless of route).

**Ban parameters:** single address, TTL 30 minutes, reason code = the
highest-weight signal of the request. Always reversible (I5).

## 6. Gating rules (normative)

These prevent the classic false positives. Each is exercised by vectors.

1. **curl gating.** `tooling_curl` fires only when a same-request signal
   fired *earlier in evaluation order* (signals 1–5). `headers_sparse` does
   NOT ungate it. Prior session score does NOT ungate it. Rationale: `curl/`
   appears in legitimate API checks and health probes.
2. **ua_rotation gating.** Requires ≥ 4 distinct user agents in the trailing
   300 s AND another same-request signal. A session that merely rotates UAs
   (some privacy tools do) is never scored on rotation alone.
3. **no_cookie_persistence gating.** Fires only in an otherwise-clean
   session (request count ≥ 5, never a cookie, cumulative score 0 before,
   no signal earlier in evaluation order this request; signals later in
   the order — `headers_sparse`, `ua_missing`, `tooling_curl` — may
   co-fire). Never stacks with scanner or decoy evidence — those already
   explain the session.

## 7. Session state and expiry

State per session key: `first_ts`, `last_ts`, `request_count`,
`cumulative_score`, `cookie_ever` (bool), `ua_seen` (list of (ua, ts)),
`unknown_paths` (list of (path, ts)), `decoys_served` (list of decoy ids),
`leads_known` (lead paths from served decoys), `tokens_minted` (honeytoken
strings from served decoys).

**Expiry:** if `ts - last_ts > 30 × 60 × 1000` ms (30 minutes), the state
resets before scoring — a new session epoch begins, cumulative score 0.
Windows (`ua_seen`, `unknown_paths`) keep only entries inside their trailing
window (300 s / 60 s) after every request.

**Recorded score:** the event records `score` = cumulative score AFTER this
request (`cum_before + request_score`). The verdict rung uses only the
request's own score and class (§5). History alone never escalates: a
clean-looking request in a dirty session can tag (via `cum_before ≥ 25`)
but never throttles or bans on history alone.

## 8. Output

```json
{
  "session_key": "fec52565aa0cf18f57d7cf5b3ac72850",
  "spec_version": "1.1.0",
  "signals": [{"id": "scanner_path", "weight": 25, "class": "high", "reason": "SIG-101"}],
  "request_score": 25,
  "score": 25,
  "verdict": "decoy_route",
  "reason_code": "SIG-101",
  "ban_ttl_ms": null
}
```

`reason_code` = the highest-weight signal of the request; `ban_ttl_ms` is
set only on `ban` verdicts (1800000).

Plain-English renderings for every reason code live in
`data/reason-texts.txt` and must be used by every dashboard and report
(I10). All attacker-controlled strings are untrusted input at render time
(I7).

## 9. Reserved test values

Vectors use only reserved values (I14): client IPs from 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24 (RFC 5737); hostnames from example.com /
.test / .invalid (RFC 2606). No real brands in decoy content beyond
technology-stack markers permitted by the decoy catalog spec.

## 10. Worked examples

These are normative and mirrored in the golden vectors.

**W1 — scanner path, plain browser UA.** `GET /.env`, UA
`Mozilla/5.0 (X11; Linux x86_64)`, 8 headers, cookie present. Fires
`scanner_path` 25 (high). `decoy_hit` suppressed (§4.2). Verdict:
`decoy_route` (25 ≥ 25, high, decoyable). Recorded score 25.

**W2 — protected route, tool UA.** `GET /wp-login.php`, UA `sqlmap/1.8`.
Fires `ua_suspicious` 15. Request score 15 → tag; protected path caps at
`tag` anyway. Recorded score 15.

**W3 — scanner path plus tool UA.** `GET /.env`, UA `sqlmap/1.8`. Fires
`scanner_path` 25 + `ua_suspicious` 15 = 40 → `throttle` (40 ≥ 40).

**W4 — honeytoken on a protected route.** `POST /api/v1/auth` with
`Authorization: Bearer mrg_live_<seed>` where the token was minted in the
`/.env` decoy served earlier to this session. Fires `honeytoken_use` 50 →
`ban`, surviving the protected-route cap (§5).

**W5 — structure-only session.** Seven scripted requests (empty UA, 2
headers, distinct unknown paths, no cookie): each fires `headers_sparse` 10
+ `ua_missing` 10 → tag (20 ≥ 15). The eighth distinct unknown path within
60 s fires `path_enumeration` 25 too → request score 45 → `throttle`. Never
`ban`: no high-class near-certain signal (I5).
