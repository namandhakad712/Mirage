---
layout: doc
title: "Signals"
description: "The 11 detection signals of SIGNALS v1.1.0: what each one sees, its fixed weight and class, a concrete example, and its gating rules."
category: guide
order: 4
---

A signal is one deterministic observation about a single HTTP request, made
against an in-memory session snapshot — no network call, disk wait or LLM
call is involved (I3). Weights, classes and reason codes are fixed by
`spec/SIGNALS.md` v1.1.0; evaluation order is the table order 1→11, and a
signal later in the order may read, but never change, the outcome of an
earlier one. High-class signals can escalate; medium-class signals alone can
never ban (I5).

## The full table

| # | id | Weight | Class | Reason | Fires when |
| --- | --- | --- | --- | --- | --- |
| 1 | `scanner_path` | 25 | high | SIG-101 | Normalized path matches `data/scanner-paths.txt`, or `dot_escape` fired |
| 2 | `decoy_hit` | 30 | high | SIG-102 | Path matches a decoy catalog entry |
| 3 | `decoy_lead_follow` | 40 | high | SIG-103 | Path matches a lead that exists only inside a decoy served earlier to this session |
| 4 | `honeytoken_use` | 50 | high | SIG-104 | Credential material in the request matches a honeytoken minted for a decoy served to this session |
| 5 | `path_enumeration` | 25 | high | SIG-105 | ≥ 8 distinct unknown paths in the trailing 60 s |
| 6 | `ua_suspicious` | 15 | medium | SIG-106 | User-Agent matches `data/ua-suspicious.txt` (case-insensitive substring) |
| 7 | `ua_rotation` | 20 | medium | SIG-107 | ≥ 4 distinct non-empty user agents in the trailing 300 s, AND gated (below) |
| 8 | `no_cookie_persistence` | 15 | medium | SIG-108 | ≥ 5 requests, never a cookie, cumulative score 0 before, no other signal this request |
| 9 | `headers_sparse` | 10 | medium | SIG-109 | `header_count < 4` (all headers, including Host and User-Agent) |
| 10 | `ua_missing` | 10 | medium | SIG-110 | User-Agent absent or empty |
| 11 | `tooling_curl` | 15 | medium | SIG-111 | UA matches `curl/`, AND gated (below) |

## Reading the signals

**High class — path evidence.** `scanner_path` (25) is the workhorse: `GET
/.env` with any user agent fires it, as does a dot-segment escape such as
`/a/../../..` that clamps at the root. `decoy_hit` (30) fires when the path
matches a catalog entry such as `/admin/login`; it is **suppressed when
`scanner_path` fired the same request** — a scanner-list hit already fully
explains the request. `decoy_lead_follow` (40) means the session asked for a
path like `/storage/logs/laravel-staging.log` that only ever appeared inside
a decoy it was served — near-certain evidence of a scout reading the bait.
`honeytoken_use` (50) means a minted fake credential such as
`mrg_live_9f2ab04c1d7e83a5c60214bd` appeared in an Authorization header,
body or query — near-certain evidence, and it names exactly which decoy
leaked. `path_enumeration` (25) fires on the eighth distinct *unknown* path
inside 60 seconds; unknown excludes `/`, protected routes, scanner paths,
decoys and lead paths.

**Medium class — request shape.** `ua_suspicious` (15): a UA containing
`sqlmap/`, `nikto`, `nuclei`, `python-requests/` and the rest of
`data/ua-suspicious.txt`. `ua_rotation` (20): four or more distinct
non-empty UAs in five minutes. `no_cookie_persistence` (15): a fifth request
in a session that has never sent a Cookie header and was spotless until now.
`headers_sparse` (10) and `ua_missing` (10): requests with fewer than four
headers or no user agent at all — real browsers send neither shape.

## The gating rules (normative)

Three signals are gated to prevent the classic false positives. Each rule is
exercised by golden vectors.

1. **curl gating.** `tooling_curl` fires only when a same-request signal
   fired earlier in evaluation order — that is, one of signals 1–5.
   `headers_sparse` does NOT ungate it, and prior session score does NOT
   ungate it. Rationale: `curl/` appears in legitimate API checks and health
   probes.
2. **ua_rotation gating.** Requires ≥ 4 distinct UAs in the trailing 300 s
   AND another same-request signal from the ungating set (signals 1–5). A
   session that merely rotates UAs — some privacy tools do — is never scored
   on rotation alone.
3. **no_cookie_persistence gating.** Fires only in an otherwise-clean
   session: request count ≥ 5 (including the current request), never a
   cookie, cumulative score 0 before, and no other signal this request. It
   never stacks with scanner or decoy evidence — those already explain the
   session.

A weight tie for `reason_code` resolves to the earliest signal in evaluation
order (vector v17: `scanner_path` over `path_enumeration`, both 25).

What the fired signals add up to is the
[verdict ladder]({{ site.baseurl }}/guide/verdicts.html). Verified bots,
owner IPs and other never-scored addresses produce no signals at all — see
[modes]({{ site.baseurl }}/guide/modes.html) and the
[charter]({{ site.baseurl }}/charter.html) for why that is deliberate.
