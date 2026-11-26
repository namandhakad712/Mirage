---
layout: doc
title: "Golden Vectors — Hand Computed"
description: "The arithmetic behind all 20 golden vector cases, computed by hand and cross-checked by tools/gen_vectors.py."
category: spec
order: 4
source: spec/golden-vectors/HAND-COMPUTED.md
---
Spec `1.1.0`, protocol `1`, 20 cases, 68 requests. Every expectation below is hand-computed from `spec/SIGNALS.md` and cross-checked by the reference engine in `tools/gen_vectors.py`; the generator exits 1 on any disagreement. All client IPs are RFC 5737 documentation addresses; all hostnames in payloads are RFC 2606 reserved.

## v01-clean-browsing — 203.0.113.20

Five ordinary browser requests with cookies and a full header set. No signal can fire: paths are real or harmless unknowns (only 4 distinct unknowns, below the enumeration threshold of 8), headers are full, a cookie is sent, the UA is a browser. Verdicts observe, cumulative 0.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET / | — | observe | 0 |
| 2 | GET /about | — | observe | 0 |
| 3 | GET /pricing | — | observe | 0 |
| 4 | GET /blog | — | observe | 0 |
| 5 | GET /contact | — | observe | 0 |

## v02-scanner-path — 203.0.113.7

Worked example W1. GET /.env with a plain browser UA: scanner_path 25 (high); decoy_hit is suppressed by SIGNALS 4.2. request 25 >= 25 with high class on a decoyable path -> decoy_route. Cumulative 25. Session key is the sha256 anchor: fec52565aa0cf18f57d7cf5b3ac72850.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /.env | scanner_path | decoy_route | 25 |

## v03-decoy-hit — 203.0.113.8

GET /admin/login (admin-panel-legacy decoy, not on the scanner list). decoy_hit 30, high, decoyable -> decoy_route. Cumulative 30.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /admin/login | decoy_hit | decoy_route | 30 |

## v04-decoy-lead-follow — 203.0.113.9

req1: GET /.env -> scanner_path 25 -> decoy_route; the decoy is served, so its lead /storage/logs/laravel-staging.log becomes known to the session. req2 follows the lead: decoy_lead_follow 40 (near-certain), path not protected -> ban. Cumulative 25 + 40 = 65.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /.env | scanner_path | decoy_route | 25 |
| 2 | GET /storage/logs/laravel-staging.log | decoy_lead_follow | ban | 65 |

## v05-honeytoken-protected — 203.0.113.10

req1: GET /.env -> decoy_route; the env decoy mints the db_password honeytoken for this session. req2 uses that exact token as a bearer credential on /api/v1/auth (protected prefix). honeytoken_use 50 survives the protected-route cap (SIGNALS section 5, R3 exception) -> ban. Cumulative 25 + 50 = 75.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /.env | scanner_path | decoy_route | 25 |
| 2 | POST /api/v1/auth | honeytoken_use | ban | 75 |

## v06-structure-only — 203.0.113.11

req1: browser-like GET /products (9 headers, cookie) -> observe; /products is an unknown path (count 1). reqs 2-8: scripted GETs /nope1../nope7, empty UA, 2 headers -> headers_sparse 10 + ua_missing 10 = 20 per request -> tag (20 >= 15). Cumulative after req7: 6 x 20 = 120. req8 (/nope7): distinct unknown paths in the trailing 60 s reach 8 (/products + /nope1-7) -> path_enumeration 25 joins: request 25 + 10 + 10 = 45 -> throttle, cumulative 165. req9 (/nope8): 9 distinct unknowns, same 45 -> throttle, cumulative 210. Never ban: no near-certain signal and request score 45 < 60.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /products | — | observe | 0 |
| 2 | GET /nope1 | headers_sparse, ua_missing | tag | 20 |
| 3 | GET /nope2 | headers_sparse, ua_missing | tag | 40 |
| 4 | GET /nope3 | headers_sparse, ua_missing | tag | 60 |
| 5 | GET /nope4 | headers_sparse, ua_missing | tag | 80 |
| 6 | GET /nope5 | headers_sparse, ua_missing | tag | 100 |
| 7 | GET /nope6 | headers_sparse, ua_missing | tag | 120 |
| 8 | GET /nope7 | path_enumeration, headers_sparse, ua_missing | throttle | 165 |
| 9 | GET /nope8 | path_enumeration, headers_sparse, ua_missing | throttle | 210 |

## v07-verified-bot — 203.0.113.12

Googlebot UA hits /.env. Verified-bot hint (case-insensitive substring) -> never scored, observe, no session state (I12: bots never meet a trap).

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /.env | — | observe | 0 |

## v08-allowlist-ip — 192.0.2.50

The owner's own IP (allowlisted in the case config) hits a decoy path. Never scored, observe, no session state.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /admin/login | — | observe | 0 |

## v09-protected-route — 203.0.113.13

Worked examples W2/W3. req1: GET /wp-login.php with sqlmap UA (4 headers, above the sparse threshold): ua_suspicious 15 -> tag; the path is protected so the verdict caps at tag anyway. req2: GET /.env with sqlmap UA: scanner_path 25 + ua_suspicious 15 = 40 -> throttle. Cumulative 15 then 55.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /wp-login.php | ua_suspicious | tag | 15 |
| 2 | GET /.env | scanner_path, ua_suspicious | throttle | 55 |

## v10-curl-gating — 203.0.113.14

SIGNALS section 6.1. req1: GET /products with curl UA and 3 headers: headers_sparse 10 fires, but tooling_curl does NOT (no signal from the ungating set 1-5 fired this request; headers_sparse does not ungate). request 10 < 15 -> observe, cumulative 10. req2: GET /.env with curl UA: scanner_path 25 fires first and ungates tooling_curl 15; headers_sparse 10 also fires: 25 + 15 + 10 = 50 -> throttle. Cumulative 60.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /products | headers_sparse | observe | 10 |
| 2 | GET /.env | scanner_path, headers_sparse, tooling_curl | throttle | 60 |

## v11-ua-rotation-gated — 203.0.113.15

SIGNALS section 6.2. reqs 1-4: four distinct non-empty UAs on /products with full headers: at req4 the count reaches 4 but NO other signal fired this request -> ua_rotation must NOT fire (observe). req5: fifth UA on /.env: scanner_path 25 fires and ungates ua_rotation 20 -> 45 -> throttle. Cumulative 45.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /products | — | observe | 0 |
| 2 | GET /products | — | observe | 0 |
| 3 | GET /products | — | observe | 0 |
| 4 | GET /products | — | observe | 0 |
| 5 | GET /.env | scanner_path, ua_rotation | throttle | 45 |

## v12-no-cookie-persistence — 203.0.113.16

SIGNALS section 6.3. Five requests to the same unknown path with a full header set and never a cookie. reqs 1-4: no signal (1 distinct unknown, full headers, normal UA). req5: request count reaches 5, cookie_ever false, cumulative 0 before, no other signal this request -> no_cookie_persistence 15 -> tag. Cumulative 15.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /products | — | observe | 0 |
| 2 | GET /products | — | observe | 0 |
| 3 | GET /products | — | observe | 0 |
| 4 | GET /products | — | observe | 0 |
| 5 | GET /products | no_cookie_persistence | tag | 15 |

## v13-no-cookie-gated — 203.0.113.17

Same as v12, but the fifth request hits /.env. scanner_path fires, so no_cookie_persistence is suppressed (the request is no longer otherwise-clean): only scanner_path 25, high, decoyable -> decoy_route. Cumulative 25.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /products | — | observe | 0 |
| 2 | GET /products | — | observe | 0 |
| 3 | GET /products | — | observe | 0 |
| 4 | GET /products | — | observe | 0 |
| 5 | GET /.env | scanner_path | decoy_route | 25 |

## v14-session-expiry — 203.0.113.18

SIGNALS section 7. req1: GET /.env -> scanner_path 25 -> decoy_route, cumulative 25. req2 arrives 31 minutes later (1 860 000 ms > 30 min TTL): the session resets first, so a clean GET /about is observe with cumulative 0. req3: GET /.env one second later in the fresh epoch: scanner_path 25 -> decoy_route, cumulative 25.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /.env | scanner_path | decoy_route | 25 |
| 2 | GET /about | — | observe | 0 |
| 3 | GET /.env | scanner_path | decoy_route | 25 |

## v15-normalization — 203.0.113.19

SIGNALS section 3. req1: /shop/../wp-config.php.bak?debug=1 -> query stripped, /shop/.. pops shop -> /wp-config.php.bak, a scanner path -> scanner_path 25. The path is NOT a catalog decoy, so the decoy_route rung does not hold -> tag. req2: /../../.env clamps at the root and resolves to /.env -> scanner_path 25, decoyable -> decoy_route. req3: /a/../../.. pops 'a', then '..' at the root clamps (dot_escape) -> scanner_path fires per 4.1; resolved path / is not decoyable -> tag. Cumulative 25, 50, 75.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /shop/../wp-config.php.bak?debug=1 | scanner_path | tag | 25 |
| 2 | GET /../../.env | scanner_path | decoy_route | 50 |
| 3 | GET /a/../../.. | scanner_path | tag | 75 |

## v16-ua-rotation-plus — 203.0.113.21

Rotation gate plus history-tagging. reqs 1-3: three distinct UAs on /products, full headers -> observe (3 < 4; rotation must NOT fire at req3). req4: fourth distinct UA, but no other signal this request -> rotation still NOT fired -> observe. req5: GET /admin/login with a fifth UA: decoy_hit 30 ungates ua_rotation 20 -> 50 -> throttle (cumulative 50). req6: clean request, but cumulative 50 >= 25 -> tag via history (verdict rungs use the request's own score except the tag rung, SIGNALS section 5.1). req7: 2 headers -> headers_sparse 10; rotation stays gated (headers_sparse is not in the ungating set 1-5): request 10, tag via history. Cumulative 60.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /products | — | observe | 0 |
| 2 | GET /products | — | observe | 0 |
| 3 | GET /products | — | observe | 0 |
| 4 | GET /products | — | observe | 0 |
| 5 | GET /admin/login | decoy_hit, ua_rotation | throttle | 50 |
| 6 | GET /products | — | tag | 50 |
| 7 | GET /products | headers_sparse | tag | 60 |

## v17-combination-ban — 203.0.113.22

Ban through a strong combination (SIGNALS section 5.4c) without any near-certain signal. reqs 1-7: scripted GETs /u1../u7, empty UA, 2 headers: 20 each -> tag, cumulative 140. req8: /u8 -> 8 distinct unknown paths in 60 s -> path_enumeration 25 + 10 + 10 = 45 -> throttle, cumulative 185. req9: GET /.env: scanner_path 25 + path_enumeration 25 (unknowns u1-u8 still in window) + headers_sparse 10 + ua_missing 10 = 70 >= 60 with high class -> BAN. Cumulative 255.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /u1 | headers_sparse, ua_missing | tag | 20 |
| 2 | GET /u2 | headers_sparse, ua_missing | tag | 40 |
| 3 | GET /u3 | headers_sparse, ua_missing | tag | 60 |
| 4 | GET /u4 | headers_sparse, ua_missing | tag | 80 |
| 5 | GET /u5 | headers_sparse, ua_missing | tag | 100 |
| 6 | GET /u6 | headers_sparse, ua_missing | tag | 120 |
| 7 | GET /u7 | headers_sparse, ua_missing | tag | 140 |
| 8 | GET /u8 | path_enumeration, headers_sparse, ua_missing | throttle | 185 |
| 9 | GET /.env | scanner_path, path_enumeration, headers_sparse, ua_missing | ban | 255 |

## v18-query-and-slash — 203.0.113.23

req1: GET /.env?token=abc123 -> the query is stripped before matching -> scanner_path 25 -> decoy_route. req2: GET /phpmyadmin-old -> loader normalization (SIGNALS 3.3): the list entry /phpmyadmin-old/ matches the slashless path -> scanner_path 25; not a decoy -> tag. Cumulative 25, 50.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /.env?token=abc123 | scanner_path | decoy_route | 25 |
| 2 | GET /phpmyadmin-old | scanner_path | tag | 50 |

## v19-honeytoken-reuse — 203.0.113.24

req1: GET /.env -> decoy_route; the env decoy mints db_password. req2 uses the minted token inside a fake postgres URL carried as credential material on /api/v2/users (protected): honeytoken_use 50 -> ban despite the cap. Cumulative 75.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /.env | scanner_path | decoy_route | 25 |
| 2 | POST /api/v2/users | honeytoken_use | ban | 75 |

## v20-ip-spoof-rejected — 198.51.100.5

Invariant I6. The request carries X-Forwarded-For: 203.0.113.99, but the peer is not a trusted proxy, so the client IP stays the socket address 198.51.100.5 and the session key is sha256('198.51.100.5')[:32] = 8959edf6884f2c2e223a9319e83a6982. The attacker cannot frame the innocent 203.0.113.99. Clean request -> observe.

| # | request | signals | verdict | score |
| --- | --- | --- | --- | --- |
| 1 | GET /about | — | observe | 0 |

## Canon decisions (recorded to keep implementations honest)

1. The ungating set for `tooling_curl` and `ua_rotation` is signals 1-5 (`scanner_path`, `decoy_hit`, `decoy_lead_follow`, `honeytoken_use`, `path_enumeration`). `headers_sparse` and other medium signals never ungate (mirrors SIGNALS 6.1 for curl; applied consistently to rotation).
2. `no_cookie_persistence` gates on signals 1-7 (its predecessors in evaluation order); `headers_sparse` / `ua_missing` / `tooling_curl` may co-fire with it.
3. A weight tie for `reason_code` resolves to the earliest signal in evaluation order (e.g. v17 req9: scanner_path over path_enumeration, both 25).
4. Unknown-path counting for enumeration excludes ALL catalog lead paths (not only served ones); a lead is Mirage's territory.
5. `request_count` for the no-cookie gate includes the current request (fires on the 5th at the earliest).
6. Decoy serving (and therefore lead registration and honeytoken minting) happens only on verdict `decoy_route`; `throttle` and `ban` do not serve.
