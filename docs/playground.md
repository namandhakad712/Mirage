---
layout: doc
title: "Verdict Playground"
description: "Score a request against the real decision engine, live in the browser: 11 signals, verdict ladder, mode actions and the 20 golden vector cases — zero network."
category: guide
order: 12
---

The playground is the decision engine itself, ported line for line to
JavaScript and running in this page. Compose a request on the left, press
**Score it**, and the right column shows what the Go core would decide:
which signals fired and which gates kept the rest silent, the exact score
arithmetic, the rung the verdict landed on, the action the selected mode
takes, and the session state the request leaves behind. Nothing is
approximated, nothing calls out — the engine is deterministic, so the
same composer state always produces the same decision.

The port is held honest by CI: the parity harness replays all
[20 golden vector cases]({{ site.baseurl }}/spec/golden-vectors/HAND-COMPUTED.html)
(68 requests) through this exact file and fails the build on any
divergence from the hand-computed expectations in
[the signal spec]({{ site.baseurl }}/spec/SIGNALS.html).

## The simulator

<link rel="stylesheet" href="{{ site.baseurl }}/assets/css/simulator.css">
<div class="sim-root" id="sim-root">
<div class="sim-grid">
<form class="sim-panel" id="sim-composer" novalidate>
<p class="sim-plate">Composer <code>one request + session priors</code></p>
<div class="sim-group">
<p class="sim-legend">Client</p>
<div class="sim-field"><label class="sim-label" for="sim-client">Client class</label>
<select class="sim-select" id="sim-client">
<option value="remote" selected>remote — 203.0.113.7 (scored)</option>
<option value="loopback">loopback — 127.0.0.1 (never scored)</option>
<option value="owner">owner range — 192.0.2.50 (never scored)</option>
</select></div>
</div>
<div class="sim-group">
<p class="sim-legend">Request</p>
<div class="sim-field"><label class="sim-label" for="sim-path">Path <span class="sim-hint">raw, dot segments and query strings allowed</span></label>
<input class="sim-input" type="text" id="sim-path" value="/.env" spellcheck="false" autocomplete="off"></div>
<div class="sim-chipbar" role="group" aria-label="Path presets">
<button type="button" class="sim-chip" data-path="/">/</button>
<button type="button" class="sim-chip" data-path="/about">/about</button>
<button type="button" class="sim-chip" data-path="/.env" aria-pressed="true">/.env</button>
<button type="button" class="sim-chip" data-path="/wp-login.php">/wp-login.php</button>
<button type="button" class="sim-chip" data-path="/storage/logs/laravel-staging.log">/storage/logs/laravel-staging.log</button>
</div>
<div class="sim-field"><label class="sim-label" for="sim-ua">User agent</label>
<select class="sim-select" id="sim-ua">
<option value="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36" selected>modern browser</option>
<option value="curl/8.5.0">curl/8.5.0</option>
<option value="sqlmap/1.8.2#stable">old scraper (sqlmap)</option>
<option value="">empty (no User-Agent header)</option>
</select></div>
<div class="sim-field"><label class="sim-label" for="sim-headers">Header count <span class="sim-hint">including Host and User-Agent</span></label>
<div class="sim-range-row"><input type="range" class="sim-range" id="sim-headers" min="1" max="12" step="1" value="8"><span class="sim-range-value" id="sim-headers-value">8</span></div></div>
<label class="sim-switch" for="sim-cookie"><input type="checkbox" id="sim-cookie"> Cookie header sent <span class="sim-hint">also mirrors the session's prior requests</span></label>
</div>
<div class="sim-group">
<p class="sim-legend">Session priors <span class="sim-hint">the session before this request</span></p>
<div class="sim-field"><label class="sim-label" for="sim-prior-requests">Requests already in this epoch <span class="sim-hint">signal 8 fires on the 5th at the earliest</span></label>
<input class="sim-input" type="number" id="sim-prior-requests" min="0" max="40" step="1" value="0"></div>
<div class="sim-field"><label class="sim-label" for="sim-prior-cum">cum_before <span class="sim-hint">cumulative score; ≥ 25 tags via history</span></label>
<input class="sim-input" type="number" id="sim-prior-cum" min="0" max="999" step="1" value="0"></div>
<div class="sim-field"><label class="sim-label" for="sim-prior-uas">Distinct user agents in 300 s <span class="sim-hint">prior requests, before this one</span></label>
<input class="sim-input" type="number" id="sim-prior-uas" min="0" max="6" step="1" value="0"></div>
<div class="sim-field"><label class="sim-label" for="sim-prior-unknowns">Distinct unknown paths in 60 s <span class="sim-hint">the threshold is 8</span></label>
<input class="sim-input" type="number" id="sim-prior-unknowns" min="0" max="12" step="1" value="0"></div>
</div>
<div class="sim-group">
<p class="sim-legend">Events</p>
<label class="sim-switch" for="sim-ev-decoy"><input type="checkbox" id="sim-ev-decoy"> Hit a decoy entry <span class="sim-hint">path becomes /admin/login, a pure catalog decoy</span></label>
<label class="sim-switch" for="sim-ev-lead"><input type="checkbox" id="sim-ev-lead"> Followed a decoy lead <span class="sim-hint">the env decoy was served earlier; path becomes its lead</span></label>
<label class="sim-switch" for="sim-ev-token"><input type="checkbox" id="sim-ev-token"> Presented a honeytoken <span class="sim-hint">credential material carries the minted db_password token</span></label>
<label class="sim-switch" for="sim-ev-protected"><input type="checkbox" id="sim-ev-protected"> Protected route <span class="sim-hint">path becomes /wp-login.php — verdict capped at tag</span></label>
</div>
<div class="sim-group">
<p class="sim-legend">Operating mode</p>
<div class="sim-field"><label class="sim-label" for="sim-mode">Mode <span class="sim-hint">verdicts are mode-blind; only actions change</span></label>
<select class="sim-select" id="sim-mode">
<option value="look">look — observe only</option>
<option value="tripwires" selected>tripwires — decoys served, enforcement disarmed</option>
<option value="protect">protect — full enforcement</option>
</select></div>
</div>
<div class="sim-actions">
<button type="button" class="btn btn-primary" id="sim-score">Score it</button>
</div>
</form>
<div class="sim-decision" id="sim-decision" aria-live="polite">
<p class="sim-note">Scoring runs when the page loads and on every Score it press. If this text is showing, the engine module did not boot — every number below would then be unproven, so it stays empty rather than guessed.</p>
</div>
</div>
<p class="sim-fallback" hidden>The simulator could not start on this browser. The engine and its parity proof still run in CI (node tools/check_simulator.mjs); only this page's interactivity is unavailable.</p>
</div>

## Reading the composer

Every control maps onto one input of the scoring engine — nothing on this
page invents a knob the real one does not have.

| Control | Spec knob | Notes |
| --- | --- | --- |
| Client class | §2 never-scored | Loopback and owner-range addresses produce `observe` with no signals and no session state. |
| Path | §3 normalization | Query strings are stripped, `.` and `..` resolve left to right, `..` at the root fires `scanner_path` via dot_escape. |
| User agent | §4.6, §4.10, §4.11 | The old scraper string matches `ua_suspicious`; empty matches `ua_missing`; curl unlocks `tooling_curl` when a high signal fires too. |
| Header count | §4.9 | `headers_sparse` fires below 4, counting Host and User-Agent. |
| Session priors | §5, §4.5, §4.7 | `cum_before` feeds the history tag; the window counters add the current request's UA and path before comparing. |
| Events | §4.2, §4.3, §4.4 | The lead and honeytoken toggles seed the session with an earlier `env-file-staging` serve — the one catalog entry with a honeytoken. |
| Protected route | §5 cap (I4) | Protected paths record at most `tag`; `honeytoken_use` is the one exception that still bans. |
| Mode | service layer (I9) | `look` caps the recorded verdict at tag and passes; `tripwires` serves decoys but passes throttle/ban; `protect` enforces: `serve_decoy`, 429 + `Retry-After: 30`, 403. |

Two engine facts are worth trying by hand, because they look like bugs
until the spec explains them. Serving a decoy happens only on
`decoy_route` — a throttled or banned request registers no leads and
mints no honeytokens, so chase the `Followed a decoy lead` toggle with a
throttle-worthy request and watch the lead stay unknown. And session
history alone never escalates: a clean request with `cum_before ≥ 25`
tags, but no request-scoring rung above it will fire on history.

## Walking the golden vectors

The same engine that scores the composer also replays the golden vector
file — the 20 hand-computed cases that gate every implementation. Pick a
case and step through its requests: session state is replayed exactly
the way the parity harness does it, one fresh session per case, expected
next to computed. The stepper is demo sugar; the proof is the harness in
CI, but watching v17 climb from `tag` to `throttle` to `ban` — or v13
suppress `no_cookie_persistence` the moment a scanner path fires — is
the fastest way to understand why those cases exist.

<div class="sim-panel" id="sim-stepper">
<p class="sim-plate">Golden vectors <code>spec/golden-vectors/vectors.json</code></p>
<div class="sim-stepper">
<select class="sim-select" id="sim-case" aria-label="Golden vector case"></select>
<button type="button" class="sim-step" id="sim-prev">&#8592; prev</button>
<span class="sim-step-label" id="sim-step-label"></span>
<button type="button" class="sim-step" id="sim-next">next &#8594;</button>
</div>
<div id="sim-stepper-out"></div>
<script type="application/json" id="sim-vectors">
{"spec_version":"1.1.0","protocol_version":"1","policy":{"protected_routes":["/wp-login.php","/wp-admin/","/checkout","/cart","/api/"],"session_ttl_ms":1800000,"ua_window_ms":300000,"enum_window_ms":60000,"enum_threshold":8,"ua_rotation_threshold":4,"ban_ttl_ms":1800000},"cases":[{"id":"v01-clean-browsing","client_ip":"203.0.113.20","allowlisted_ips":[],"requests":[{"method":"GET","path":"/","ts_ms":1780000000000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":9,"has_cookie":true},{"method":"GET","path":"/about","ts_ms":1780000001000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":9,"has_cookie":true},{"method":"GET","path":"/pricing","ts_ms":1780000002000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":9,"has_cookie":true},{"method":"GET","path":"/blog","ts_ms":1780000003000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":9,"has_cookie":true},{"method":"GET","path":"/contact","ts_ms":1780000004000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":9,"has_cookie":true}],"expected":[{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"}]},{"id":"v02-scanner-path","client_ip":"203.0.113.7","allowlisted_ips":[],"requests":[{"method":"GET","path":"/.env","ts_ms":1780000000000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false}],"expected":[{"signals":["scanner_path"],"verdict":"decoy_route","score":25,"reason_code":"SIG-101"}]},{"id":"v03-decoy-hit","client_ip":"203.0.113.8","allowlisted_ips":[],"requests":[{"method":"GET","path":"/admin/login","ts_ms":1780000000000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false}],"expected":[{"signals":["decoy_hit"],"verdict":"decoy_route","score":30,"reason_code":"SIG-102"}]},{"id":"v04-decoy-lead-follow","client_ip":"203.0.113.9","allowlisted_ips":[],"requests":[{"method":"GET","path":"/.env","ts_ms":1780000000000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false},{"method":"GET","path":"/storage/logs/laravel-staging.log","ts_ms":1780000001000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false}],"expected":[{"signals":["scanner_path"],"verdict":"decoy_route","score":25,"reason_code":"SIG-101"},{"signals":["decoy_lead_follow"],"verdict":"ban","score":65,"reason_code":"SIG-103"}]},{"id":"v05-honeytoken-protected","client_ip":"203.0.113.10","allowlisted_ips":[],"requests":[{"method":"GET","path":"/.env","ts_ms":1780000000000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false},{"method":"POST","path":"/api/v1/auth","ts_ms":1780000001000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false,"auth_hint":"Bearer mrg_live_63e36e2d68663c27f6841a68"}],"expected":[{"signals":["scanner_path"],"verdict":"decoy_route","score":25,"reason_code":"SIG-101"},{"signals":["honeytoken_use"],"verdict":"ban","score":75,"reason_code":"SIG-104"}]},{"id":"v06-structure-only","client_ip":"203.0.113.11","allowlisted_ips":[],"requests":[{"method":"GET","path":"/products","ts_ms":1780000000000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":9,"has_cookie":true},{"method":"GET","path":"/nope1","ts_ms":1780000001000,"user_agent":"","header_count":2,"has_cookie":false},{"method":"GET","path":"/nope2","ts_ms":1780000002000,"user_agent":"","header_count":2,"has_cookie":false},{"method":"GET","path":"/nope3","ts_ms":1780000003000,"user_agent":"","header_count":2,"has_cookie":false},{"method":"GET","path":"/nope4","ts_ms":1780000004000,"user_agent":"","header_count":2,"has_cookie":false},{"method":"GET","path":"/nope5","ts_ms":1780000005000,"user_agent":"","header_count":2,"has_cookie":false},{"method":"GET","path":"/nope6","ts_ms":1780000006000,"user_agent":"","header_count":2,"has_cookie":false},{"method":"GET","path":"/nope7","ts_ms":1780000007000,"user_agent":"","header_count":2,"has_cookie":false},{"method":"GET","path":"/nope8","ts_ms":1780000008000,"user_agent":"","header_count":2,"has_cookie":false}],"expected":[{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":["headers_sparse","ua_missing"],"verdict":"tag","score":20,"reason_code":"SIG-109"},{"signals":["headers_sparse","ua_missing"],"verdict":"tag","score":40,"reason_code":"SIG-109"},{"signals":["headers_sparse","ua_missing"],"verdict":"tag","score":60,"reason_code":"SIG-109"},{"signals":["headers_sparse","ua_missing"],"verdict":"tag","score":80,"reason_code":"SIG-109"},{"signals":["headers_sparse","ua_missing"],"verdict":"tag","score":100,"reason_code":"SIG-109"},{"signals":["headers_sparse","ua_missing"],"verdict":"tag","score":120,"reason_code":"SIG-109"},{"signals":["path_enumeration","headers_sparse","ua_missing"],"verdict":"throttle","score":165,"reason_code":"SIG-105"},{"signals":["path_enumeration","headers_sparse","ua_missing"],"verdict":"throttle","score":210,"reason_code":"SIG-105"}]},{"id":"v07-verified-bot","client_ip":"203.0.113.12","allowlisted_ips":[],"requests":[{"method":"GET","path":"/.env","ts_ms":1780000000000,"user_agent":"Mozilla/5.0 (compatible; Googlebot/2.1; +\u0068ttp://www.google.com/bot.html)","header_count":8,"has_cookie":false}],"expected":[{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"}]},{"id":"v08-allowlist-ip","client_ip":"192.0.2.50","allowlisted_ips":["192.0.2.50/32"],"requests":[{"method":"GET","path":"/admin/login","ts_ms":1780000000000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false}],"expected":[{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"}]},{"id":"v09-protected-route","client_ip":"203.0.113.13","allowlisted_ips":[],"requests":[{"method":"GET","path":"/wp-login.php","ts_ms":1780000000000,"user_agent":"sqlmap/1.8.2#stable (\u0068ttp://sqlmap.org)","header_count":4,"has_cookie":false},{"method":"GET","path":"/.env","ts_ms":1780000001000,"user_agent":"sqlmap/1.8.2#stable (\u0068ttp://sqlmap.org)","header_count":4,"has_cookie":false}],"expected":[{"signals":["ua_suspicious"],"verdict":"tag","score":15,"reason_code":"SIG-106"},{"signals":["scanner_path","ua_suspicious"],"verdict":"throttle","score":55,"reason_code":"SIG-101"}]},{"id":"v10-curl-gating","client_ip":"203.0.113.14","allowlisted_ips":[],"requests":[{"method":"GET","path":"/products","ts_ms":1780000000000,"user_agent":"curl/8.5.0","header_count":3,"has_cookie":false},{"method":"GET","path":"/.env","ts_ms":1780000001000,"user_agent":"curl/8.5.0","header_count":3,"has_cookie":false}],"expected":[{"signals":["headers_sparse"],"verdict":"observe","score":10,"reason_code":"SIG-109"},{"signals":["scanner_path","headers_sparse","tooling_curl"],"verdict":"throttle","score":60,"reason_code":"SIG-101"}]},{"id":"v11-ua-rotation-gated","client_ip":"203.0.113.15","allowlisted_ips":[],"requests":[{"method":"GET","path":"/products","ts_ms":1780000000000,"user_agent":"UA-A/1.0","header_count":7,"has_cookie":true},{"method":"GET","path":"/products","ts_ms":1780000001000,"user_agent":"UA-B/1.0","header_count":7,"has_cookie":true},{"method":"GET","path":"/products","ts_ms":1780000002000,"user_agent":"UA-C/1.0","header_count":7,"has_cookie":true},{"method":"GET","path":"/products","ts_ms":1780000003000,"user_agent":"UA-D/1.0","header_count":7,"has_cookie":true},{"method":"GET","path":"/.env","ts_ms":1780000004000,"user_agent":"UA-E/1.0","header_count":7,"has_cookie":false}],"expected":[{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":["scanner_path","ua_rotation"],"verdict":"throttle","score":45,"reason_code":"SIG-101"}]},{"id":"v12-no-cookie-persistence","client_ip":"203.0.113.16","allowlisted_ips":[],"requests":[{"method":"GET","path":"/products","ts_ms":1780000000000,"user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)","header_count":8,"has_cookie":false},{"method":"GET","path":"/products","ts_ms":1780000001000,"user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)","header_count":8,"has_cookie":false},{"method":"GET","path":"/products","ts_ms":1780000002000,"user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)","header_count":8,"has_cookie":false},{"method":"GET","path":"/products","ts_ms":1780000003000,"user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)","header_count":8,"has_cookie":false},{"method":"GET","path":"/products","ts_ms":1780000004000,"user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)","header_count":8,"has_cookie":false}],"expected":[{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":["no_cookie_persistence"],"verdict":"tag","score":15,"reason_code":"SIG-108"}]},{"id":"v13-no-cookie-gated","client_ip":"203.0.113.17","allowlisted_ips":[],"requests":[{"method":"GET","path":"/products","ts_ms":1780000000000,"user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)","header_count":8,"has_cookie":false},{"method":"GET","path":"/products","ts_ms":1780000001000,"user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)","header_count":8,"has_cookie":false},{"method":"GET","path":"/products","ts_ms":1780000002000,"user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)","header_count":8,"has_cookie":false},{"method":"GET","path":"/products","ts_ms":1780000003000,"user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)","header_count":8,"has_cookie":false},{"method":"GET","path":"/.env","ts_ms":1780000004000,"user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)","header_count":8,"has_cookie":false}],"expected":[{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":["scanner_path"],"verdict":"decoy_route","score":25,"reason_code":"SIG-101"}]},{"id":"v14-session-expiry","client_ip":"203.0.113.18","allowlisted_ips":[],"requests":[{"method":"GET","path":"/.env","ts_ms":1780000000000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false},{"method":"GET","path":"/about","ts_ms":1780001860000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":9,"has_cookie":true},{"method":"GET","path":"/.env","ts_ms":1780001861000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false}],"expected":[{"signals":["scanner_path"],"verdict":"decoy_route","score":25,"reason_code":"SIG-101"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":["scanner_path"],"verdict":"decoy_route","score":25,"reason_code":"SIG-101"}]},{"id":"v15-normalization","client_ip":"203.0.113.19","allowlisted_ips":[],"requests":[{"method":"GET","path":"/shop/../wp-config.php.bak?debug=1","ts_ms":1780000000000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false},{"method":"GET","path":"/../../.env","ts_ms":1780000001000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false},{"method":"GET","path":"/a/../../..","ts_ms":1780000002000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false}],"expected":[{"signals":["scanner_path"],"verdict":"tag","score":25,"reason_code":"SIG-101"},{"signals":["scanner_path"],"verdict":"decoy_route","score":50,"reason_code":"SIG-101"},{"signals":["scanner_path"],"verdict":"tag","score":75,"reason_code":"SIG-101"}]},{"id":"v16-ua-rotation-plus","client_ip":"203.0.113.21","allowlisted_ips":[],"requests":[{"method":"GET","path":"/products","ts_ms":1780000000000,"user_agent":"Rot-A/1.0","header_count":7,"has_cookie":true},{"method":"GET","path":"/products","ts_ms":1780000001000,"user_agent":"Rot-B/1.0","header_count":7,"has_cookie":true},{"method":"GET","path":"/products","ts_ms":1780000002000,"user_agent":"Rot-C/1.0","header_count":7,"has_cookie":true},{"method":"GET","path":"/products","ts_ms":1780000003000,"user_agent":"Rot-D/1.0","header_count":7,"has_cookie":true},{"method":"GET","path":"/admin/login","ts_ms":1780000004000,"user_agent":"Rot-E/1.0","header_count":7,"has_cookie":false},{"method":"GET","path":"/products","ts_ms":1780000005000,"user_agent":"Rot-F/1.0","header_count":7,"has_cookie":true},{"method":"GET","path":"/products","ts_ms":1780000006000,"user_agent":"Rot-G/1.0","header_count":2,"has_cookie":false}],"expected":[{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"},{"signals":["decoy_hit","ua_rotation"],"verdict":"throttle","score":50,"reason_code":"SIG-102"},{"signals":[],"verdict":"tag","score":50,"reason_code":"SIG-000"},{"signals":["headers_sparse"],"verdict":"tag","score":60,"reason_code":"SIG-109"}]},{"id":"v17-combination-ban","client_ip":"203.0.113.22","allowlisted_ips":[],"requests":[{"method":"GET","path":"/u1","ts_ms":1780000001000,"user_agent":"","header_count":2,"has_cookie":false},{"method":"GET","path":"/u2","ts_ms":1780000002000,"user_agent":"","header_count":2,"has_cookie":false},{"method":"GET","path":"/u3","ts_ms":1780000003000,"user_agent":"","header_count":2,"has_cookie":false},{"method":"GET","path":"/u4","ts_ms":1780000004000,"user_agent":"","header_count":2,"has_cookie":false},{"method":"GET","path":"/u5","ts_ms":1780000005000,"user_agent":"","header_count":2,"has_cookie":false},{"method":"GET","path":"/u6","ts_ms":1780000006000,"user_agent":"","header_count":2,"has_cookie":false},{"method":"GET","path":"/u7","ts_ms":1780000007000,"user_agent":"","header_count":2,"has_cookie":false},{"method":"GET","path":"/u8","ts_ms":1780000008000,"user_agent":"","header_count":2,"has_cookie":false},{"method":"GET","path":"/.env","ts_ms":1780000008000,"user_agent":"","header_count":2,"has_cookie":false}],"expected":[{"signals":["headers_sparse","ua_missing"],"verdict":"tag","score":20,"reason_code":"SIG-109"},{"signals":["headers_sparse","ua_missing"],"verdict":"tag","score":40,"reason_code":"SIG-109"},{"signals":["headers_sparse","ua_missing"],"verdict":"tag","score":60,"reason_code":"SIG-109"},{"signals":["headers_sparse","ua_missing"],"verdict":"tag","score":80,"reason_code":"SIG-109"},{"signals":["headers_sparse","ua_missing"],"verdict":"tag","score":100,"reason_code":"SIG-109"},{"signals":["headers_sparse","ua_missing"],"verdict":"tag","score":120,"reason_code":"SIG-109"},{"signals":["headers_sparse","ua_missing"],"verdict":"tag","score":140,"reason_code":"SIG-109"},{"signals":["path_enumeration","headers_sparse","ua_missing"],"verdict":"throttle","score":185,"reason_code":"SIG-105"},{"signals":["scanner_path","path_enumeration","headers_sparse","ua_missing"],"verdict":"ban","score":255,"reason_code":"SIG-101"}]},{"id":"v18-query-and-slash","client_ip":"203.0.113.23","allowlisted_ips":[],"requests":[{"method":"GET","path":"/.env?token=abc123","ts_ms":1780000000000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false},{"method":"GET","path":"/phpmyadmin-old","ts_ms":1780000001000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false}],"expected":[{"signals":["scanner_path"],"verdict":"decoy_route","score":25,"reason_code":"SIG-101"},{"signals":["scanner_path"],"verdict":"tag","score":50,"reason_code":"SIG-101"}]},{"id":"v19-honeytoken-reuse","client_ip":"203.0.113.24","allowlisted_ips":[],"requests":[{"method":"GET","path":"/.env","ts_ms":1780000000000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false},{"method":"POST","path":"/api/v2/users","ts_ms":1780000001000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":8,"has_cookie":false,"auth_hint":"postgres://deploy:mrg_live_1aae9c952da11715b60a8218@db.test:5432/staging"}],"expected":[{"signals":["scanner_path"],"verdict":"decoy_route","score":25,"reason_code":"SIG-101"},{"signals":["honeytoken_use"],"verdict":"ban","score":75,"reason_code":"SIG-104"}]},{"id":"v20-ip-spoof-rejected","client_ip":"198.51.100.5","allowlisted_ips":[],"requests":[{"method":"GET","path":"/about","ts_ms":1780000000000,"user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36","header_count":9,"has_cookie":true,"x_forwarded_for":"203.0.113.99"}],"expected":[{"signals":[],"verdict":"observe","score":0,"reason_code":"SIG-000"}]}]}
</script>
</div>

## What this playground proves

Exactly one thing, and it is the thing that matters: the numbers on this
page are the numbers the shipped engines produce. The JavaScript module
in your tab and the Go core answer the 68 golden vector requests
identically, because CI replays the file through this module on every
push and refuses to pass on any mismatch — signals in evaluation order,
verdict, cumulative score, reason code, all four exact. There is no
second "demo math" hiding behind the panels, and nothing here needs a
network round trip to decide.

It proves nothing beyond the engine. The playground does not model the
gatekeeper's budgets, the never-ban list, ban renewal, the kill switch,
store events or connector fan-out — those live upstream of scoring and
are covered by the [mode guide]({{ site.baseurl }}/guide/modes.html),
the [operations guide]({{ site.baseurl }}/guide/operations.html) and the
[testing guide]({{ site.baseurl }}/guide/testing.html). When the real
system fails a deadline it fails open (I1); this page has no deadlines
to miss. For the full ladder arithmetic and every gate in prose, read
[verdicts]({{ site.baseurl }}/guide/verdicts.html) and
[signals]({{ site.baseurl }}/guide/signals.html); for the port itself,
`docs/assets/js/simulator.js` in the repository is the source of truth
this page runs.

<script type="module" src="{{ site.baseurl }}/assets/js/simulator.js"></script>
