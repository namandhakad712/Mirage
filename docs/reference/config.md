---
layout: doc
title: "Configuration Reference"
description: "Every key of the Mirage site config with its type, default, validation bound, what it controls, and the invariant behind it."
category: reference
order: 2
---

This page walks `mirage.example.yaml` key by key — the complete annotated
config surface, which mirrors `internal/config` exactly. Loading is strict:
a YAML file must decode with KnownFields enabled, so a typo or an unknown
key is a boot-time error, never a silently disabled security control.
`config.Validate` lists ALL violations before failing; Mirage fails closed
at boot and open at request time (I1).

## Identity and network

| Key | Type | Default | Bound / validation | Controls | Why |
| --- | --- | --- | --- | --- | --- |
| `mode` | string | `"look"` | One of `look`, `tripwires`, `protect`; anything else is rejected at boot | The integration ladder (see [modes]({{ site.baseurl }}/guide/modes.html)) | I9: observe by default; enforcement needs more than the mode |
| `site` | string | `""` | Free text | Site name or origin URL used in dashboards and reports | Identification only |
| `listen` | string | `"127.0.0.1:8080"` | Valid address | The address the proxy binds | Loopback by default; the dashboard never binds `listen` — it is a separate loopback server on `--dashboard-addr` |
| `trusted_proxies` | list of CIDR | none (socket address only) | Every entry must parse as a CIDR or boot fails | Proxies whose `X-Forwarded-For` chain is trusted; walked right-to-left, the first non-trusted address is the client | I6: an unlisted peer's forwarding headers are ignored entirely, so an attacker cannot frame an innocent address. List ONLY proxies you control |
| `dashboard_token` | string | required | Must not be empty — a hard validation rule, not advice | The token guarding every dashboard endpoint except `/healthz` | An unauthenticated local endpoint is one `curl` away from a takeover. Generate with `openssl rand -hex 32`. The one secret carried inline; the loader ships `Redacted()` for safe logging (I11) |
| `owner_ips` | list of CIDR | none | Every entry must parse as a CIDR | Ranges that are never scored and never banned (office egress, VPN, load balancer) | I6, I15: requests from them produce verdict `observe` and record no session state |
| `protected_routes` | list of strings | the five routes below | A route ending in `/` is a prefix match; anything else matches exactly | Routes never decoyed and never throttle-capped by decoy logic | I4. Absent means the canon default; an explicitly empty list (`[]`) means no protected routes — a deliberate choice made out loud |

Canon `protected_routes` default: `/wp-login.php`, `/wp-admin/`, `/checkout`,
`/cart`, `/api/`.

## Store

| Key | Type | Default | Bound / validation | Controls | Why |
| --- | --- | --- | --- | --- | --- |
| `store.path` | string | `"mirage.db"` | Filesystem path | Store file location; SQLite in WAL mode | One file, durable events and ban records, safe concurrent reads |
| `store.retention_days` | int | `30` | 1..3650 | How long decision events are kept | Bounded history; the store cannot grow forever |
| `store.hash_ips` | bool | `true` | An explicit `false` is honored (it survives loading) | Salt-and-hash stored client IPs | Privacy by default; `false` trades it for debuggability |

## Events

| Key | Type | Default | Bound / validation | Controls | Why |
| --- | --- | --- | --- | --- | --- |
| `events.queue_capacity` | int | `10000` | 100..1000000 | Capacity of the bounded event queue between the request path and the store | I3: when the queue is full the newest entry is dropped and counted — emission never blocks a request |

## Decoys

| Key | Type | Default | Bound / validation | Controls | Why |
| --- | --- | --- | --- | --- | --- |
| `decoys.catalog_path` | string | `"spec/decoy-catalog/catalog.yaml"` | Path to a catalog in `spec/DECOY-CATALOG.md` format | Decoy catalog location | The shipped catalog is data, not code, shared by both engines |
| `decoys.enabled` | bool | `true` | An explicit `false` is honored | Serve decoys at all | The one-line way to take the deception layer down |

## Enforcement

| Key | Type | Default | Bound / validation | Controls | Why |
| --- | --- | --- | --- | --- | --- |
| `enforcement.enabled` | bool | `false` | May only be `true` when `mode` is `protect`; otherwise a boot-time error | Master opt-in for enforcement | I9: even when true, the kill switch and the budgets still gate every action |
| `enforcement.kill_switch` | bool | `false` | — | The global off-switch: while `true` no ban or throttle executes and no connector is called | Flip it when anything looks wrong; it takes effect immediately, renewal included |
| `enforcement.ban_ttl_ms` | int | `1800000` — 1,800,000 ms (30 minutes) | Milliseconds | Ban TTL, single address | I5, I15: short and reversible by design |

### Budgets

Caps so Mirage can never ban its way through legitimate traffic. When a
budget is exceeded, enforcement drops to observe rather than over-ban.

| Key | Type | Default | Bound / validation | Controls |
| --- | --- | --- | --- | --- |
| `enforcement.budgets.max_bans_per_minute` | int | `10` | — | Bans per minute |
| `enforcement.budgets.max_concurrent_bans` | int | `100` | — | Concurrent active bans |
| `enforcement.budgets.max_share_pct` | int | `5` | 1..100 | Maximum share of sessions that may be banned |

## Connectors

All connector blocks are optional. A block left entirely empty counts as
not configured; setting any key of a block requires its siblings —
half-configured connectors are boot-time errors. No connector credential
lives in this file (I11): each block carries only the NAME of an
environment variable holding the secret; the value is resolved at call
time and never stored on the Config.

| Key | Type | Default | Controls | Why |
| --- | --- | --- | --- | --- |
| `connectors.crowdsec.lapi_url` | string | `""` (disabled) | Local CrowdSec LAPI URL (e.g. `http://127.0.0.1:8081`) | Bans pushed as alerts with a single decision, origin `mirage` |
| `connectors.crowdsec.api_key_env` | string | `""` | Environment variable holding the LAPI machine key | Both crowdsec keys are required together |
| `connectors.cloudflare.account_id` | string | `""` (disabled) | Cloudflare account ID | Bans become zone IP access rules |
| `connectors.cloudflare.zone_id` | string | `""` (disabled) | Cloudflare zone ID | All three cloudflare keys are required together |
| `connectors.cloudflare.api_token_env` | string | `""` | Environment variable holding the Cloudflare API token | Rules carry the notes prefix `mirage: `; anything without it is never touched |
| `connectors.webhook.url` | string | `""` (disabled) | Receiver URL for signed ban/unban notices | Body is JSON; signature is hex HMAC-SHA256 in `X-Mirage-Signature` |
| `connectors.webhook.secret_env` | string | `""` | Environment variable holding the HMAC signing secret | Both webhook keys are required together |
| `connectors.denyfile.path` | string | `""` (disabled) | Path of the nginx/Apache-compatible deny map | Atomic rewrites (temp file, fsync, rename), one line per address, sorted, `# managed by mirage` header |

## Loading rules worth remembering

- Copy the example to `mirage.yaml` (gitignored on purpose) — or generate
  one with `mirage init`, which writes `mode: "look"` and a generated
  `dashboard_token` (nothing else) and validates the file before
  reporting success. The decoy-path rules — duplicate entry paths, leads
  under `/.well-known/`, lead/entry collisions — are enforced by the
  catalog loader at load time (I4), not by init.
- Every violation is listed before the boot fails, so one edit can fix
  them all.
- Validate staged changes without booting: `mirage doctor --config
  mirage.yaml` (see the [CLI reference]({{ site.baseurl }}/reference/cli.html)).

The [operations guide]({{ site.baseurl }}/guide/operations.html) explains
how to choose between these values; this page only states what they are.
