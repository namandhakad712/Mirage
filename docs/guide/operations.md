---
layout: doc
title: "Operations"
description: "The Mirage production runbook: choosing a store, budget tuning, connector selection, dashboard usage, ban renewal and fail-open behavior."
category: guide
order: 9
---

This is the runbook for running Mirage on real traffic. The mode ladder and
its safety rails are covered in [modes]({{ site.baseurl }}/guide/modes.html);
this page is about the knobs underneath.

## Choosing a store

SQLite in WAL mode is the default (`store.path`, default `mirage.db`): one
file, safe concurrent reads, events and ban records survive a restart, kept
for `store.retention_days` (default 30, bound 1–3650). The in-memory store
is for tests and ephemeral deployments — a restart loses events, while
decisions stay correct (the engine's session snapshot is in memory in every
configuration). `store.hash_ips: true` (default) stores salted-hashed
client IPs; an explicit `false` is honored and trades privacy for
debuggability.

## Budgets

| Budget | Default | Effect when exceeded |
| --- | --- | --- |
| Decision budget | 5 ms | The decision degrades to fail-open `pass`; the adapter never waits. |
| Event queue | 10,000 events (bound 100–1,000,000) | The newest event is dropped and counted in `/api/status` (`queue.dropped`). |
| Bans per minute | 10 | Enforcement drops to observe; verdicts still record. |
| Concurrent bans | 100 | Same. |
| Share of sessions banned | 5% (bound 1–100) | Same. |

The ban budgets exist so Mirage can never ban its way through legitimate
traffic (I5, I15). Raising them is a deliberate risk decision, not tuning.

## Choosing connectors

Connectors deliver bans (and unbans) — only in protect mode, only when
armed. All are optional; protect without connectors is a valid
local-enforcement deployment.

| Connector | Pick it when | Notes |
| --- | --- | --- |
| `denyfile` | You run nginx/Apache on the same host. | Zero dependencies; atomic rewrites (temp file, fsync, rename), one line per address, sorted; the reload is yours to automate. |
| `webhook` | You want bans in your own automation. | POSTs JSON signed with hex HMAC-SHA256 in `X-Mirage-Signature`; verify before acting. |
| `crowdsec` | You already run CrowdSec. | Pushes to the local LAPI as alerts with one decision, origin `mirage`. |
| `cloudflare` | Your zone is on Cloudflare. | Zone IP access rules, `mirage: `-prefixed for ownership; anything un-prefixed is never touched. |

No connector credential lives in the config file (I11): each block carries
only the NAME of an environment variable (`api_key_env`, `api_token_env`,
`secret_env`), resolved at call time and never stored on the Config. A
missed or crashed Apply heals on the reconcile pass (every 30 s), which
also removes stale and revoked bans from providers.

## Dashboard usage

The dashboard is a separate server from the proxy: it binds
`--dashboard-addr` (default `127.0.0.1:8090`, loopback only — non-
loopback binds are refused) and requires the token even on loopback.
Reach it through an SSH tunnel, not a public bind:

```bash
ssh -L 8090:127.0.0.1:8090 you@example.com
curl -s -H "X-Mirage-Dashboard-Token: $TOKEN" http://127.0.0.1:8090/api/status
```

Endpoints: `/healthz` (tokenless probe, fixed body), `/api/status` (mode,
spec and protocol versions, uptime, queue length and drops, store health,
connector health), `/api/events` (recorded decisions), `/api/sessions`
(per-session summaries), `/api/bans` (ban records) and
`POST /api/bans/revoke` — the one-click reversal every ban must have (I5).
Listing endpoints page with a `limit` parameter (default 50, capped at
1,000). Every response is JSON with `Cache-Control: no-store`.

## Renewal, reversal and the kill switch

An active ban renews on every request from the banned address, citing the
original reason and remaining TTL — long bans do not silently expire under
sustained probing. Reversal is `POST /api/bans/revoke` (the reconcile loop
removes it from providers within 30 s). The kill switch disarms renewal
within one decision. Session state itself expires after 30 idle minutes,
starting a fresh epoch with cumulative score 0.

## Upgrade discipline

Run `make check` before every deploy — the same gates CI runs
([tooling]({{ site.baseurl }}/guide/tooling.html)). Config loading is
strict and fails closed at boot: unknown keys, out-of-bound values and
half-configured connector blocks are boot-time errors, so a bad config
stops the process, not the site. Validate staged changes with
`mirage doctor --config mirage.yaml` (exit 0 / 1).

## What fail-open means operationally

A broken Mirage is an invisible Mirage (I1). Store down: decisions stay
exact, event persistence fails loudly in logs, `/healthz` stays 200. Queue
full: events drop and count; requests never wait. Connector dead or hung:
the local ban holds, the request returns promptly, reconcile heals later.
Decision overruns the budget: the request passes unscored. The one
deployment rule that follows: keep the origin reachable directly, so
removing Mirage from the path is a one-line edit, not an architecture
change — the [nginx topology]({{ site.baseurl }}/deploy/nginx.html) shows
the break-glass pattern.
