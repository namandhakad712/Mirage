---
layout: doc
title: "Architecture"
description: "The Mirage decision path end-to-end: adapter request to engine scoring, verdict ladder, actions, events, store and connectors."
category: guide
order: 3
---

Mirage is one synchronous decision per request plus asynchronous everything
else. That split is the architecture: the hot path is local and bounded (I3),
every failure degrades to pass-through (I1), and every automated action
leaves evidence (I10). This page walks the path once, then maps each step to
its Go package.

## The path of one request

The figure below traces the full lifecycle at a glance: the synchronous
decision from the client through the adapter, engine and verdict ladder to
the action, then the asynchronous trail from the bounded event queue through
the store to the connectors.

{% include diagrams/decision-path.html %}

**1. Adapter submits a request.** An edge adapter — Go middleware, the
Cloudflare Worker, a future plugin — builds a `model.Request`: `method`,
`path` (raw, including dot segments and query), `client_ip`, `user_agent`,
`header_count` (all headers, including Host and User-Agent), `has_cookie`,
`ts_ms`, and optionally `auth_hint` (credential material the adapter can
see, matched against minted honeytokens). An adapter that cannot see a
field passes the neutral value; signals requiring the field do not fire.
`client_ip` is the adapter's own trusted-proxy walk result, never a raw
spoofable header (I6).

**2. `Service.Decide` runs the fixed sequence** (`internal/service`):

1. The decision is timestamped once, so deadline arithmetic, ban bookkeeping
   and store records agree.
2. Never-scored resolution (I6): owner, CDN and allowlisted-bot ranges, and
   verified-bot user agents, produce an `observe` decision with no session
   state recorded.
3. Renewal (protect mode, enforcement armed): a request from an address
   holding an unexpired ban renews it — verdict `ban`, the ORIGINAL reason
   code, the remaining TTL, no signals, no rescore. A banned address must
   not earn its way out with clean-looking requests. Flipping the kill
   switch disarms renewal on the next decision (I9).
4. The engine scores the request deterministically, in memory (I3), against
   the session snapshot: session key is `sha256(client_ip)[:32]`, state
   expires after 30 idle minutes.
5. Deadline check: if scoring overran the budget (5 ms), the decision is
   `model.FailOpen()` — verdict `observe`, action `pass`, reason `SIG-000` —
   and no event is emitted. `SIG-000` is reserved for fail-open and is never
   a ban input.
6. Mode gating (I9): `look` caps the verdict at `tag` and always passes;
   `tripwires` keeps `serve_decoy` but passes throttle/ban actions;
   `protect` enforces, and a ban action goes through the gatekeeper.
7. Deadline check again, after enforcement wiring; on overrun the adapter
   still sees the fail-open decision.
8. Event emission: a bounded queue write that never blocks (I3). On a full
   queue the newest event is dropped and counted — losing evidence is better
   than stalling a request.

**3. The adapter acts** on the returned `model.Decision`: `pass` (forward
unmodified), `serve_decoy` (render the decoy named by `decoy_id` locally
from the snapshot — never a network fetch), `throttle` (a local, capped
slowdown), or `ban` (a short block, only when enforcement is enabled).

**4. Events drain to the store.** A background drainer (`internal/service`)
drains the queue every 250 ms in batches of 512, appends events, folds
per-session rolling summaries (bounded at 65,536 sessions, least-recently-
seen eviction) and upserts them. `Stop` flushes the queue once more.

**5. Bans fan out and reconcile.** An applied ban is written to the
gatekeeper, a renewal memo and the store, then handed to every connector on
a bounded goroutine (5 s). A reconcile loop shows every connector the
store's active ban set every 30 s, so a missed or crashed Apply heals and a
revoked ban disappears from providers. Connectors are outbound-only and
fail-open by design.

## The packages

| Package | Role on the path |
| --- | --- |
| `internal/model` | Shared types: `Request`, `Decision`, `Event`; session key; the trusted-proxy IP walk and never-scored ranges (I6); the reason-text sanitizer (I7). |
| `internal/config` | Strict YAML loading, every bound, the loopback token requirement; fails closed at boot. |
| `internal/detect` | The SIGNALS v1.1.0 engine: scoring, verdict ladder, gating; the parity target. |
| `internal/service` | `Decide`, renewal, mode gating, the drainer, the dashboard. Holds I1/I3/I9/I10 across packages. |
| `internal/decoy` | Catalog loader, deterministic renderer, pollution suite (I8, I12–I14). |
| `internal/enforce` | The gatekeeper: kill switch and per-verdict budgets (I5, I9). |
| `internal/events` | The bounded queue with drop policies and a drop counter (I3). |
| `internal/store` | SQLite (WAL) and in-memory stores; versioned schema. |
| `internal/connectors` | Denyfile, webhook, CrowdSec LAPI, Cloudflare — one retry envelope. |
| `packages/mirage-worker` | The TypeScript port: same engine and vectors, zero runtime dependencies, per-isolate state, fail-open handler. |

## Two implementations, one spec

The Go core and the worker must produce identical verdicts on
`spec/golden-vectors/vectors.json` (20 cases, 68 requests); CI fails on any
divergence. The worker is stateless across isolates, so durable bans and
long-horizon session signals belong to the core — a recorded limit in
[known limits]({{ site.baseurl }}/known-limits.html).

Continue with [signals]({{ site.baseurl }}/guide/signals.html) for what the
engine actually measures.
