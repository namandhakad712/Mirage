# Mirage Adapter Protocol — v1

Normative. Every edge adapter (Go middleware, Cloudflare Worker, future
plugins) speaks this protocol. A conformance suite runs against each adapter
before it ships; golden-vector parity is mandatory.

`protocol_version: "1"`

## 1. Shape

An adapter is a synchronous decision point plus an asynchronous event emit:

```
request ──► Mirage.decide(DecisionRequest, deadline) ──► Decision ──► act
                                   │
                                   └─(async, bounded)──► Mirage.event(Event)
```

Two transports are allowed (I3):

- **In-process**: the engine is a library linked into the adapter (Go
  middleware, Worker bundle). Decision is a function call.
- **Local IPC**: unix socket or loopback HTTP to a local Mirage Edge
  process, with a hard deadline. No remote calls in the hot path.

## 2. DecisionRequest

```json
{
  "protocol_version": "1",
  "method": "GET",
  "path": "/.env?x=1",
  "client_ip": "203.0.113.7",
  "trusted_peer": true,
  "user_agent": "curl/8.5.0",
  "header_count": 3,
  "has_cookie": false,
  "ts_ms": 1780000000000,
  "deadline_ms": 5
}
```

- `client_ip` is the adapter's best client IP **after** its own trusted-proxy
  walk. `trusted_peer` says whether the immediate peer was a trusted proxy.
- `deadline_ms` is the maximum wall-clock budget the adapter will wait.
  Recommended: 5 ms. On overrun the engine returns the fail-open decision.

## 3. Decision

```json
{
  "protocol_version": "1",
  "spec_version": "1.1.0",
  "verdict": "decoy_route",
  "action": "serve_decoy",
  "decoy_id": "env-file-staging",
  "session_key": "fec52565aa0cf18f57d7cf5b3ac72850",
  "reason_code": "SIG-101",
  "request_score": 25,
  "score": 25,
  "signals": ["scanner_path"],
  "ban_ttl_ms": null
}
```

`action` ∈ `pass` | `serve_decoy` | `throttle` | `ban`:

- `pass` — forward to origin unmodified (observe, tag).
- `serve_decoy` — the adapter renders the decoy identified by `decoy_id`
  from its local snapshot. Never a network fetch (I3, I2).
- `throttle` — apply the adapter's local throttle (e.g. 429 or tarpit with
  caps); the origin is protected but never hard-failed by Mirage itself.
- `ban` — the adapter blocks (short TTL) **only if enforcement is enabled
  for the site**; otherwise it degrades to `throttle`. Enforcement is
  opt-in (I9).

The fail-open decision — returned on any internal error, unknown protocol
version, or deadline overrun — is always:

```json
{"protocol_version": "1", "verdict": "observe", "action": "pass", "decoy_id": null,
 "session_key": null, "reason_code": "SIG-000", "request_score": 0, "score": 0,
 "signals": [], "ban_ttl_ms": null}
```

Reason code `SIG-000` is reserved for fail-open and is never a ban input.

## 4. Event

```json
{
  "protocol_version": "1",
  "ts_ms": 1780000000000,
  "session_key": "fec52565aa0cf18f57d7cf5b3ac72850",
  "client_ip": "203.0.113.7",
  "method": "GET",
  "path": "/.env",
  "decision": { "...": "the Decision object as returned" }
}
```

- Emission is **asynchronous and bounded**: a ring buffer with a configured
  cap (default 10 000 events). When full, oldest events are dropped and a
  drop counter increments. Emitting must never block the hot path.
- Events are idempotent by `(session_key, ts_ms, path)`; consumers must
  tolerate replays after Core recovery.
- All fields are attacker-influenced: consumers escape on render (I7).

## 5. Conformance requirements

An adapter is conformant when:

1. **Fail-open proof**: with the engine removed, slow, or erroring, 100% of
   requests reach the origin unmodified within the latency budget.
2. **Vector parity**: identical verdicts on `spec/golden-vectors/vectors.json`.
3. **Deadline honored**: p99 decision overhead < deadline; overrun ⇒
   fail-open decision, counter incremented.
4. **No asset-path dependency**: real routes render identically without
   Mirage present (I2).
5. **Decoy hygiene**: decoys served only on `serve_decoy`; every decoy
   response carries the noindex header set (I12); no third-party redirects
   (I8, I14).
6. **Event discipline**: bounded queue, drop counter, no hot-path blocking.

## 6. Versioning

`protocol_version` changes only on breaking wire changes; `spec_version`
tracks the signal spec independently. An adapter that receives a request or
snapshot with a newer `spec_version` than it knows fails open and reports a
version-mismatch counter.
