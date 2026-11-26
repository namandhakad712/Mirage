# Vendor notes — exactly what Mirage calls, and what it expects back

Provider APIs are pinned (design §5): each connector documents the surface
it talks to, so an operator can audit the traffic Mirage generates. Every
connector implements one interface (`internal/connectors/connector.go`):
`Apply` (make the ban exist, idempotent), `Revoke` (remove it; revoking a
non-existent ban is success), `Reconcile` (walk provider state and remove
expired or unwanted bans — it only removes, never re-adds), `HealthCheck`.
TTLs belong to Mirage: durations are computed from the ban's
`expires_at_ms`, never read back from the provider.

Ban records carry: `ip` (a bare, validated address — no port, no CIDR;
anything else is refused before it can reach a file, URL or payload, I7),
`reason` (a stable `SIG-nnn` code), `note` (bounded context), and the
`created_at_ms` / `expires_at_ms` timestamps.

## The shared retry envelope

All HTTP connectors share one policy (`internal/connectors/retry.go`):

- **Three attempts total**; network errors retry like 5xxs.
- **Backoff:** 500 ms base doubling per failure (one failure → 500 ms, two
  → 1 s) plus 0–200 ms jitter (auto-seeded, concurrency-safe).
- **429:** the provider's `Retry-After` is honored as delta-seconds, capped
  at 30 s, and replaces the computed backoff for that attempt. HTTP-date
  values are deliberately not parsed — misreading one is worse than
  backing off.
- **5xx:** retried. **Any other 4xx:** permanent — fail immediately, no
  retry.
- **Per-call client timeout: 5 s.** Response bodies are drained (bounded at
  8 KiB) so connections are reusable; decoded bodies are bounded at 1 MiB.
- **Errors carry the HTTP status only** — never the URL (query strings can
  embed data) and never a token (I11).

Every connector is fail-open by design: a connector failure degrades
enforcement, never traffic.

## CrowdSec LAPI

Config: `connectors.crowdsec.lapi_url` (base URL) and
`connectors.crowdsec.api_key_env` (name of the environment variable
holding the machine key). Both are required if either is set. Mirage talks
to the pinned LAPI v1 surface with `Authorization: Bearer <key>`:

| Call | Endpoint | Used by |
| --- | --- | --- |
| Create ban | `POST {lapi}/v1/alerts` | `Apply` |
| List our decisions | `GET {lapi}/v1/decisions?origin=mirage` | `Reconcile` |
| Delete decisions for an address | `DELETE {lapi}/v1/decisions?ip=ADDR` | `Revoke`, `Reconcile` |
| Health | `GET {lapi}/v1/decisions?limit=1` (any 2xx is healthy) | `HealthCheck` |

`POST /v1/alerts` carries one alert with a single ban decision, and the
decision `scope` carries the address itself:

```json
{
  "capacity": 0,
  "events": [
    { "meta": { "log_source": "mirage" }, "timestamp": "2026-11-26T12:00:00Z" }
  ],
  "decisions": [
    { "duration": "30m", "reason": "mirage: SIG-104", "scope": "203.0.113.7",
      "type": "ban", "origin": "mirage" }
  ],
  "source": "mirage",
  "start_at": "2026-11-26T12:00:00Z"
}
```

Semantics worth knowing:

- **Durations are Mirage's**: `NNm` computed as
  `ceil((expires_at_ms - now) / 60s)`, clamped to a minimum of one minute,
  from an injected clock. The provider's own expiry is never read back.
- **Revocation deliberately bypasses the alerts delete endpoint** —
  removing whole alerts proved unreliable for per-address removal, so
  revocation goes through `DELETE /v1/decisions?ip=...` instead. A 404
  there is success with nothing removed.
- **Idempotence is enforced at Mirage's layer** (an applied-set keyed by
  address + reason, because the alerts endpoint would happily accept
  duplicates): re-applying the same address + reason while unexpired is a
  no-op success, so queue retries do not spam duplicate alerts.
- **`origin: "mirage"` is stamped on everything**, and Reconcile never
  touches foreign-origin decisions — the query filters by origin and each
  entry is re-checked before deletion.
- `Apply` refuses a ban whose expiry has already passed, so the queue can
  drop stale evidence instead of enforcing it.

## Cloudflare

Config: `connectors.cloudflare.account_id`, `zone_id` and
`api_token_env` — all three required if any is set; the token (from the
named environment variable) must be scoped to the one zone (I11). Mirage
talks to the zone-scoped IP access-rules API at
`api.cloudflare.com/client/v4` with `Authorization: Bearer <token>`:

| Call | Endpoint | Used by |
| --- | --- | --- |
| Create rule | `POST {api}/zones/{zone}/firewall/access_rules/rules` | `Apply` |
| List rules (paged) | `GET {api}/zones/{zone}/firewall/access_rules/rules?per_page=100&page=N` | `Reconcile`, `Revoke` fallback |
| Delete rule | `DELETE {api}/zones/{zone}/firewall/access_rules/rules/{id}` | `Revoke`, `Reconcile` |
| Health | `GET {api}/zones/{zone}` | `HealthCheck` |

The created rule shape is:

```json
{
  "mode": "block",
  "configuration": { "target": "ip", "value": "203.0.113.7" },
  "notes": "mirage: SIG-104"
}
```

Semantics worth knowing:

- **The `notes` prefix `mirage: ` is the safety boundary.** Reconcile
  deletes only rules carrying that prefix — the owner's own rules and
  other tools' rules are never touched, even when they block the same
  address.
- **Access rules have no native expiry.** Mirage owns TTL: Reconcile
  removes `mirage: `-prefixed rules whose address is no longer covered by
  an unexpired ban.
- **Idempotence:** a tracked IP → rule-ID map makes re-Apply a no-op;
  Revoke uses the tracked ID, or finds Mirage's own rule by listing — so a
  restart cannot orphan a rule at the provider. A 404 is success with
  nothing removed.
- **The pagination walk is bounded** (100 pages of 100), so a lying
  provider cannot make Mirage list forever.

## Webhook receiver contract

Config: `connectors.webhook.url` and `connectors.webhook.secret_env`
(both required if either is set). Mirage POSTs a signed JSON notice to the
endpoint on every ban and unban:

```
POST {endpoint}
Content-Type: application/json
X-Mirage-Signature: <hex(HMAC-SHA256(secret, body))>

{"ip":"203.0.113.7","reason":"SIG-104","note":"...",
 "created_at_ms":1780000000000,"expires_at_ms":1780018000000,
 "action":"ban"}
```

`action` is `"ban"` or `"unban"`; `reason` is the stable `SIG-nnn` code;
`ip` is a bare, validated address.

**Verifying the signature.** The `X-Mirage-Signature` header is the
hex-encoded HMAC-SHA256 of the **exact request body bytes** (the same
bytes that go on the wire), keyed by the secret. Verify before parsing,
and never verify over re-serialized JSON — parse first and the signature
will not match. In Python:

```python
import hashlib, hmac

secret = os.environ["MIRAGE_WEBHOOK_SECRET"]     # the env var secret_env names
body = request.raw_body                            # exact bytes, before any JSON parse
expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
if not hmac.compare_digest(expected, request.headers["X-Mirage-Signature"]):
    raise Reject("bad signature")
```

Equivalent check with `openssl` while debugging:

```sh
printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$MIRAGE_WEBHOOK_SECRET"
# compare the printed hex with the X-Mirage-Signature header
```

Delivery semantics:

- **At-least-once**, with authentication end to end; idempotence at the
  receiver is your choice (a common one: key on `ip` + `created_at_ms`).
- **5 s client timeout**, retried per the shared envelope above.
- **Reconcile is a no-op** — an opaque receiver offers no state to list;
  redelivery is the queue's job.
- **HealthCheck only validates the URL** (http/https scheme, non-empty
  host). It deliberately never sends a live probe: probing an unknown
  receiver with a real request could trigger enforcement side effects,
  which is exactly what a health check must never do.

## The deny map

The fourth connector (`denyfile`) has no vendor: it maintains an
nginx/Apache-compatible deny map at `connectors.denyfile.path` — one line
per address, sorted, atomically rewritten, with the expiry carried in a
comment and Reconcile owning expiry. See
[deploy/nginx.md](deploy/nginx.md) for the include and reload wiring.

## See also

- [deploy/nginx.md](deploy/nginx.md) — the transparent-proxy topology and
  the deny map.
- [deploy/quickstart.md](deploy/quickstart.md) — modes and the token
  rules.
- `internal/connectors/*.go` — the authoritative source for everything on
  this page; these notes mirror the code.
