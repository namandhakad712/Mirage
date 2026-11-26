# nginx — the transparent-proxy integration

This is the reference topology for self-hosted Mirage: nginx terminates
TLS and proxies to Mirage; Mirage scores each request, serves decoys to
already-suspicious sessions, and passes everything else to your origin
unmodified. Two parts of this page are runnable today — the deny map and
the reverse-proxy/X-Forwarded-For conventions — and the rest describes the
deployment the `mirage` server binary serves when it lands with the server
release. Nothing here is hypothetical about Mirage's side: every behavior
described is pinned by `internal/config` (the `listen` and
`trusted_proxies` keys), `internal/connectors` (the deny map and webhook
connectors) and the invariants.

## What Mirage needs in front

- **A TLS-terminating proxy.** Mirage does no TLS termination in v1 — it
  sits behind nginx (or Caddy, or Cloudflare). This keeps Mirage's attack
  surface small; see [known-limits.md](../known-limits.md).
- **One proxy hop it can trust.** Mirage derives the real client IP from
  the socket address, or from `X-Forwarded-For` **only when the immediate
  peer is a trusted proxy listed in `trusted_proxies`** (I6). The chain is
  walked right-to-left, skipping trusted proxies; the first non-trusted
  address is the client. A peer that is not listed has its forwarding
  headers ignored entirely — an attacker must not be able to frame an
  innocent address by sending a forged `X-Forwarded-For`.
- **An origin that stays reachable.** Mirage never sits between your users
  and your site as the only path: any internal failure sends traffic to the
  origin unmodified (I1). nginx keeps the origin as the fallback — see the
  fail-open section below.

## The worked configuration

nginx side — terminate TLS, forward everything to Mirage's listen address
(default `127.0.0.1:8080`, from `listen` in `mirage.yaml`):

```nginx
# /etc/nginx/sites-available/example.com
server {
    listen 443 ssl;
    server_name example.com;

    # TLS stays in nginx (Mirage terminates none in v1).
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;

        # Identity: nginx is the one proxy Mirage trusts. The nginx
        # builtin appends $remote_addr to any incoming X-Forwarded-For,
        # and Mirage walks the resulting chain right-to-left, stopping
        # at the first non-trusted address.
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host              $host;

        # The deny map Mirage maintains, if you use the denyfile
        # connector. Create the file (empty) before enabling the include;
        # the glob form tolerates the file being absent. Reload is
        # yours to automate (see below).
        # include /etc/nginx/mirage-deny*.conf;
    }
}
```

Mirage side — `mirage.yaml`:

```yaml
listen: "127.0.0.1:8080"

# nginx runs on the same host: trust exactly the loopback it comes from.
# Add your CDN's ranges here ONLY if you control that CDN account (I6).
trusted_proxies:
  - "127.0.0.1/32"
  - "::1/128"
```

Do not add addresses you do not control to `trusted_proxies`. A listed
proxy can spoof client identity to Mirage; an unlisted one cannot.

## The loopback dashboard

The dashboard and core API bind to `listen`, loopback by default. Reach it
through an SSH tunnel instead of opening it:

```sh
ssh -L 8080:127.0.0.1:8080 you@example.com
# then, on your workstation: http://127.0.0.1:8080
```

The dashboard requires a token **even on loopback** — an unauthenticated
local endpoint is one `curl` away from a full takeover. Generate it with
`openssl rand -hex 32` and set `dashboard_token` in `mirage.yaml`. This is
a hard validation rule, not advice: an empty token is a boot-time error.

## The deny map (runnable today)

The denyfile connector (`internal/connectors/denyfile.go`) maintains an
nginx-compatible deny map: one line per address, sorted, and written
atomically — content goes to a temp file in the same directory, is fsynced,
then renamed over the target, so a crash mid-rewrite leaves the previous
map intact rather than a truncated include your web server would refuse to
load (I1). Configure it with `connectors.denyfile.path` (for example
`/etc/nginx/mirage-deny.conf`) and include it in the `location` block as
shown above. The file looks like this:

```nginx
# managed by mirage — do not edit
deny 203.0.113.7;  # SIG-104 expires 2026-11-26T18:00:00Z
```

nginx picks up deny-map changes only on reload. Mirage writes the file; it
does not signal nginx — an automated reload belongs to your automation.
The natural place is a small webhook receiver: Mirage signs every ban and
unban notice with `X-Mirage-Signature`
([vendor-notes.md](../vendor-notes.md) documents the exact verification), and
your receiver runs `nginx -t && nginx -s reload` only after the signature
checks out.

## Mode matrix

| `mode` | What Mirage does on a request | What nginx must do |
| --- | --- | --- |
| `look` | Observe and record only. No decoys are served, nothing is enforced. | Nothing beyond `proxy_pass` above. |
| `tripwires` | As `look`, plus: sessions already scored suspicious are served inert decoys on decoy routes. Real routes untouched (I12: never to verified bots or ordinary visitors). | Nothing. Decoys are served by Mirage, not by nginx. |
| `protect` | As `tripwires`, plus enforcement *may* run — only with `enforcement.enabled: true`, kill switch off, budgets in range (I9). | Optional: include the deny map and automate the reload. |

Moving between modes is a `mirage.yaml` edit; each mode is fully
reversible.

## The fail-open contract (I1)

Mirage fails open by design: any internal failure — crash, timeout, bad
config, full disk — sends traffic to the origin unmodified. Mirage must
never be the reason a site is down. Three practical consequences for this
topology:

1. **Keep the origin reachable directly.** A break-glass `location` (or a
   commented `proxy_pass` pointing at the origin) lets you take Mirage out
   of the path in one edit. Moving down a rung is deleting one line, not
   re-architecting.
2. **The origin fetch is never Mirage's to retry.** In the worker this is
   pinned by code (origin errors are never mistaken for Mirage errors);
   the same discipline applies here — an origin outage must surface as an
   origin outage.
3. **The deny map is the only synchronous enforcement surface**, and it
   degrades safely: rewrites are atomic and sorted so the map is always
   loadable, and Reconcile prunes expired entries so a stale ban cannot
   outlive its TTL. The file must exist before nginx loads it — create it
   empty first, or use the glob include shown above, which tolerates
   absence.

## See also

- [quickstart.md](quickstart.md) — from zero to a verified build and a
  prepared `mirage.yaml`.
- [vendor-notes.md](../vendor-notes.md) — the CrowdSec, Cloudflare and
  webhook receiver contracts behind `protect` mode.
- [cloudflare-worker.md](cloudflare-worker.md) — the edge deployment that
  runs today, if you would rather not self-host at all.
