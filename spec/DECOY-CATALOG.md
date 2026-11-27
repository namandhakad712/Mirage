# Mirage Decoy Catalog Specification — v1

Normative format for `spec/decoy-catalog/` entries. The catalog is data, not
code: shared verbatim by the Go core and the TypeScript worker (generated
into `src/generated/` at build time by `scripts/gen-data.mjs`).

`catalog_version: "1"`

## 1. Entry format (YAML)

```yaml
id: env-file-staging          # unique, stable, kebab-case
persona: laravel-staging      # references a persona below
path: /.env                   # absolute, no query string
status: 200                   # HTTP status served
content_type: text/plain
headers:                      # extra headers; noindex set is added automatically
  - "X-Powered-By: PHP/8.2.12"
size_cap_bytes: 2048          # hard cap per I12 bounded footprint
body: |                       # template with {{SEED:*}} placeholders (§4)
  APP_NAME=staging
  APP_KEY=base64:{{SEED:44_B64}}
  DATABASE_URL=postgres://deploy:{{TOKEN:db_password}}@db.test:5432/staging
  MAIL_MAILER=smtp
  MAIL_HOST=mail.test
leads:                        # paths that exist ONLY inside this decoy response
  - /storage/logs/laravel-staging.log
honeytokens:                  # inert credential formats minted per session
  - id: db_password
    format: token_alnum_24
```

## 2. Personas

A persona is one consistent fake identity per attacker session: stack,
headers, error pages, file contents, timestamps and fake IDs all agree,
because inconsistency is how an agent or its operator spots a trap. Seeded
generation (session key as seed) keeps each session deterministic and
reproducible.

v1 ships three personas:

| persona | stack story | tells |
| --- | --- | --- |
| `laravel-staging` | Laravel 10 on PHP 8.2 behind nginx, staging environment | `X-Powered-By: PHP/8.2.12`, .env layout, laravel-style logs |
| `legacy-cpanel` | aged shared-hosting cPanel box | `.cpanel`-style paths, Apache-ish headers, old backup listings |
| `node-api-dev` | Node API left in dev mode | JSON error payloads, `/api/docs`, source maps |

## 3. v1 catalog entries (6)

| id | persona | path | lures |
| --- | --- | --- | --- |
| `env-file-staging` | laravel-staging | `/.env` | env-file hunters |
| `git-config-staging` | laravel-staging | `/.git/config` | git-directory readers |
| `admin-panel-legacy` | legacy-cpanel | `/admin/login` | panel seekers |
| `debug-endpoint-legacy` | legacy-cpanel | `/debug` | debug-endpoint probers |
| `api-docs-dev` | node-api-dev | `/api/docs` | API enumerators |
| `source-map-dev` | node-api-dev | `/app.js.map` | source-map miners |

Catalog safety rules (validated by `internal/decoy` and mirrored in the
worker):

1. Entry paths are unique within the catalog, and a lead must not claim
   `/.well-known/**` or collide with an entry path — the catalog loader
   enforces those at load time (`internal/decoy`). Entries must also
   stay off real routes, robots.txt, sitemaps and health checks; that
   part is catalog-author discipline (the shipped catalog complies), and
   the engine independently caps protected routes at `tag`, so a
   colliding entry is never served there (I4).
2. `/.env` and `/.git/config` also appear in `data/scanner-paths.txt`;
   the engine suppresses `decoy_hit` behind `scanner_path` (SIGNALS §4.2) —
   the catalog entry is still what gets **served** on `decoy_route`.
3. Body templates are inert: no executable content, no scripts, no
   third-party links, no redirects (I8, I14).
4. Every response carries `X-Robots-Tag: noindex, nofollow, noarchive`
   (I12) regardless of template headers.

## 4. Placeholders and seeding

Placeholders are resolved per session deterministically from
`sha256(session_key + ":" + entry_id + ":seed:" + spec + ":" + k)` where
`k` is the 0-based occurrence index of **that spec string** in the body —
two identical `{{SEED:…}}` placeholders in one body never render the same
value, while the derivation stays byte-identical across the Go and
TypeScript implementations. The formula is pinned byte-for-byte by
`spec/golden-vectors/renders.json` (rendered body of every entry for two
fixed session keys); both engines must reproduce it exactly.

- `{{SEED:N_HEX}}` — first N hex chars of the digest (N ≤ 64).
  `{{SEED:N_B64}}` — N unpadded standard-base64 chars (N must be a
  multiple of 4, derived from the first 3N/4 digest bytes).
  `{{SEED:N_UPPER}}` — first N digest bytes folded mod 36 over A-Z0-9.
- `{{TOKEN:id}}` — mint the honeytoken for (session, entry, id) as
  `"mrg_live_" + hex(sha256(session_key + ":" + entry_id + ":" + token_id))[:24]`
  — the first 24 hex characters of the digest, so a token names its
  session, entry and slot without a database. The one mintable format is
  `token_alnum_24` in `data/token-formats.md`. Later use of the exact
  string anywhere Mirage can see fires `honeytoken_use` (SIG-104) and
  proves which decoy leaked.

Timestamps inside bodies render from `ts_ms` of the serving request, so
decoys never contradict themselves within a session.

## 5. Honeytoken formats (I14)

All formats are in the `mrg_` namespace that no real service issues, or use
reserved hosts/ranges — see `data/token-formats.md`. A honeytoken must
never validate against a real service. The validation suite runs secret
scanners over every rendered decoy to prove it.

## 6. Pollution suite (pass 7b, runs on every decoy change)

1. Crawl the test site as a verified search bot: zero decoy URLs, zero
   hidden links.
2. Every decoy response carries the noindex header set; none appear in
   sitemaps.
3. Secret scanners + format validators over the rendered catalog: no
   live-valid credential patterns, no real personal data, no real domains
   outside the permitted technology-stack markers.
4. Depth, size and tarpit connection caps hold under load.
5. Feed-poisoning test: forged reports produce no ban (I15).
