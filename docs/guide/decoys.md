---
layout: doc
title: "Decoys"
description: "The Mirage decoy catalog: personas, entries, leads and honeytokens, how serving works, render determinism, and writing your own entry."
category: guide
order: 6
---

Decoys are Mirage's answers to scouts: inert, consistent fake surfaces
served only to sessions already scored suspicious. The catalog is data, not
code — one YAML file shared verbatim by the Go core and the TypeScript
worker (generated into `src/generated/` at worker build time), specified by
`spec/DECOY-CATALOG.md` v1.

## Catalog structure

A catalog has **personas** and **entries**. A persona is one consistent fake
identity — stack, headers, error style, file layout all agree, because
inconsistency is how an attacker spots a trap. v1 ships three personas
(`laravel-staging`, `legacy-cpanel`, `node-api-dev`) and six entries:

| id | persona | path |
| --- | --- | --- |
| `env-file-staging` | laravel-staging | `/.env` |
| `git-config-staging` | laravel-staging | `/.git/config` |
| `admin-panel-legacy` | legacy-cpanel | `/admin/login` |
| `debug-endpoint-legacy` | legacy-cpanel | `/debug` |
| `api-docs-dev` | node-api-dev | `/api/docs` |
| `source-map-dev` | node-api-dev | `/app.js.map` |

Each entry carries a `status`, `content_type`, extra `headers`,
`size_cap_bytes`, a body template, `leads` and `honeytokens`.

## Leads and honeytokens

Both are traps inside a served decoy, at different depths:

- A **lead** is a path that exists only inside a decoy response — the log
  file named in the fake `.env`, the `/admin/login/verify` action of the
  fake panel. Following one fires `decoy_lead_follow` (40, high); on an
  unprotected path that is a ban. Leads are registered for a session only
  when that decoy is served to it.
- A **honeytoken** is inert credential material minted into the body per
  session. The `token_alnum_24` format is deterministic:
  `"mrg_live_" + sha256(session_key + ":" + entry_id + ":" + token_id)[:24]`
  — so a token names its session, entry and slot without a database. Using
  the exact string anywhere Mirage can see (Authorization header, body
  keys, query) fires `honeytoken_use` (50, high) and proves which decoy
  leaked. Every format lives in the `mrg_` namespace that no real service
  issues, or uses reserved hosts (I14); formats are catalogued in
  `data/token-formats.md`.

## When a decoy is served

Only on a `decoy_route` verdict — never on `tag`, `throttle` or `ban`,
which record and act but do not serve. `look` mode caps every verdict at
`tag`, so no decoy is ever served there; `tripwires` and `protect` serve.
Protected routes are never decoyed (I4), verified bots and ordinary
visitors never see a decoy (I12), and every response carries
`X-Robots-Tag: noindex, nofollow, noarchive` regardless of template
headers, plus robots.txt disallow and absence from sitemaps.

## Render determinism

Bodies are templates with `{% raw %}{{SEED:*}}{% endraw %}` and `{% raw %}{{TOKEN:*}}{% endraw %}` slots. Seeds derive
from `sha256(session_key + ":" + entry_id + ":seed:" + spec + ":" + k)`,
where `k` counts occurrences of that spec string in the body — two
identical slots never render the same value, and the derivation is
byte-identical across the Go and TypeScript engines. Formats:
`{% raw %}{{SEED:N_HEX}}{% endraw %}` (first N hex chars, N ≤ 64), `{% raw %}{{SEED:N_B64}}{% endraw %}` (N unpadded
base64 chars, N a multiple of 4), `{% raw %}{{SEED:N_UPPER}}{% endraw %}` (N digest bytes folded
mod 36 over A-Z0-9). The rendered body of every entry for two fixed session
keys is pinned byte-for-byte by `spec/golden-vectors/renders.json`; both
engines must reproduce it exactly, and CI fails on any divergence.

## The pollution suite

Every decoy change runs it (I12–I15): crawl the test site as a verified
search bot and assert zero decoy URLs and zero hidden links; assert the
noindex header set on every decoy response; run secret scanners and format
validators over the rendered catalog to prove no live-valid credential
patterns, real personal data or real domains; assert depth, size and
connection caps under load; and a feed-poisoning test proving forged
reports produce no ban.

## Writing your own entry

Entries are YAML and the lowest-barrier contribution. A realistic addition
to the shipped catalog:

```yaml
personas:
  - id: wordpress-staging
    story: "WordPress 6.4 on PHP 8.1, staging"
    headers:
      - "X-Powered-By: PHP/8.1.29"

entries:
  - id: db-dump-staging
    persona: wordpress-staging
    path: /backups/staging-db.sql.gz
    status: 200
    content_type: text/plain
    size_cap_bytes: 1024
    body: |
      -- WordPress database dump (staging)
      -- dump id: {% raw %}{{SEED:12_UPPER}}{% endraw %}
      -- restore token: {% raw %}{{TOKEN:restore_key}}{% endraw %}
      --
      -- [binary payload truncated]
    leads:
      - /backups/staging-db.sql.gz.1
    honeytokens:
      - id: restore_key
        format: token_alnum_24
```

The rules the loader enforces: paths must not collide with real routes,
`/.well-known/**`, robots.txt, sitemaps or health checks (`mirage init`
checks at install time); bodies are inert — no scripts, no redirects, no
third-party links (I8, I14); hostnames come from reserved namespaces only
(`example.com`, `.test`, `.invalid`, the RFC 5737 ranges); no real brands
beyond technology-stack markers; no prose content, only technical artifacts
(I13). Validate with `go test ./internal/decoy/` — changes to the shipped
catalog also update the render fixture, and both engines' suites must stay
green.

Serving rules are decided by the [verdicts]({{ site.baseurl }}/guide/verdicts.html)
ladder; audience rules by [modes]({{ site.baseurl }}/guide/modes.html).
