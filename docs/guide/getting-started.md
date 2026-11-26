---
layout: doc
title: "Getting Started"
description: "From a fresh clone to a running look-mode Mirage instance: build, gates, minimal config, serve, and reading your first events."
category: guide
order: 2
---

This page takes you from zero to a running look-mode instance. Look mode
observes and records only — no decoys are served, nothing is enforced (I9) —
so it is the safest starting point and the default. For the Cloudflare
Worker deployment path, read
[the worker guide]({{ site.baseurl }}/deploy/cloudflare-worker.html); this
page covers the Go core and its CLI.

## Prerequisites

- **git** and **GNU make**.
- **Go 1.23 or newer** — the module pins `go 1.23.0`.
- **Python 3 with PyYAML** — only for the golden-vector gate
  (`tools/gen_vectors.py` imports `yaml`).
- **Node 20 or newer and npm** — only for the worker package; no Go gate
  needs network access.

## 1. Get the code and run every gate

```bash
git clone https://github.com/namandhakad712/Mirage.git
cd Mirage
make check
```

`make check` runs, in order: `fmt-check` (fails if any Go file is not
gofmt-clean), `vet` (`go vet ./...`), `build` (`go build ./...`),
`test` (`go test -race ./...`), `vectors` (regenerates the golden vectors
and cross-checks the two independent sources in `tools/gen_vectors.py`; the
generator exits 1 on any disagreement), and `slop` (the grep gate that
rejects unfinished-work markers in code files). If `make check` is green you
hold the same evidence CI produces on main — deterministic gates, not trust.
See [tooling]({{ site.baseurl }}/guide/tooling.html) for what each target
runs.

## 2. Write a minimal config

```bash
mirage init --config mirage.yaml
```

`mirage init` writes a minimal valid config (it also refuses decoy paths
that collide with real routes, `/.well-known/`, robots.txt, sitemaps and
health checks — I4). Open `mirage.yaml` and make two decisions:

- **`dashboard_token`** — required, and required even though the default
  `listen` is loopback: an unauthenticated local endpoint is one `curl`
  away from a takeover. Generate one and paste it in:

  ```bash
  openssl rand -hex 32
  ```

- **`mode`** — leave it at `look`.

Every key, default and bound is documented in the
[config reference]({{ site.baseurl }}/reference/config.html). Loading is
strict: a typo, an unknown key or a half-configured connector block is a
boot-time error, never a silently disabled control.

Validate before running:

```bash
mirage doctor --config mirage.yaml
```

Exit 0 means every check passed; exit 1 means at least one failed, and the
failure is named. Add `--json` for machine-readable output (see the
[CLI reference]({{ site.baseurl }}/reference/cli.html)).

## 3. Run it

```bash
mirage serve --config mirage.yaml
```

Mirage binds `listen` (default `127.0.0.1:8080`), scores every request
that reaches it, and serves the token-guarded dashboard on the same
address. In a second terminal, confirm the process is alive:

```bash
curl -s http://127.0.0.1:8080/healthz
```

`/healthz` is the one tokenless endpoint — the load-balancer probe — with
a fixed body and nothing else.

## 4. Generate a benign request and a scanner path

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/.env
```

Score both requests the way the engine does. The first is ordinary: a bare
`curl` sends three headers (Host, User-Agent, Accept), which fires
`headers_sparse` (10, medium) — under the tag threshold of 15 — so the
verdict is `observe`. The second matches `data/scanner-paths.txt`, firing
`scanner_path` (25, high, `SIG-101`); because a signal from the ungating
set fired the same request, `tooling_curl` (15) fires too: request score
25 + 15 = 40. In look mode the verdict is capped at `tag` and the action
is always `pass` — both requests reach the origin unmodified (I1, I9).
What changes is the record.

## 5. Read the events

```bash
TOKEN="paste-the-dashboard_token-value"
curl -s -H "X-Mirage-Dashboard-Token: $TOKEN" http://127.0.0.1:8080/api/events
```

The token also rides as `Authorization: Bearer ...`. `/api/events` returns
recorded decisions; each event carries `ts_ms`, `session_key`, `method`,
`path` and the full decision — signals, request score, cumulative score,
verdict, reason code. The other endpoints are `/api/status`,
`/api/sessions` and `/api/bans`. Reason codes render in plain English from
`data/reason-texts.txt` (I10).

Where events go: emission is a bounded queue write that never blocks a
request (I3); a drainer moves them into the store — SQLite in WAL mode at
`store.path` (default `mirage.db`), kept for `store.retention_days`
(default 30) — and the dashboard reads the store.

## Where to go next

- [Signals]({{ site.baseurl }}/guide/signals.html) — what each score means.
- [Modes]({{ site.baseurl }}/guide/modes.html) — when to move up a rung.
- [Deploy: nginx]({{ site.baseurl }}/deploy/nginx.html) — the
  transparent-proxy topology for real traffic.
