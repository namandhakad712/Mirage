---
layout: doc
title: "CLI Reference"
description: "The mirage CLI: serve, doctor, init, posture, replay and version, with flags, exit codes and the --json output shapes."
category: reference
order: 3
---

The `mirage` binary has six subcommands. One global flag applies
everywhere: `--config FILE` selects the site config (default `mirage.yaml`
where the command accepts it). Exit codes are uniform: **0** success,
**1** failure or mismatch — the same convention as the repo's quality
gates, so scripts can trust a single check.

## mirage serve

```bash
mirage serve --config mirage.yaml
```

Runs the core: loads and validates the config (strict — a bad config exits
1 before serving anything), binds `listen` (default `127.0.0.1:8080`),
scores every request that reaches it, serves decoys per mode, drives
enforcement and connectors, and serves the token-guarded dashboard
(`/healthz`, `/api/status`, `/api/events`, `/api/sessions`, `/api/bans`,
`POST /api/bans/revoke`). Any internal failure during a decision answers
`pass` to the request (I1).

## mirage doctor

```bash
mirage doctor --config mirage.yaml
mirage doctor --config mirage.yaml --json
```

Validates a config file without serving: strict decoding, every policy
bound, the dashboard-token requirement, mode/enforcement consistency,
connector completeness. Human output lists each check; `--json` emits the
machine form. Shape:

```json
{
  "ok": true,
  "mode": "look",
  "checks": [
    {"name": "dashboard_token", "status": "pass", "detail": "present"},
    {"name": "protected_routes", "status": "pass", "detail": "5 routes"}
  ]
}
```

`ok` is true only when every check passed; the process exits 0 on ok, 1
otherwise. (The JSON block above shows the shape of the envelope — field
values are illustrative.)

## mirage init

```bash
mirage init
mirage init --config path/to/mirage.yaml
```

Writes a minimal valid config, including a generated dashboard token, and
refuses decoy paths that collide with real routes, `/.well-known/`,
robots.txt, sitemaps and health checks (I4). Exits 1 if the target exists
or a collision is found.

## mirage posture

```bash
mirage posture --config mirage.yaml
mirage posture --config mirage.yaml --json
```

Reviews the site's effective posture from its config: mode, enforcement
state, budgets, protected routes and connector readiness, reported as the
same `ok` / `mode` / `checks[]` envelope as doctor. Use it before moving
up the [mode ladder]({{ site.baseurl }}/guide/modes.html) — it answers
"what would this config actually do" without booting the server.

## mirage replay

```bash
mirage replay --config mirage.yaml --vectors spec/golden-vectors/vectors.json
mirage replay --config mirage.yaml --vectors path/to/cases.json --json
```

Replays a vector file through the real engine and config, comparing every
expected field (signals, verdict, score, reason code) the way the test
suites do. Exit 0 only on full parity; exit 1 names the first mismatch and
counts the rest. `--json` emits the run summary — the `ok` / `mode` /
`checks[]` envelope, with the vector run reported as checks covering each
case. This is the command for verifying a modified config or catalog
against the executable contract before deploying.

## mirage version

```bash
mirage version
```

Prints the build version. The decision protocol the build speaks is
version `1` and the signal spec is `1.1.0` — the same versions carried in
every Decision, so a deployed binary can be matched to its spec revision.

## Notes for scripting

- `--json` exists on `doctor`, `posture` and `replay` only; `serve` logs,
  `init` writes a file, `version` prints one line.
- Every subcommand accepts `--config`; for `init` it selects the file to
  write.
- An unknown flag or subcommand is an error (exit 1), matching the
  fail-closed-at-boot discipline of the config loader.
- Machine consumers should read the [agent
  page]({{ site.baseurl }}/agent/) for the full machine-readable
  surface.
