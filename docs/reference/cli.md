---
layout: doc
title: "CLI Reference"
description: "The mirage CLI: serve, doctor, init, posture, replay and version, with flags, exit codes and the --json output shapes."
category: reference
order: 3
---

The `mirage` binary has six subcommands. `--config FILE` names the site
config on every subcommand that takes one — required on `serve`, `doctor`,
`posture` and `replay` (no default), and the file to write on `init`
(default `mirage.yaml`); `version` takes no flags. Exit codes are
uniform: **0** success, **1** failure or mismatch — the same convention
as the repo's quality gates, so scripts can trust a single check.

## mirage serve

```bash
mirage serve --config mirage.yaml --upstream http://127.0.0.1:9000
```

Runs the core: loads and validates the config (strict — a bad config
exits 1 before serving anything), then runs two servers. The proxy binds
`listen`, scores every request that reaches it, forwards traffic to the
upstream, serves decoys per mode and drives enforcement and connectors.
The token-guarded dashboard binds its own loopback address
(`/healthz`, `/api/status`, `/api/events`, `/api/sessions`, `/api/bans`,
`POST /api/bans/revoke`). Any internal failure during a decision answers
`pass` to the request (I1).

| Flag | Default | Meaning |
| --- | --- | --- |
| `--config FILE` | required | Site configuration file |
| `--upstream URL` | required | Upstream origin URL the proxy forwards to — there is no upstream key in the config |
| `--listen ADDR` | the config's `listen` (`127.0.0.1:8080`) | Proxy listen address |
| `--dashboard-addr ADDR` | `127.0.0.1:8090` | Dashboard listen address — loopback only, non-loopback binds are refused |

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

| Flag | Default | Meaning |
| --- | --- | --- |
| `--config FILE` | required | Site configuration file |
| `--json` | `false` | Emit machine-readable JSON instead of the check table |

## mirage init

```bash
mirage init
mirage init --config path/to/mirage.yaml --force
```

Writes a minimal valid config — `mode: "look"` and a crypto/rand
`dashboard_token` are the only keys; every other key keeps its
documented default — and loads the written file back through strict
validation before reporting success. Init checks nothing else: the
decoy-path rules are the catalog loader's, enforced when a catalog is
loaded, not at install time. Exits 1 if the target exists (unless
`--force`) or the generated file fails validation.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--config FILE` | `mirage.yaml` | Configuration file to write |
| `--force` | `false` | Overwrite an existing file |

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

| Flag | Default | Meaning |
| --- | --- | --- |
| `--config FILE` | required | Site configuration file |
| `--json` | `false` | Emit machine-readable JSON instead of the report |

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

| Flag | Default | Meaning |
| --- | --- | --- |
| `--config FILE` | required | Site configuration file |
| `--vectors PATH` | `spec/golden-vectors/vectors.json` | Golden vector file to replay |
| `--json` | `false` | Emit machine-readable JSON instead of the per-case lines |

## mirage version

```bash
mirage version
```

Prints the build version; it accepts no flags. The decision protocol the
build speaks is version `1` and the signal spec is `1.1.0` — the same
versions carried in every Decision, so a deployed binary can be matched
to its spec revision.

## Notes for scripting

- `--json` exists on `doctor`, `posture` and `replay` only; `serve` logs,
  `init` writes a file, `version` prints one line.
- `--config` is required on `serve`, `doctor`, `posture` and `replay`;
  on `init` it selects the file to write (default `mirage.yaml`);
  `version` accepts none.
- An unknown flag or subcommand is an error (exit 1), matching the
  fail-closed-at-boot discipline of the config loader.
- Machine consumers should read the [agent
  page]({{ site.baseurl }}/agent/) for the full machine-readable
  surface.
