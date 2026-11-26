# Security Policy

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository:
Security tab → "Report a vulnerability" (directly:
<https://github.com/namandhakad712/Mirage/security/advisories/new>).
There is no email address to use instead, and public issues are the wrong
channel for anything exploitable — a public report is itself an attack
surface for Mirage-protected sites.

Please include what you found, how you reproduced it, the affected commit,
and any logs or requests that pin the behavior. You will hear back from a
maintainer on the advisory thread.

## Supported versions

The **`main` branch only**. Mirage has no tagged releases yet; the
[CHANGELOG](CHANGELOG.md) tracks what exists at any point. Security fixes
land on `main` first and oldest first if backports ever become necessary.

## Scope

In scope:

- Everything under `internal/` (the Go core: config, detection engine,
  decoy data layer, enforcement, connectors, store, model).
- `packages/mirage-worker/` (the Cloudflare Worker).
- The decoy catalog (`spec/decoy-catalog/`) and shared data (`data/`) as
  safety-relevant content.
- The build and CI layer itself (a gate that can silently pass is a
  vulnerability in a security project).

Out of scope:

- **Tripping a decoy.** Decoys are inert by design (I8); probing one on a
  Mirage-protected site is expected behavior, not a bug. They carry no
  public marker by design — see
  [docs/adr/0001-no-public-decoy-marker.md](docs/adr/0001-no-public-decoy-marker.md).
- Reconnaissance *against Mirage-protected sites* that Mirage
  deliberately does not stop. Decoys catch scouting, not exploits; see
  [docs/known-limits.md](docs/known-limits.md) before reporting a
  "protection gap" that is a documented limit.
- Anything in a fork or deployment configured contrary to the documented
  defaults.

## What is security-sensitive in this project

- **The `mrg_` honeytoken namespace.** Mirage mints honeytokens in
  formats that no real provider issues (`mrg_live_…`, `mrg_bearer_…`,
  `mrg-pw-…`, `AKIAMRG…` — the full list with inertness guarantees is
  [data/token-formats.md](data/token-formats.md), I14). If you encounter
  an `mrg_`-shaped credential, it is an inert Mirage decoy, not a leaked
  live credential. **Do** report any way one of these formats could
  validate against a real service — that breaks the inertness guarantee
  the whole project rests on.
- **Reserved hosts and ranges.** All decoy content must stay inside the
  reserved names and networks in
  [data/reserved-hosts.txt](data/reserved-hosts.txt) (`example.com`,
  `*.test`, `*.invalid`, … and RFC 5737 ranges `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`, I14). Any decoy referencing a
  real host, brand, or non-reserved address is a reportable violation —
  the catalog validation and pollution suite enforce this, but reports
  are welcome anyway.
- **Dashboard token handling.** The dashboard requires a token even on
  loopback (a hard validation rule, not advice), and the token must be
  redacted before any log or debug dump (`Config.Redacted()`, I11).
  Anything that can log or leak the dashboard token, a connector
  credential, or a signed webhook secret is a reportable finding (I11:
  connector tokens live only in environment variables, never in the
  config file or the repo).
- **Client-IP derivation.** The trusted-proxy walk (I6) decides who can
  be banned. A way to spoof a client IP through a non-trusted peer, or
  to get an innocent shared address banned (I15), is a high-severity
  report.
