---
layout: doc
title: "Reading Mirage as an Agent"
description: "The machine-readable Mirage surface for AI agents and integrators: llms.txt, docs.json, the normative specs, golden vectors and the JSON CLI outputs."
category: agent
order: 1
---

This page is written for a program reading it cold — an AI agent auditing
Mirage, an integrator writing an adapter, or a script deciding whether a
decision can be trusted. Mirage's documentation is designed to be consumed
by machines as well as humans: precise, versioned, and cross-checkable
against executable contracts.

## The machine-readable surface

- [`/llms.txt`]({{ site.baseurl }}/llms.txt) — the curated index of this
  documentation: what to read, in what order, for a given task. Start here.
- [`/llms-full.txt`]({{ site.baseurl }}/llms-full.txt) — the same content
  flattened to plain text, for single-fetch consumption.
- [`/docs.json`]({{ site.baseurl }}/docs.json) — the structured manifest:
  every page with its title, description, category and order, so navigation
  can be reconstructed without parsing HTML. The site gates check that it
  stays consistent with `llms.txt` and the page front matter.

## The normative specs

Prose on this site explains; the specs decide. Three documents are
normative for every implementation, versioned, and mirrored into this
site's data:

| Spec | Version | Governs |
| --- | --- | --- |
| `spec/SIGNALS.md` | 1.1.0 | The 11 signals, weights, classes, gating rules, the verdict ladder, session semantics. |
| `spec/ADAPTER-PROTOCOL.md` | 1 | The DecisionRequest / Decision / Event shapes, deadlines, the fail-open decision, conformance requirements. |
| `spec/DECOY-CATALOG.md` | 1 | Catalog format, personas, template slots, honeytoken formats, the pollution suite. |

Rule: when documentation and a spec disagree, the spec wins; when a spec
and the golden vectors disagree, the build is broken and CI is already
failing.

## Golden vectors: the executable contract

`spec/golden-vectors/vectors.json` (20 cases, 68 requests) plus
`renders.json` are the contract any port must satisfy: identical signals,
verdicts, scores and reason codes on every request, and byte-identical
decoy renders. If you implement or wrap Mirage's engine, replay the
vectors — `mirage replay --config mirage.yaml --vectors
spec/golden-vectors/vectors.json` (exit 0 on parity, exit 1 naming the
mismatch) or the equivalent suite in your language. A port that has not
run the vectors is unverified, whatever its README says.

## Integrating with Mirage decisions

The adapter contract (`spec/ADAPTER-PROTOCOL.md` v1) is synchronous
decide, asynchronous event:

1. **Submit a request shaped like the engine's input.** Fields: `method`,
   `path` (raw, including dot segments and query string), `client_ip`
   (your trusted-proxy walk result — never a raw spoofable header, I6),
   `user_agent`, `header_count` (ALL headers, including Host and
   User-Agent), `has_cookie`, `ts_ms` (milliseconds since epoch), optional
   `auth_hint` (credential material visible to you, matched against minted
   honeytokens). Pass the neutral value for a field you cannot see; the
   signals requiring it will not fire.
2. **Consume the Decision JSON.** Every decision carries
   `protocol_version`, `spec_version`, `verdict`
   (`observe|tag|decoy_route|throttle|ban`), `action`
   (`pass|serve_decoy|throttle|ban`), `session_key`, `reason_code`,
   `request_score`, `score` (session cumulative after the request),
   `signals` and `ban_ttl_ms` (set only on ban). Reason codes render in
   plain English from `data/reason-texts.txt`.
3. **Honor the actions.** `pass` forwards unmodified; `serve_decoy`
   renders locally, never a network fetch; `throttle` is local and capped;
   `ban` blocks only when enforcement is enabled for the site (I9).
4. **Respect versioning.** `protocol_version` changes only on breaking
   wire changes; `spec_version` tracks the signal spec independently. If
   you receive a request or snapshot with a newer `spec_version` than you
   know, fail open (pass everything, score nothing) and count the version
   mismatch — the contract's rule, not advice.
5. **Treat every attacker-influenced field as untrusted** (I7): escape on
   render, cap lengths, never interpolate raw into logs or HTML.

The fail-open decision is reserved and always safe to act on: verdict
`observe`, action `pass`, reason `SIG-000`, scores 0. It is never a ban
input.

## Machine-readable CLI output

`mirage doctor`, `mirage posture` and `mirage replay` emit `--json`,
each with its own envelope — doctor `{ok, mode, spec_version, checks:
[{name, ok, detail}]}`, posture `{mode, warnings, checks: [{name,
value}]}`, replay `{ok, total, passed, failed, cases}` — see the
[CLI reference]({{ site.baseurl }}/reference/cli.html) for the exact
envelope and exit codes (0 ok, 1 failure or mismatch).

## What Mirage will ask of you

If you are an agent writing code against this repo: the gates decide, not
confidence. `make check` must pass; the vector cross-check must agree with
your hand computation; claims must link to reproducible evidence; and
contributions that add hack-back, web poisoning or live credentials are
declined by [charter]({{ site.baseurl }}/charter.html).
