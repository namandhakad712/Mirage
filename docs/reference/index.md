---
layout: doc
title: "Reference"
description: "The Mirage reference shelf: every configuration key, every CLI subcommand, the shared data files, and the normative specs."
category: reference
order: 1
---

The reference pages are complete enumerations, not tutorials. Each one
walks its source file key by key or command by command, so a claim made
anywhere else in this documentation can be checked here against the exact
default, bound or flag. If a number on a guide page and a number here ever
disagree, this page and the file it mirrors are wrong together with it —
file that as a bug.

| Page | What it enumerates |
| --- | --- |
| [Configuration]({{ site.baseurl }}/reference/config.html) | Every key of `mirage.example.yaml` — type, default, validation bound, what it controls, and the invariant behind it. |
| [CLI]({{ site.baseurl }}/reference/cli.html) | The `mirage` subcommands: `serve`, `doctor`, `init`, `posture`, `replay`, `version` — flags, exit codes and `--json` shapes. |

## The shared data files

Policy lives in `data/`, shared verbatim by the Go core and the TypeScript
worker (the worker's build regenerates its snapshot from these files, so
the two engines can never drift):

| File | Contents |
| --- | --- |
| `data/scanner-paths.txt` | The scanner path list behind `scanner_path` (SIG-101). |
| `data/ua-suspicious.txt` | Attack-tool user-agent substrings behind `ua_suspicious` (SIG-106). |
| `data/ua-verified-bots.txt` | Verified-bot hints; a match marks the request never-scored. |
| `data/reserved-hosts.txt` | Reserved hostnames and ranges permitted in decoy content (I14). |
| `data/token-formats.md` | The inert honeytoken formats (the `mrg_` namespace). |
| `data/reason-texts.txt` | Plain-English renderings for every reason and verdict code (I10). |

## The spec library

The normative documents every implementation must satisfy. Changes bump
the recorded version and regenerate the golden vectors:

| Spec | Version | Governs |
| --- | --- | --- |
| `spec/SIGNALS.md` | 1.1.0 | The 11 signals, weights, classes, gating, the verdict ladder, session semantics. |
| `spec/ADAPTER-PROTOCOL.md` | 1 | The DecisionRequest / Decision / Event contract, deadlines, fail-open, conformance. |
| `spec/DECOY-CATALOG.md` | 1 | The catalog format, personas, template slots, honeytoken formats, the pollution suite. |
| `spec/golden-vectors/` | — | The executable contract: 20 cases / 68 requests, plus the render fixture. |

For prose that explains rather than enumerates, start at the
[guide index]({{ site.baseurl }}/guide/index.html). For machine-readable
consumption of this documentation, see
[Reading Mirage as an agent]({{ site.baseurl }}/agent/index.html).
