---
layout: doc
title: "Invariants"
description: "I1-I15: the properties every line of Mirage must preserve, and the tests that hold them."
category: project
order: 4
---
These fifteen invariants are binding. Every feature, pull request and agent
run is checked against them, and at least one test exists for each one. A
human maintainer can waive one only through a recorded ADR in `docs/adr/`.

## I1 — Fail-open

Any internal failure — crash, timeout, bad config, full disk — sends traffic
to the origin unmodified. Mirage must never be the reason a site is down.

*Test hooks:* fault-injection suite (`lab/faultinject`) kills Core, corrupts
config and stalls the store while asserting the pass-through path stays clean.

## I2 — Never in the asset path

The customer's JavaScript bundle and pages never depend on Mirage to load.
This is the key difference from a hosted "serve your bundle through us" mode.

*Test hooks:* adapter conformance suite asserts pages render with Mirage
removed entirely; no `<script>` for Mirage on real routes.

## I3 — Hot path is local

No network call, disk wait or LLM call while handling a request. Decisions
come from an in-memory snapshot, under a hard deadline. Loopback / unix
socket calls to a local process with a hard deadline are allowed; remote
calls are not. On timeout the adapter passes the request through.

*Test hooks:* deadline-guard tests force a slow snapshot and assert the
verdict degrades to observe + pass-through within the deadline budget.

## I4 — Protected routes

Login, checkout, API prefixes and anything the owner lists are never decoyed
or throttled by decoy logic: the engine caps the verdict at `tag` on any
protected route. The decoy catalog loader separately rejects duplicate
entry paths and leads that would claim `/.well-known/` or collide with an
entry path.

*Test hooks:* golden vectors v05/v09/v19 assert cap behavior; the pollution
suite asserts no decoy appears on protected routes.

## I5 — Bans are earned

High-confidence signals only, short TTL, budget-capped, one-click reversible,
always with reason codes. Structure signals alone can tag and throttle, never
ban.

*Test hooks:* vector set asserts no structure-only sequence reaches ban;
enforce tests assert budget caps and reversibility.

## I6 — Trusted client IP

The real client IP is read only from proxies the owner explicitly trusts
(uniformly, walking the chain right-to-left). Otherwise an attacker spoofs a
header and gets innocent users banned.

*Test hooks:* `internal/model` IP-extraction table tests cover chained
spoofing; never-scored ranges (own IPs, CDN ranges) are listed in data.

## I7 — Attacker data is hostile

Every header, path and body that reaches logs, the dashboard or exports is
untrusted input: escaped on output, length-capped, log-injection-safe.

*Test hooks:* XSS/HTML-escaping tests on every render path; log-injection
tests assert newlines and control characters cannot forge entries.

## I8 — Decoys are inert

Synthetic data only. Never real data, nothing executable, nothing that acts
on the visitor's machine, no redirects to third parties.

*Test hooks:* decoy validate suite rejects executable content, redirects and
real-looking credentials.

## I9 — Observe by default

Enforcement is opt-in per site, and there is a global kill switch.

*Test hooks:* config tests reject configs that enable enforcement without an
explicit opt-in block; kill-switch tests assert DropToObserve within one
interval.

## I10 — Everything is explainable

Each automated action stores its evidence: signals fired, weights, verdict,
reason code, session key. Plain-English reason texts ship in `data/reason-texts`.

*Test hooks:* every vector expectation carries a reason code; service tests
assert stored events reference them.

## I11 — Least privilege

Connector tokens are scoped, never logged, never in the repo. Secrets come
from the environment or a secret store.

*Test hooks:* slop/secret grep gates the repo; connector tests assert tokens
never appear in logs or errors.

## I12 — No pollution of the public web

Decoys are never indexable (`X-Robots-Tag: noindex, nofollow, noarchive`,
robots.txt disallow, absent from sitemaps), never served to verified search
engines, archivers or ordinary visitors, and served only to sessions already
scored suspicious. Hidden-link injection never reaches verified crawlers.

*Test hooks:* pollution suite crawls the test site as a verified bot and
asserts zero decoy URLs; header assertions on every decoy response.

## I13 — No misinformation, no junk content

Decoys are inert technical artifacts — config files, fake admin shells, error
pages — never articles, facts or claims about real people, brands or
products. No plausible prose pages. Content scrapers are blocked or
rate-limited; they are never fed garbage.

*Test hooks:* catalog validation rejects prose-style decoys; brand/domain
lint over the whole catalog.

## I14 — No third-party harm

Honeytokens never contain credentials that could work on a real service:
formats that cannot validate, or registered canary tokens owned by the site
owner. Decoy hostnames use reserved names only (`example.com`, `.test`,
`.invalid`) and reserved ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
No real brand names, no real personal data, no outbound links, no redirects.

*Test hooks:* secret scanners and format validators run over the decoy
catalog; reserved-host lint; vectors use reserved IPs only.

## I15 — Blocklist hygiene

Bans are local, short and expiring by default. Shared feeds, if ever offered,
are opt-in, signed, corroborated, expiring, with appeals. Shared and
carrier-grade NAT addresses, CDN ranges and addresses with recent legitimate
sessions are never banned by default. Tor and VPN exits are tagged, not
banned. A default ban covers a single address for minutes to hours, never a
range.

*Test hooks:* never-ban range table tests; ban record TTL tests; a
feed-poisoning test asserts forged reports produce no ban.

---

## Source

Derived from the production design (Part I section 1, Part II section 18),
which is reproduced in full at `docs/design/MIRAGE-DESIGN.md`. Invariants are
numbered and quoted there; this file is the normative copy the gates check
against.
