---
layout: doc
title: "Production Design"
description: "The full design document Mirage is built from: architecture, modes, data flow, failure philosophy."
category: project
order: 8
---
Working codename (rename freely) · Design draft v0.1 · November 20, 2026

## 0. Framing: what we are really building

Mirage is a small trusted core plus a lot of carefully engineered glue. The detection ideas, honeypots, WAFs and ban lists already exist. Our product is three things: it never breaks the site it protects, it is honest about what it can and cannot stop, and it works in minutes instead of days.

Because the glue is ours, every decision below starts from one question: when this piece fails, what happens to the user’s website? The answer must always be: nothing bad.

Scope honesty:

- Decoys and tripwires catch noisy reconnaissance and raise attacker cost. They do not stop an agent that goes straight to a real vulnerability. We never say ‘stops ARTEX’; we say ‘detects scouting and wastes attacker effort’.
- No hack-back, ever. Passive deception only.
- ‘Not an MVP’ means every release is production-grade and gated, not that everything ships at once. Version 1.0 is defined by exit criteria (section 12), not by a date.

## 1. Non-negotiable invariants

These are the constitution. Every feature, PR and agent is checked against them, and a test exists for each one.

- I1 Fail-open. Any internal failure (crash, timeout, bad config, full disk) sends traffic to the origin unmodified.
- I2 Never in the asset path. The customer’s JavaScript bundle and pages never depend on Mirage to load. This is the key difference from a hosted ‘serve your bundle through us’ mode.
- I3 Hot path is local. No network call, disk wait or LLM call while handling a request. Decisions come from an in-memory snapshot, under a hard deadline.
- I4 Protected routes. Login, checkout, API prefixes and anything the owner lists are never decoyed or throttled by decoy logic.
- I5 Bans are earned. High-confidence signals only, short TTL, budget-capped, one-click reversible, always with reason codes.
- I6 Trusted client IP. The real client IP is read only from proxies the owner explicitly trusts. Otherwise an attacker could spoof headers and get innocent users banned.
- I7 Attacker data is hostile. Every header, path and body that reaches logs, the dashboard or exports is untrusted input.
- I8 Decoys are inert. Synthetic data only, never real data, nothing executable, nothing that acts on the visitor’s machine.
- I9 Observe by default. Enforcement is opt-in per site, and there is a global kill switch.
- I10 Everything is explainable. Each automated action stores its evidence.
- I11 Least privilege. Connector tokens are scoped, never logged, never in the repo.

## 2. Architecture

```
Internet ──► CDN/WAF (Cloudflare, etc.) ──► Mirage Edge ──► Your origin
                                               │              (always the fallback)
                                               │ async events, never blocking
                                               ▼
                                        Mirage Core
   ┌───────────┬────────────┬──────────────┬──────────┬───────────────┐
   Detection   Deception    Enforcement    Store      Dashboard + API
   engine      engine       connectors     (SQLite/   (separate
                                           Postgres)  process)
```

- Edge (data plane): a small static Go binary, or an adapter inside the owner’s existing edge (Cloudflare Worker, nginx or Caddy, Next.js or Express middleware). It only classifies, tags, routes to a decoy and emits an event. Everything else is async.
- Core (control plane): config, policy, decoy catalog, detection engine, connectors, store, dashboard and API. It is a separate process with separate credentials. If it dies, Edge keeps running on its last good snapshot.
- Language: Go. Single static binaries, memory safety, native fuzzing, and the same ecosystem as Caddy and CrowdSec.

Integration ladder. Each rung is useful alone and fully reversible:

1. Watch: tail existing nginx, Caddy or Cloudflare logs, or add a tiny async script tag. Zero traffic risk. Shows who scouts you.
2. Tripwires: decoy paths (/.env, /.git/config, fake source maps) routed to Mirage by one proxy rule. Real traffic untouched.
3. Edge adapter: per-request scoring and decoy routing inside your own edge.
4. Enforce: connectors ban or throttle, with budgets and a kill switch.

Moving up a rung is a config change. Moving down is deleting one line.

## 3. Detection and verdicts

Signals, each with a weight, a confidence class and a reason code:

- Decoy hit: a request to a path no real user requests. High confidence.
- Followed a decoy lead: requested a path that exists only inside a decoy response. Near certain.
- Honeytoken use: a fake credential planted in a decoy shows up anywhere Mirage can see.
- Structure: sparse or inconsistent headers, user-agent versus TLS fingerprint (JA3/JA4) mismatch, machine-regular timing, breadth-first path enumeration, IP or user-agent rotation.

Verdict ladder: observe → tag → decoy-route → throttle → short ban. Only the top confidence classes (decoy-lead follow, honeytoken use, or a strong combination) can ban. Structure signals alone can tag and throttle, never ban.

Allowlists beat every rule: verified search engines (reverse DNS plus forward confirmation), owner IPs, uptime monitors, CI.

The engine is deterministic and rule-based, with versioned rules. A replay tool re-runs yesterday’s traffic against a new rule set and diffs the verdicts before anything is enabled. A false-positive review queue feeds tuning. Optional LLM analysis runs offline on stored sessions for summaries and rule suggestions only, never inline.

## 4. Deception engine

- Decoy catalog: YAML templates for fake files and panels (env files, git configs, admin logins, backup listings, API docs, source maps, debug endpoints). Community packs, each reviewed.
- Decoy personas: every attacker session gets one consistent fake identity, for example ‘Laravel 10 on PHP 8.2 behind nginx, staging’. Headers, error pages, file contents, timestamps and fake IDs all agree within a session, because inconsistency is how an agent or its operator spots a trap. Seeded generation keeps each session deterministic and reproducible.
- Content generation: templates and seeded generators first. Optional LLM decoys are pre-generated offline, sanitized and cached, never generated per request.
- Honeytokens: fake API keys, database URLs and cloud keys in realistic formats, unique per decoy, so later use proves which decoy leaked. Optionally integrate a canary service (such as Canarytokens) for alerts outside our view.
- Tarpit with limits: slow responses and endless link trees, with hard caps on held connections per IP and globally, so the tarpit can never become our own denial of service.
- Prompt-injection bait aimed at LLM agents: off by default, labeled experimental. Its effectiveness against human-steered frameworks is unproven, and we will never ship anything that tries to command the attacker’s machine.
- Decoy safety rules: synthetic data only, no executable content, no redirects to third parties, sanitized output, no links to real routes, and consistency with robots.txt so well-behaved crawlers never meet a trap.

## 5. Enforcement connectors

Connector interface: Plan, Apply, Reconcile, Revoke, HealthCheck. Built-ins by priority: CrowdSec (decisions API), Cloudflare (IP lists or custom rules via scoped tokens), AWS WAF IP sets, an nginx or Caddy deny-map file, nftables, and a generic webhook.

Rules for every connector:

- Idempotent and queued, with retries, backoff, jitter and respect for 429s.
- A reconcile loop compares desired and actual state, so a missed call heals itself and expired bans are removed even after crashes. We compute TTLs ourselves and do not trust provider expiry.
- Budgets: max bans per minute, max concurrent bans, max share of recent traffic. Exceeding a budget drops the site to Observe automatically and alerts the owner. This stops a bug or an attack from turning Mirage into a self-inflicted outage.
- Never-ban list: private ranges, own IPs, CDN and load balancer ranges, allowlisted bots.
- Dry-run mode shows exactly what would be banned and why.
- Recorded-fixture contract tests, plus a nightly canary against a real sandbox account, with provider API versions pinned and a verified-on date.

## 6. State, memory and privacy

- Store: SQLite (WAL) by default, Postgres optional behind the same interface. Append-only event log, versioned schema, migrations with tested downgrades.
- Attacker session memory: a bounded in-memory LRU for hot decisions, plus persisted summaries for the dashboard and for personas that stay coherent across restarts.
- Retention is configurable and short by default, with an option to hash or truncate IPs. The design aims to be workable under data-protection laws such as GDPR and India’s DPDP Act, but owners must confirm their own obligations.
- Config as code: one schema-validated YAML file, signed snapshots to Edge, last-known-good always retained.
- Single-file export and import, with a tested restore.

## 7. Observability and dashboard

- Prometheus metrics, structured logs, OpenTelemetry traces, health and readiness endpoints.
- Heartbeat attacker: a built-in synthetic scanner touches a decoy every minute and verifies the whole pipeline (detect, store, connector plan). If heartbeats stop, we alert, because silent failure is the worst failure of a security tool.
- Dashboard, the part that can win people over: a clear ‘who scouted you today’ timeline, attacker sessions showing what they touched and how long we held them, the cost imposed on them, the ban ledger with reasons, and a false-positive queue with one-click allow and unban. Everything attacker-controlled is escaped (I7). Mobile friendly, calm and honest copy, no fear marketing.
- The dashboard has no write path into Edge. It only edits config, which Core validates and signs.

## 8. Failure-mode matrix

Format: failure → behavior → detection → recovery.

- Edge crashes or hangs → traffic bypasses to the origin (load balancer health check or adapter try/catch) → alert → supervisor restarts it, crash dump saved.
- Edge exceeds its deadline on a request → request forwarded unmodified → latency metric → investigate the slow rule.
- Core is down → Edge continues on the last-known-good snapshot, events buffered in a bounded ring (oldest dropped) → heartbeat gap alert → buffer replayed on recovery.
- Config invalid or tampered → rejected, previous snapshot kept → validation or signature alert → owner fixes it, `mirage doctor` explains.
- Store slow or disk full → events sampled and shed, enforcement unaffected → disk and queue metrics → retention purge and alert.
- Cloudflare, AWS or CrowdSec API errors → queued with backoff, local deny-map as fallback → connector health → reconcile loop heals.
- False-positive storm → ban budget exceeded, site drops to Observe automatically → page the owner → review queue, unban, tune.
- Decoy generator error → static fallback decoy or plain 404 → error metric.
- Clock skew → TTLs on monotonic time, idempotent expiry job → skew check in doctor.
- Bad release → staged channels, canary, auto-rollback on health regression → release gates → tested schema downgrade path.
- Dashboard down or compromised → no effect on Edge, separate process and credentials → health check → restart and rotate credentials.

## 9. Threat model of Mirage itself

- Attackers will target the tool: stored XSS through user-agent or path strings in the dashboard, log injection, SSRF through decoy features, header spoofing to frame innocent IPs, tarpit and connection exhaustion, config tampering, and abuse of the ban pipeline to ban the world.
- Supply chain: pinned and verified dependencies, a package allowlist, govulncheck and software-composition scanning in CI, reproducible builds, an SBOM, signed releases (Sigstore/cosign) and provenance.
- Hardening: dashboard auth with no default credentials (forced local admin setup, optional OIDC), CSRF protection, strict CSP, mTLS between Edge and Core, secrets from the environment or a secret store, minimal containers (distroless, non-root, read-only filesystem).
- Disclosure: SECURITY.md, private advisories, and a fix SLA we can honestly keep.

## 10. Easy integration, the smooth setup

- `mirage init` detects your stack (nginx, Caddy, Cloudflare, Vercel, Docker) and prints or applies the exact recipe.
- `mirage doctor` checks everything: trusted-proxy config, connector permissions, a dry-run ban, the heartbeat, and a real fail-open test (it stops Core and confirms your site still serves).
- Copy-paste recipes per platform, each tested in CI on real environments.
- Safe default: Observe mode with a seven-day report before the tool ever suggests enforcement.
- One-command uninstall that leaves nothing behind.

## 11. The Build Factory: how we keep the glue from failing

AI agents will write much of this, so the quality system matters as much as the code. Rule one: agents propose, deterministic gates decide. An LLM critic can share the implementer’s blind spots, so critics are advisory and never the only gate.

Personas, each with a written charter in the repo:

- Architect: owns the invariants and ADRs, vetoes designs that violate I1 to I11.
- Implementer: writes code to a spec.
- Test engineer: writes tests from the spec independently, without seeing the implementation.
- Adversary: tries to break the invariants (spoofed headers, ban-the-world, log injection, tarpit exhaustion) and ships every break as a regression test.
- Reviewer: line-level review against a checklist.
- Critic: design-level skeptic who asks ‘what if this fails’ and ‘what are we assuming’. Runs on a different model family from the implementer where possible.
- Slop Hunter: looks for AI slop. Invented APIs and packages, dead code, needless abstraction, tests that assert nothing or mock the thing under test, copy-paste duplication, vague names, comments that restate code, and in docs, marketing fluff and unverifiable claims.
- Release captain: verifies every gate, the changelog and signatures.

Factory memory lives in git, reviewed like code, never in hidden state:

- docs/adr/: decisions with reasons.
- docs/invariants.md: the constitution.
- docs/failure-ledger.md: every bug or incident becomes a regression test plus a lesson.
- docs/hallucination-list.md: APIs, flags and packages that agents wrongly invented.
- docs/vendor-notes/: pinned provider API versions with a verified-on date and an expiry, so stale notes get re-checked.

Agents receive a bounded context pack, not the whole repo history.

Strict passes. All must pass. Agents cannot waive a failure; only a human maintainer can, in a logged ADR:

0. Spec and invariant check.
1. Static: build, lint, types, gosec, govulncheck, dependency allowlist, and a check that every package really exists and is the intended one.
2. Unit and property tests, plus mutation testing with a minimum score, which exposes empty tests.
3. Connector contract tests (recorded fixtures, nightly live canary).
4. Fuzzing of every parser: headers, config, decoy templates, log formats.
5. Fault injection: kill Core, corrupt config, slow or full disk, provider 429 and 5xx, clock skew, and assert I1 holds in each.
6. Load and soak: a latency budget on the pass-through path and flat memory over 24 hours.
7. Adversarial suite built from the Adversary’s regression tests.
8. Slop review.
9. Independent Reviewer and Critic.
10. Human sign-off on security-critical paths via CODEOWNERS.
11. Release: signed artifacts, SBOM, provenance, staged channels (nightly, beta, stable), canary on our own sites first, auto-rollback on health regression.

Tiering keeps process from killing progress. Tier 1 (Edge, scoring, enforcement, config loader, auth) runs everything. Tier 2 (connectors, store) runs passes 1 to 7 and 9. Tier 3 (dashboard UI, docs, decoy content) runs passes 1, 2, 8, 9 plus the I7 escaping tests.

Loop control: iterations are capped per task. If the Implementer and Critic disagree twice, it escalates to the maintainer with both arguments. Track escaped defects, slop rate, flake rate and time to green.

Start small. For a solo maintainer, the deterministic CI gates plus the written invariants deliver most of the value. The agent orchestration is itself glue and can itself produce slop, so add it gradually.

## 12. Roadmap with exit criteria

- 0.1 Watch: log ingestion, decoy-hit detection, local dashboard. Exit: runs on your own sites for 14 days without touching traffic.
- 0.3 Tripwires: decoy paths, personas v1, honeytokens, heartbeat. Exit: fault-injection suite green, I1 demonstrated.
- 0.6 Edge: adapters (nginx or Caddy, Cloudflare Worker), replay tool, doctor. Exit: latency budget met, 7-day soak clean.
- 0.8 Enforce beta: CrowdSec and Cloudflare connectors, budgets, kill switch. Exit: ban-the-world and spoofing tests pass, 30 days of dogfooding with zero fail-open violations.
- 1.0: stable config schema, complete docs, signed releases, and an external security review or at least a public audit call. Exit criteria are evidence, not a date.
- After 1.0: AWS WAF, more adapters, community decoy packs, an optional shared threat feed (opt-in, privacy-reviewed).

## 13. Legal, ethics and governance

- Passive deception only. No hack-back, no executing code on attacker machines, no data collection beyond what the owner’s site already sees.
- License proposal: AGPL-3.0 for Core, Apache-2.0 for adapters and SDKs so they can be embedded anywhere.
- Governance: CODEOWNERS, contribution guide, security policy, code of conduct, and a claims policy: any performance or detection claim in the docs must link to a reproducible test.
- Pick the final name only after a trademark and repository conflict search.

## 14. Open decisions

1. The name (Mirage is a placeholder).
2. The first two adapters: where do your sites run (Cloudflare, Vercel, a VPS)?
3. The license split above.
4. Solo maintainer, or contributors from day one?

## Part II: Deeper plan (added November 20, 2026)

This part answers three questions: who this is for, how it applies to almost any server or hosting setup, and how we guarantee we never pollute the wider internet. It extends sections 1 to 14. The new invariants (I12 to I15) join the constitution in section 1.

### 15. Who this is for

Principle: anyone with something on the public web should be able to install this in minutes without being a security person. Reporting on ARTEX campaigns includes hospitals, schools and ordinary businesses, because one operator can aim an agent framework at many targets at once. So the audience is wide, but each segment gets a different first experience.

Segments, in the order we serve them:

1. Indie developers and small teams on a VPS or Docker host (nginx or Caddy in front). This is the sweet spot and the first target: they have root, logs and a process manager, and nobody else is watching their servers. Path: Watch, then Tripwires, then Enforce with CrowdSec.
2. Sites behind Cloudflare, free plan included. Mirage runs as a Worker adapter plus a Cloudflare connector, so even people with no server get the full ladder.
3. Students, portfolios and hobby projects on static or managed hosts (GitHub Pages, Vercel, Netlify, Render). No server access and often no logs. They get Watch through a Cloudflare front or an edge function, plus the posture check below. We are honest that there is little to steal on a static site, so for them the value is early warning and a safer setup, not heavy enforcement.
4. WordPress, PHP and shared-hosting owners (cPanel, .htaccess only). The most scanned population on the web. A plugin plus an .htaccess recipe, no root needed, with limited enforcement.
5. Startups and teams on cloud platforms (AWS, Kubernetes, managed ingress). Ingress middleware, WAF connectors, OpenTelemetry export, multi-environment config.
6. Agencies and service providers running many sites. Multi-site dashboard, per-client reports, strict least privilege. Service-provider tooling is itself a high-value target, so this segment gets the strictest hardening and never shares secrets across clients.
7. Security teams and researchers. Full API, SIEM export, rule authoring, the replay tool, and an easy way to contribute decoy packs.
8. Schools, nonprofits and open-source maintainers. Free forever, with the lowest-maintenance defaults.

Honest limits: Mirage protects public HTTP and HTTPS services. It does not cover SSH, databases or mail in version 1 (a later integration with existing SSH honeypots is possible), and a site entirely behind a login or private network gains less. ‘Applies to everyone online’ really means ‘applies to anyone with a public web surface’.

### 16. A feature for everyone: the posture check

For most owners the most valuable thing is not catching attackers but finding what attackers would find. Add a safe, read-only self-check:

- Is /.env, /.git/, a backup file, a source map, a directory listing or an admin panel reachable? Are security headers missing?
- Ownership verification first (a DNS TXT record or a token file), so the tool can never be used to scan other people’s sites. Rate-limited, GET and HEAD only, a fixed list of safe paths, no exploitation, no brute force.
- Plain-language output with copy-paste fixes for the user’s stack: an nginx rule, a Caddy matcher, an .htaccess line.

This matches the lesson from real campaigns: basic exposure is what gets exploited. It is also the best onboarding hook, because it shows value before any traffic is touched.

### 17. Universal deployment model

Four shapes cover nearly every setup:

- A. Log-tail: Mirage reads logs the server already writes. No traffic path, no risk.
- B. Adapter: a thin piece inside the owner’s existing proxy, CDN or framework.
- C. Standalone Edge: the Mirage Edge binary in front of the app, behind a TLS-terminating proxy such as Caddy. We do not terminate TLS ourselves in version 1, which keeps our attack surface small.
- D. Serverless Lite: the logic runs as an edge Worker with a small managed store, for people with no server at all. This needs a feasibility spike on free-tier limits before we promise it.

Choosing a shape takes three questions, asked by `mirage init`:

```
Can you put a proxy like Cloudflare in front (change DNS)?
   yes → Worker adapter (B or D) + Cloudflare connector
   no  ↓
Can you edit your web server config?
   yes → nginx / Apache / Caddy / Traefik adapter (B) + deny-map bans
   no  ↓
Can you install a plugin or middleware?
   yes → WordPress plugin or framework middleware (B)
   no  ↓
Can you read any server logs?
   yes → log-tail (A), Watch only
   no  → async script tag (Watch) + the posture check
```

Environment matrix. These are design targets; each recipe is verified against the vendor’s current docs at build time and recorded in docs/vendor-notes/:

- Cloudflare in front: Worker adapter, Cloudflare connector for bans. Full ladder.
- nginx: decoy locations proxied to Mirage, log-tail, a generated deny map for bans, reload on change.
- Apache and .htaccess: rewrite rules for decoys, a plugin or small handler for events, a generated deny file. Limited by what the host allows.
- Caddy: a matcher plus handler for decoys, log-tail for events.
- Traefik and Kubernetes ingress: a middleware or forward-auth style hook, a Helm chart, a sidecar option, OpenTelemetry out.
- Docker Compose: a sidecar container with label-based routing.
- Vercel, Netlify, Cloudflare Pages: edge middleware with a strict timeout and try/catch (fail-open), rewrites for decoy paths. Bans need a platform firewall API where one exists, otherwise Cloudflare in front.
- AWS: a CloudFront function or Lambda@Edge for routing, a WAF IP-set connector, load balancer logs from S3.
- Frameworks (Express, Fastify, Flask, Django, FastAPI, Laravel, Rails, Go net/http): small middleware libraries for tripwires and event emit only.
- GitHub Pages and other hosts with no control: only via Cloudflare in front, or Watch with the script tag. We say plainly what is impossible there.
- Bare VPS with nothing in front: one command installs Caddy plus Mirage, rather than Mirage terminating TLS.

One protocol, many adapters. Every adapter speaks the same small, versioned Mirage Adapter Protocol: a decision request with a hard deadline, and an event emit. A conformance suite runs against each adapter, and a documented SDK lets a contributor write a new adapter in a few hundred lines. This clarifies I3: calls over loopback or a unix socket to a local process, with a hard deadline, are allowed; remote network calls are not. On timeout the adapter skips Mirage and passes the request through.

Collision-proofing: `mirage init` reads the owner’s real route inventory (sitemap, framework route list, a short crawl) and refuses any decoy path that collides with a real route. Decoys never touch /.well-known/ (certificate renewal, security.txt), robots.txt, sitemap files or health-check paths. This enforces I4 automatically.

### 18. Charter: no internet pollution

My reading of ‘no internet poisoning’: Mirage must not pollute the public web, search indexes, AI training data, shared blocklists or third-party systems. We deter attackers without making the internet worse. New invariants:

- I12 No pollution of the public web. Decoys are never indexable (noindex, nofollow and noarchive headers, robots.txt disallow, absent from sitemaps), never served to verified search engines, archivers or ordinary visitors, and hidden-link injection never reaches verified crawlers, which also avoids search-engine cloaking penalties. Decoys are served only to sessions already scored suspicious.
- I13 No misinformation, no junk content. Decoys are inert technical artifacts (config files, fake admin shells, error pages), never articles, facts or claims about real people, brands or products. We do not generate plausible prose pages. For content scrapers and AI crawlers we block, challenge or rate-limit; we do not feed them garbage. Data-poisoning tools are out of scope by charter.
- I14 No third-party harm. Honeytokens never contain credentials that could work on a real service. Fake keys use formats that cannot validate, or are registered canary tokens owned by the site owner. Decoy hostnames use reserved names (.test, .invalid, example.com) and reserved address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). No real brand names, no real personal data, no outbound links, no redirects, and nothing that makes a visitor contact a third party.
- I15 Blocklist hygiene. Bans are local, short and expiring by default. Any shared threat feed is opt-in, signed, requires corroboration from several independent sources, expires entries and offers appeals, so nobody can frame an innocent address through us. Shared and carrier-grade NAT addresses, CDN ranges and addresses with recent legitimate sessions are never banned by default. Tor and VPN exits are tagged, not banned, unless the owner chooses otherwise. By default a ban covers a single address for minutes to hours, never a range.
- Bounded footprint: decoy depth and size are capped, generated content is deterministic and cached with a TTL, nothing accumulates forever, and tarpits have connection caps.

Decision recorded: decoys carry no public ‘this is a decoy’ marker, because that would reveal the trap. Instead we rely on audience gating, noindex and robots rules, and we publish a security.txt contact so legitimate researchers can ask to be allowlisted.

The pollution suite is added to the strict passes as pass 7b and runs on every change that touches decoys, adapters or connectors:

- Crawl the test site as a verified search bot and assert that zero decoy URLs or hidden links appear.
- Assert every decoy response carries the noindex headers and that none appear in sitemaps.
- Run secret scanners and format validators over the decoy catalog to prove there are no live-valid credential patterns, and lint for real brands, real domains and real personal data.
- Assert the decoy depth, size and connection caps hold under load.
- Feed-poisoning test: submit forged reports to the shared feed and confirm none produce a ban.

### 19. Designing for the long tail

- Three questions to install, in plain language with no security jargon. Event explanations read like: ‘This visitor asked for /.env, where apps keep passwords. Nothing real was exposed.’
- Runs small: a single binary and SQLite, with a modest memory target measured in CI, so it fits a cheap VPS or a Raspberry Pi.
- No phone-home. Telemetry is off by default; if offered, it is opt-in, anonymous and documented.
- Calm alerts: a weekly digest, and instant alerts only for confirmed high-confidence events, delivered by email, Telegram, Discord or webhook. Alert fatigue kills tools.
- Accessible and translatable: dashboard and docs built for screen readers and localization from day one.
- Signed updates with rollback, and a long-term-support channel for conservative users.
- Support load control: doctor output designed to paste into issues, issue templates, docs first.

### 20. Roadmap and checks added by Part II

- Serve segments in order: VPS with nginx or Caddy, then Cloudflare, then WordPress and PHP, then Vercel and Netlify, then Kubernetes. Each adapter ships with its conformance suite and a recipe tested in CI against the real environment or its closest emulator.
- Add the posture check to release 0.1, since it delivers value before any enforcement exists.
- Add the pollution suite to every release gate from 0.3.
- New success measures: time to first useful insight under ten minutes, uninstall leaves no trace, and zero decoy URLs ever found in a search index during dogfooding.

### 21. Updated open decisions

1. Confirm the reading of ‘no internet poisoning’ above, or say if you meant something else.
2. Which segment do we design the first-run experience for: VPS owners or Cloudflare users?
3. Run a feasibility spike on the serverless Lite mode before promising it.
4. Posture check scope: which paths, and is ownership verification by DNS TXT record enough?
5. Telemetry policy: strictly zero, or opt-in anonymous?
6. The open decisions in section 14 still stand.

## Part III: The most common web surface, and the beginner path (added November 20, 2026)

This part grounds the plan in what the web actually runs on, then designs the experience so a complete beginner can apply it. Where it conflicts with the segment order in Part II (section 15), Part III wins, because it is based on measured trends.

### 22. What the web runs on: a dated snapshot

Figures are W3Techs samples, not a census, and different trackers disagree. Treat them as direction, and re-check them every quarter (section 27).

- Web servers, July 2026: nginx 31.5%, Cloudflare 29.0%, Apache 23.1%, LiteSpeed 15.1%, Node.js 6.7%, IIS 3.1%, Caddy 0.4%. The shares overlap because a site can show more than one server. ‘Cloudflare’ means the site answers through Cloudflare’s proxy, and whatever server sits behind it is unknown.
- Size matters. In March 2026 Cloudflare fronted about 27% of all sites but about 55% of the top 1,000, while Apache fell from about 24% overall to under 10% of the top 1,000. Big sites sit behind Cloudflare; the long tail of small sites sits on Apache, LiteSpeed and nginx, often on shared or managed hosting.
- Content management, October to November 2026: WordPress about 39 to 40% of all websites (roughly 58% of sites with a detectable CMS), Shopify about 5.4%, Wix about 4.2%, Squarespace about 2.4%. Around 30% of sites show no detectable CMS (custom code, static sites, apps).
- Trend: WordPress is still far ahead but slowly losing share (about 43% of all sites in December 2025 to about 40% in autumn 2026) while hosted builders and Shopify grow.

What that adds up to: roughly four in ten sites are WordPress, roughly three in ten are behind Cloudflare, about 12% are on closed builders (Shopify, Wix, Squarespace) where the owner cannot install anything, and about 30% are custom or static.

### 23. Coverage priorities (this replaces the Part II order)

1. Cloudflare-fronted sites (about 29%, and it works for any stack behind it, WordPress included). One implementation (a Worker) covers the largest slice, so it comes first.
2. WordPress (about 40%). Most owners are non-technical and on shared or managed hosting. Two routes: Cloudflare in front (priority 1) now, and a dedicated plugin once the spec is stable.
3. Apache and LiteSpeed hosts (about 38% combined). LiteSpeed reads most Apache rules, so one .htaccess recipe usually covers both. Verify per host.
4. nginx (about 31%) and VPS owners. The power-user path: CLI, Docker, log-tail. Still essential, because these are the people most likely to contribute and test.
5. Node.js, frameworks and static hosts (Vercel, Netlify, GitHub Pages). Middleware and edge functions for developers.
6. IIS, Caddy, Envoy and the rest. Later, driven by demand.
7. Closed builders (Shopify, Wix, Squarespace, about 12%). Nothing can be installed, and the platform manages the servers. We do not pretend otherwise: these owners get the posture check of their public pages, a plain explanation of what the platform already handles, and Watch only where the platform allows custom DNS or scripts. Platform rules differ and change, so this is verified per platform at build time.

Sequencing logic: Cloudflare first, because one Worker implementation reaches the biggest slice. A WordPress plugin means a second implementation in PHP, so it waits until the spec is stable (section 26).

Honest risk: moving a domain to Cloudflare means changing nameservers, which is the scariest step for a beginner and can break email if DNS records are not copied. The wizard must check records before and after, warn about MX and TXT records, and explain rollback.

### 24. The beginner path (UI and flow)

Design rule: a person who has never opened a terminal can finish setup and understand every screen.

- One front door. The first screen asks, in pictures and plain words: ‘Where does your website live?’ Cards: WordPress, Wix, Shopify, Squarespace, Cloudflare, Vercel/Netlify/GitHub Pages, a server I manage, I don’t know. ‘I don’t know’ offers Detect for me, which reads only the public homepage headers like any browser would, rate-limited and logged.
- One path per card, each a short checklist with one action per step, a screenshot, and a copy button for anything to paste.
- Every step has a live check. After a step, a Test it button sends a harmless request to a decoy and shows it arriving in the dashboard: ‘It works: we just saw the test knock.’ Success is visible, never assumed.
- Three modes, in human words. Look (Watch): we only observe. Set traps (Tripwires): fake doors that only scouts touch. Protect (Enforce): short blocks for confirmed scouts. The default is Look. Protect stays locked until seven days of Look and a review screen: ‘In the last 7 days we would have blocked 3 visitors. All 3 look like scanners. Turn on Protect?’
- Undo everywhere. Every file or setting we change is backed up first, with a diff shown before applying. A big Turn everything off button and an Undo last change button are always visible.
- Honest copy. We say ‘watching’, not ‘protected’, unless Protect is actually on. Each event is written in plain English: ‘Someone asked for /.env, which is where apps keep passwords. Nothing real was exposed.’
- Accessible and calm. Mobile first, screen-reader friendly, status by icon plus text (never color alone), translatable from day one, and no hacker-terminal aesthetic or fear marketing.

Home screen sketch:

```
┌──────────────────────────────────────────────┐
│ mysite.com                     ● Watching    │
│                                              │
│ This week: 14 scouts knocked.                │
│ 0 reached anything real.                     │
│                                              │
│ [ See who knocked ]   [ Set traps ]          │
│                                              │
│ Next step: turn on traps (about 2 minutes)   │
│ [ Turn everything off ]                      │
└──────────────────────────────────────────────┘
```

Four screens in total: Home, Activity (a timeline of plain-English event cards), Setup (the guided checklist), and Settings (allowlist, alerts, the off button, export).

### 25. Instructions that work for beginners

Every recipe follows one template, so users learn it once:

1. What you need: two lines, including how long it takes.
2. Steps: one action each, with a screenshot and a copy button.
3. Test it: the live check from section 24.
4. Undo: how to remove it completely.
5. If it did not work: the three most common failures, with fixes.

Illustrative Cloudflare recipe (exact screens are verified at build time, since dashboards change):

1. Create a free Cloudflare account and add your site.
2. The wizard shows your current DNS records and warns about email records. Confirm the copy is complete.
3. Change the nameservers at your domain registrar to the two Cloudflare gives you.
4. Wait for Cloudflare to show the site as active (the wizard checks for you).
5. Create the API token using our pre-filled link (permissions limited to what Mirage needs) and paste it. Where a pre-filled link is not supported, a screenshot checklist is used instead.
6. The wizard deploys the Worker and runs Test it.
7. You land on Home in Look mode.

Illustrative WordPress recipe (plugin route, later phase): install from the official plugin directory, activate, open the Mirage menu, answer three questions, press Test it.

Docs are tested, not trusted. Recipes are executable checklists in CI where possible, screenshots are regenerated on a schedule, and any recipe untouched for a quarter is flagged for re-verification.

### 26. Keeping several implementations honest

The coverage plan implies more than one codebase: Go for servers and Docker, TypeScript for Workers, Node and edge platforms, and PHP for WordPress. Several codebases can drift, and drift in a security tool is a hidden bug. Rules:

- A written spec is the source of truth: signals, weights, the verdict ladder, the decoy catalog format and the adapter protocol.
- Golden test vectors: a shared set of request sequences with expected verdicts. Every implementation must produce identical results, and CI fails on any divergence.
- Shared data, not shared code: the decoy catalog, rules and allowlists are data files used by all implementations.
- Stage the implementations. Go and TypeScript first. PHP only after the spec and vectors have been stable for a full release cycle.
- WordPress plugin security rules, because the plugin runs inside the attacked app: minimal code, nonces and capability checks on every admin action, escaped output (I7), prepared statements, no remote code loading, no rule updates without a signature check, fail-open on any error or timeout, and distribution through the official directory.

### 27. Beginner-readiness gates and trend upkeep

- Usability gate: at least 8 of 10 non-technical testers complete their path unaided in under 15 minutes, and can say in their own words what Look mode does. A path that fails does not ship.
- Time to first useful insight under ten minutes, and uninstall leaves nothing behind (both from section 20).
- Surface census: every quarter, refresh section 22 from current trackers, record the date and sources in docs/vendor-notes/, and re-rank adapter priorities. Numbers without a date do not enter the docs.
- Support signals feed the ranking: the most common ‘I’m stuck’ reports decide what we simplify next.

### 28. Updated open decisions

1. Approve the new order: Cloudflare Worker first, then WordPress (via Cloudflare now, plugin later), then Apache and LiteSpeed, then nginx and VPS.
2. Approve three implementations in stages (Go, TypeScript, then PHP) with golden vectors, or choose a simpler path with fewer.
3. Closed builders: posture check only, or also explore script-tag Watch per platform?
4. Name and visual identity for the dashboard. This is where your design skills matter most.
5. The earlier open decisions in sections 14 and 21 still stand.

## Part IV: Finalized plan and growth strategy (added November 20, 2026)

### 29. Decisions locked

These are now the charter for version 1. Changing one needs an ADR.

- Build order: Cloudflare Worker first, then WordPress (through Cloudflare now, plugin later), then Apache and LiteSpeed, then nginx and VPS.
- Constitution: invariants I1 to I15 (sections 1, 17 and 18).
- Scope: public HTTP and HTTPS only. No TLS termination in version 1. Passive deception only: no hack-back, no poisoning.
- Languages: Go for Core and Edge, TypeScript for Workers and edge adapters, PHP only after the spec is stable.
- License: AGPL-3.0 for Core, Apache-2.0 for adapters and SDKs. This is the default unless you object.
- Defaults: Look mode first, fail-open everywhere, no phone-home, no paywalls on safety features.
- Still open: the name (section 32), the dashboard look, and the contributor model.

### 30. Why this can get popular, and what must be true

Honest first: most open-source projects never take off, and nobody can promise popularity. A plan can remove the reasons projects fail and copy what the breakout ones did right.

A recent example is Anubis, the bot blocker. It began as one developer’s fix for AI scrapers hammering her own server and spread fast. 404 Media reported nearly 200,000 downloads within months of its January 2025 launch, with adopters including GNOME, FFmpeg and UNESCO, and a software directory lists it at roughly 17,000 GitHub stars. What it did right:

- It solved a pain people were feeling that month, during a news wave about AI scrapers.
- One clear purpose, lightweight, and a memorable mascot.
- An honest README that calls itself a bit of a nuclear response and admits it can block good bots.
- A live demo, plain packaging (binaries, packages, Docker) and quick releases.
- It survived public criticism: a well-known security researcher argued its proof-of-work math favors well-funded scrapers. Projects that publish their limits survive this; projects that overclaim do not.

Our equivalent wave is AI attack agents: the FBI warning about ARTEX and the reporting around it. The conditions for popularity, each with the plan’s answer:

1. A pain people feel now: ‘AI agents scan everything; what is knocking on my site?’ Look mode answers it in minutes.
2. Five-to-ten-minute time to value: the beginner path (Part III) and the Test it button.
3. A shareable, delightful dashboard (the Pi-hole effect: a counter people screenshot): ‘14 scouts knocked, 0 reached anything real.’
4. Trust, because it is security software: claims policy, Evidence page, signed releases, external review.
5. Distribution where the audience already is: section 33.
6. A community flywheel with low-barrier ways to contribute: section 34.

### 31. Positioning

One sentence: open-source tripwires and decoys that show you who is scanning your website and waste their time, set up in ten minutes with no security background.

Message pillars: it never breaks your site; it tells the truth about what it can and cannot stop; it keeps the internet clean; anyone can install it.

Against the alternatives (we say this plainly in the docs):

- OrcaRouter Shield: hosted and paywalled, tied to their router. Ours is free and self-hostable.
- Cloudflare AI Labyrinth: aimed at scrapers, and it feeds them generated content. Ours targets attack agents and never pollutes the web.
- CrowdSec: shared IP reputation and bans. We integrate with it rather than compete.
- Anubis: proof-of-work against scrapers. Complementary.

‘Works with’ beats ‘versus’: each integration brings us that ecosystem’s users.

### 32. Name and brand

Clearance check run today against npm, PyPI and GitHub (domains and trademarks not yet checked):

- Mirage: crowded. Taken on npm and PyPI, 13 security-topic GitHub repos with the name (including an AI red-team tool), and shared with other well-known software. Drop it.
- Scarecrow, Bramble, Tripline, Moat, Lantern: names already taken on npm and PyPI by unrelated packages. Not a legal conflict by itself, but we would not own the name in package registries. Bramble also collides with a popular password manager.
- Thornwall and Decoyfox: free on npm and PyPI, with no security-topic GitHub repo of that name.

Recommendation: choose for feel, then clear the domain, GitHub organization and trademark before announcing anything. A friendly mascot is part of the brand (Anubis and Pi-hole both show it helps), with a calm palette. Avoid skulls and hacker-green. The name and mascot are your design call.

### 33. Distribution plan

Before launch (start now): make the repo public early with the README, invariants and design. Dogfood on your own sites and keep a weekly scout report of what knocked. That is a real, shareable story: ‘I put tripwires on my site; here is who knocked in 7 days.’ Use anonymized data only and never publish individuals’ IPs.

Launch assets: a one-command install and a deploy button for the Cloudflare path, a public demo with synthetic data, a 90-second video, an honest comparison page, and the Known limits page.

Soft launch first: 20 to 50 hand-picked testers (beginners and sysadmins), fix what they hit, then go public.

Channels, roughly in order:

1. Hacker News (Show HN), with the honest framing.
2. Reddit communities for self-hosting, homelabs, web development and sysadmins (read each community’s rules first).
3. Lobsters, dev.to, X, LinkedIn and Bluesky for the build-in-public story.
4. Self-hosting YouTubers and newsletters: offer early access and a good demo.
5. awesome-selfhosted and awesome-security list entries, the Cloudflare community and Workers showcase, and a CrowdSec integration listing.
6. The WordPress plugin directory when the plugin ships.
7. Student and local communities in India (FOSS United, college clubs, meetups), then conference lightning talks.
8. Programs that bring contributors: Hacktoberfest, and later Google Summer of Code (check the current rules). OWASP project status after 1.0.

Timing: ride the news wave without fear marketing. Facts and a calm tone win trust.

### 34. Community and trust flywheel

- Low-barrier contributions: decoy packs (YAML, no code), recipes, translations, and adapters through the SDK. Labeled good-first-issues. Promise a first response within 48 hours, and only promise what you can keep.
- Open governance: CODE\_OF\_CONDUCT, CONTRIBUTING, SECURITY.md, public ADRs, a public roadmap with exit criteria, monthly release notes.
- Trust: reproducible builds, signed releases, an SBOM, a public threat model, and an independent security review before 1.0 (explore funders and programs that sponsor open-source audits).
- An Evidence page: every claim links to a reproducible test, including what failed.
- A Known limits page, written first: decoys do not stop an agent that goes straight for a real vulnerability. Say it before critics do.
- Sustainability: sponsorships, optional paid support later, no paywalls on safety features. Recruit a co-maintainer by month six to avoid burnout.

### 35. Metrics and milestones

Targets, not predictions:

- Time to first useful insight under ten minutes, install completion rate, and week-four retention (still running).
- Trust metrics: zero fail-open violations, and every reported false-positive ban resolved within seven days.
- Visible growth: stars, installs that report in voluntarily, external contributors. Illustrative goals: 100 real installs in the first month after launch, and 10 external contributors by 1.0.
- Pivot rule: if after six months of public beta there are very few active installs, narrow to the Cloudflare-only product and double down on its polish.

### 36. Risks that could sink it

- Attackers learn our decoys. If every install shows the same decoy paths and content, scanners can fingerprint and skip them. Mitigation: per-install seeded variation, rotating decoy packs, many personas, and no fixed signature.
- Overclaiming. One viral ‘it did not stop X’ thread can kill trust. The claims policy and Evidence page are the defense.
- A bug that blocks real visitors or breaks a site. Mitigation: fail-open, budgets, observe-first, staged releases.
- Supply-chain compromise of our own releases: signing, provenance, pinned dependencies, and two-person release approval once there are co-maintainers.
- Big vendors shipping free equivalents. Differentiate on openness, self-hosting, honesty and beginner experience.
- Offensive-feature creep: contributions that add hack-back or poisoning are declined by charter.
- Maintainer burnout: scope control, a no-promises policy, and co-maintainers.

## Part V: The agentic build system (added November 20, 2026)

### 37. System overview

Principles, restated: agents propose and deterministic gates decide; humans own security-critical merges; all state lives in git; autonomy is bounded by turns, budgets and permissions; and the orchestration glue stays small and boring, because it is glue too.

Layers:

- L0 Constitution: CLAUDE.md (how to work), docs/invariants.md, agent charters.
- L1 Agents: custom subagents as Markdown files in .claude/agents/, each with a charter, tool limits and a model tier.
- L2 Orchestrator: the Lead, which is your main Claude Code session or a headless run. It decomposes work, delegates to agents and advances each task through the pipeline.
- L3 Gates: deterministic checks (Makefile targets and CI) plus Claude Code hooks that enforce rules at tool-call time.
- L4 Memory: files in git: ADRs, failure ledger, hallucination list, vendor notes, task ledger.
- L5 Lab: an isolated environment for adversary runs, fault injection and soak tests.
- L6 Humans: you, as maintainer, at defined approval points.

This relies on the following, checked against Claude Code’s documentation. Subagents are Markdown files with YAML frontmatter in .claude/agents/, with fields such as name, description, tools, disallowedTools, model, permissionMode, maxTurns, hooks, memory and isolation. Hooks are configured in .claude/settings.json: a PreToolUse hook that exits with code 2 blocks the call, and a Stop hook can return a block decision that sends the agent back to work (check stop\_hook\_active to avoid loops). Headless runs use claude -p with limits such as maximum turns and a budget cap. Flags and fields evolve, so verify against the docs for your installed version when wiring.

### 38. The roster

Model tiers use aliases (opus, sonnet, haiku): the strongest tier where judgment matters, cheaper tiers for volume work.

- Lead (main session): decomposes tasks, keeps the task ledger, runs the pipeline in order, enforces loop limits, escalates to you.
- Architect (opus; writes only in docs/ and spec/): owns invariants, ADRs and specs; vetoes designs that break I1 to I15.
- Test engineer (sonnet): writes tests and golden vectors from the spec only, in a separate worktree that does not contain the implementation, so it is blind by construction.
- Implementer Go and Implementer TS (sonnet): write code in an isolated worktree to the spec and the failing tests. They may not edit invariants, CI or hooks.
- Adversary (opus; writes only in lab/ and tests/adversarial/): tries to break the invariants in the lab (spoofed headers, ban-the-world, log injection, tarpit exhaustion, fail-open violations) and ships each break as a regression test.
- Reviewer (sonnet): line-level review against a checklist. Read-only.
- Critic (opus): design-level skeptic: what fails, what are we assuming, what is the cheapest way to be wrong. Read-only.
- Security reviewer (opus): threat-model delta for every Tier 1 change. Read-only.
- Slop hunter (sonnet): runs the slop script and reviews for AI slop: invented APIs and packages, tautological tests, dead code, over-abstraction, filler comments, and marketing fluff in docs.
- Docs editor (sonnet): recipes, plain-language copy, reading-level check, following the recipe template.
- UX reviewer (sonnet): dashboard flows, accessibility, honest-copy rules, beginner-path walkthroughs.
- Release captain (sonnet): runs the release checklist, changelog and provenance. Cannot publish without your approval.
- Triage (haiku): read-only with no secrets. Labels issues, finds duplicates, drafts replies for you to approve.

Start small. The minimum factory is Architect, Test engineer, Implementer, Reviewer and Adversary, plus the deterministic gates. Add the rest as real pain appears.

Honest limit: all of these are the same model family, so critics can share blind spots. Diversity comes from isolation (the blind test engineer), from different prompts and incentives, from deterministic gates, fuzzing and real beginners, and optionally from a second model family run as an independent reviewer on Tier 1 changes.

### 39. Pipelines

Task states are recorded in ledger/tasks/T-NNNN.md: proposed, specced, tests-written, implementing, gates, adversary, review, human-approve, merged, released. Each transition appends links and hashes of its artifacts, so any run can resume from the ledger.

Pipeline A, feature (the tier decides how much runs):

1. Intake: the Lead classifies the tier (1, 2 or 3) and writes the task file.
2. Spec: the Architect writes acceptance criteria, the invariants touched, and golden vectors. You approve for Tier 1.
3. Tests first: the Test engineer writes failing tests from the spec in the blind worktree.
4. Implement: the Implementer works in its own worktree until tests pass. Loop cap: three implement-and-fix cycles.
5. Deterministic gates (the passes in section 11), as the tier requires.
6. Adversary pass (Tier 1 and 2): attacks the change in the lab.
7. Slop pass.
8. Review: Reviewer, Critic and (Tier 1) Security reviewer, independently and in parallel. Any unresolved blocker stops the task.
9. Human approval: required for every Tier 1 change. Tier 2 and 3 may be batch-approved once gates are green.
10. Merge, then the change joins the release train.

Pipeline B, bug or incident: write the failure-ledger entry; the Test engineer writes the regression test first; fix; the Adversary tries variants; the ledger is updated with the lesson, and the hallucination list if an agent invented something.

Pipeline C, recipe or docs: the Docs editor drafts from the template; the UX reviewer checks plain language; a novice-simulation agent follows the recipe in a clean container and reports where it got stuck (a cheap pre-test, never a replacement for real beginners); then human beginner testers.

Pipeline D, adapter: conformance suite and environment-matrix CI before anything else.

Pipeline E, nightly and weekly (agents propose, never merge): dependency-update PRs, the live vendor-API canary, long fuzz runs, docs-rot checks, and the quarterly surface census refresh.

Pipeline F, release train: nightly, then beta, then stable. The Release captain runs the checklist. Signing and publishing only on your approval.

Pipeline G, community: Triage labels and drafts; you approve replies; first-time contributors get a friendly checklist reply.

Loop control: caps on turns, wall-clock time and spend per run. If the same failure repeats twice, stop and escalate. If the Implementer and Critic disagree twice, escalate with both arguments. The Lead never overrides a failing gate.

Two-key rule for Tier 1: all gates green, no unresolved blocker from the Reviewer, Critic or Security reviewer, and then your explicit approval.

### 40. Memory for agents

Everything lives in git and is reviewed like code. No hidden state.

- CLAUDE.md: a short working agreement and pointers.
- docs/invariants.md, docs/adr/, docs/failure-ledger.md, docs/hallucination-list.md, docs/vendor-notes/ (with verified-on dates), docs/surface-census.md, docs/claims-policy.md, and ledger/tasks/.
- A context-pack script assembles a bounded pack per task (invariants, relevant ADRs, recent ledger entries, the task file), so agents never load the whole history.
- Staleness: vendor notes expire, and a check flags anything older than 90 days.
- Write authority: only the Architect and Release captain write ADRs and ledger entries, through PRs. Implementers propose entries in the PR description and reviewers verify them.
- Memory-poisoning defense: memory files change only through reviewed PRs and are protected by CODEOWNERS.

### 41. Guardrails

Prompt injection is the new supply-chain risk: once agents read community issues and PRs, outsiders can try to instruct them.

- Anything from outside (issues, PR text, web pages, logs) is untrusted data, never instructions. Triage runs read-only with no secrets and no write access to the repo.
- CI never runs agents with secrets on fork PRs. Only deterministic gates run on untrusted code.
- Permissions: deny rules for secrets, destructive commands, git push, sudo and unrestricted network tools. Agents work in worktrees and can never push to main.
- Hooks: a PreToolUse hook blocks edits to protected paths (invariants, hooks, settings, CI, release scripts, CODEOWNERS) unless you set a human override. A Stop hook runs the fast gate and sends the agent back if it fails. A PostToolUse hook writes an audit log of tool calls.
- New dependencies need an allowlist entry and a registry existence check, which stops invented or look-alike package names.
- Lab isolation: attack simulations run only against lab targets, in containers with no route to real sites or real accounts and a restricted outbound allowlist. Cloudflare sandbox tokens are scoped, rotated and kept only in the lab.
- Do not run unvetted ARTEX copies. Copies circulate and some may be tampered with. Use purpose-built simulators and well-known open-source pentest agents from official sources, only against your own lab.
- Budgets: per-run turn and spend caps, a daily cap, and alerts on anomalies.

### 42. Repository layout

```
repo/
  CLAUDE.md  CODEOWNERS  SECURITY.md  Makefile
  .claude/agents/        one file per agent
  .claude/hooks/         guard-paths.sh, stop-gate.sh, audit-log.sh
  .claude/settings.json  permissions and hook wiring
  .claude/commands/      /ship and /gate shortcuts
  docs/                  invariants, adr/, failure-ledger, hallucination-list,
                         vendor-notes/, surface-census, claims-policy
  spec/                  signals, adapter protocol, golden-vectors/, decoy-catalog/
  core/ edge-worker/ adapters/ plugins/wordpress/   product code (later)
  lab/                   compose lab, attack simulators, fault injection
  ledger/tasks/          one file per task
  tools/                 context-pack, slop-check, structure check, run-task
  .github/workflows/     gate.yml (deterministic), nightly.yml (placeholder)
```

The starter kit delivered with this plan contains everything except the product code.

### 43. Operating manual

- Daily: open Claude Code in the repo and describe a task. The Lead creates the ledger entry and runs the pipeline, and you approve at the gates. Tier 3 work can run mostly unattended.
- Weekly: review the ledger, the failure ledger and the audit log; read the Critic’s top concerns; refresh the surface census on its schedule.
- Headless: tools/run-task.sh runs a task in a fresh worktree with turn and spend caps. GitHub Actions runs the deterministic gate on every PR, and agent jobs run only on trusted branches with budgets.
- Your jobs that cannot be delegated: approving ADRs and Tier 1 merges, running real beginner tests, community conversation, and the brand.

First 30 days:

- Days 1 to 3: pick the name, create the organization and repo, add the starter kit. The Architect drafts spec v0 and the golden-vector skeleton, and you review.
- Week 1: Go Edge skeleton with fail-open proven by tests, CI gates green, log-tail Watch.
- Week 2: Cloudflare Worker adapter and sandbox connector, decoy catalog v0 with the pollution suite.
- Week 3: dashboard v0 in the beginner design, posture check, Test it button.
- Week 4: Cloudflare recipe tested with three real beginners, dogfood on your own sites, first scout report.

### 44. Honest limits of agentic building

- LLM reviewers miss things and agree with each other. Hence deterministic gates, a human on Tier 1, fuzzing, real testers and an external audit before 1.0.
- Agents write plausible but wrong security code. Never merge Tier 1 on agent confidence alone.
- Process can swamp a solo maintainer. Use the minimum factory first.
- Costs add up. Keep budgets, and use the cheaper tiers for volume work.
- The orchestration is glue too. Keep it in plain Markdown, shell and Make, with no framework lock-in, so it can be rebuilt in a day.

### 45. The finalized plan in ten actions

1. Choose the name and clear the domain, organization and trademark.
2. Create the repo and drop in the starter kit.
3. Run the Architect to produce spec v0 and golden vectors, and approve them.
4. Turn on the CI gates and hooks, and confirm they actually block.
5. Build the Go Edge with fail-open proven, plus log-tail Watch.
6. Build the Cloudflare Worker adapter and connector in a sandbox account.
7. Build the dashboard and the posture check.
8. Dogfood for 14 days on your own sites and publish the first scout report.
9. Run beginner tests with ten non-technical people and fix the path.
10. Soft launch to testers, then the public launch.
