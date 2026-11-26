# ADR-0001: Decoys carry no public marker

- **Status:** Accepted
- **Date:** 2026-11-26
- **Deciders:** maintainer (design doc Part II section 18), Architect
- **Invariants touched:** I12, I13, I14

## Context

A visible "this is a decoy" marker (comment, header, footer badge) would tell
reconnaissance tooling exactly which surfaces to ignore, collapsing the cost
imposed on attackers. It could also be read as consent-baiting or as cloaking
by search engines.

## Decision

Decoys carry **no public marker**. Safety is delivered by:

1. **Audience gating** — decoys are served only to sessions already scored
   suspicious; verified bots and ordinary visitors never see them (I12).
2. **Noindex** — `X-Robots-Tag: noindex, nofollow, noarchive` on every decoy
   response, robots.txt disallow, absent from sitemaps.
3. **A published security.txt** — so legitimate researchers can identify the
   operator and ask to be allowlisted instead of probing.

## Consequences

- A researcher who trips a decoy without reading security.txt may report the
  site as "serving fake content". The security.txt contact resolves this.
- The pollution suite must assert both directions: verified crawlers see zero
  decoys, and suspicious sessions see consistent, inert decoys.
- Rejected alternative: a `X-Decoy: true` header. It fails the cost analysis
  (one fingerprinting request and the whole catalog is skippable) and is
  inconsistent with the deception engine's purpose.
