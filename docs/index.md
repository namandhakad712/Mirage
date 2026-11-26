---
layout: page
title: "Mirage"
description: "Open-source deception-layer defense against AI-driven attack agents: deterministic signal scoring, decoy personas, fail-open by design."
category: landing
order: 0
---

<div class="hero">
  <div class="hero-scrim" aria-hidden="true"></div>
  <div class="hero-mark" aria-hidden="true"></div>
  <div class="hero-inner">
    <p class="hero-eyebrow">Deception layer · Signal spec 1.1.0</p>
    <h1 class="hero-title">Bait the machines. Protect the <em>humans</em>.</h1>
    <p class="hero-lede">
      Mirage is an open-source deception layer for your origin: every request
      is scored by eleven deterministic signals, attackers are quietly routed
      into decoy personas, and the whole system fails open — a broken Mirage
      never breaks your site.
    </p>
    <div class="hero-actions">
      <a class="btn btn-primary" href="{{ site.baseurl }}/guide/getting-started.html">Get started</a>
      <a class="btn btn-ghost" href="{{ site.baseurl }}/spec/SIGNALS.html">Read the spec</a>
    </div>
    <div class="hero-meta">
      <span><span class="dot"></span>Go core</span>
      <span><span class="dot"></span>Cloudflare Worker port</span>
      <span><span class="dot"></span>20 golden vector cases, 68 requests</span>
      <span><span class="dot"></span>zero runtime dependencies in the worker</span>
    </div>
  </div>
</div>

<div class="spec-strip">
  <div class="spec-strip-inner">
    <span>SIGNALS v1.1.0</span>
    <span>ADAPTER-PROTOCOL v1</span>
    <span>DECOY-CATALOG v1</span>
    <span>20 golden vectors</span>
    <span>AGPL-3.0</span>
  </div>
</div>

<section class="section">
  <div class="section-inner">
    <div class="section-head">
      <p class="section-kicker">Design contracts</p>
      <h2 class="section-title">The four contracts</h2>
      <p class="section-lede">Fifteen invariants bind every line of the code; these four are the ones an owner, a visitor and an auditor meet first. All fifteen are normative in <a href="{{ site.baseurl }}/invariants.html">Invariants</a>.</p>
    </div>
    <div class="contracts">
      <div class="contract">
        <p class="contract-num">01</p>
        <h3 class="contract-title">Fail-open <span class="inv">I1</span></h3>
        <p>Any internal failure — crash, timeout, bad config, full disk — sends traffic to the origin unmodified. Mirage must never be the reason a site is down.</p>
      </div>
      <div class="contract">
        <p class="contract-num">02</p>
        <h3 class="contract-title">Observe by default <span class="inv">I9</span></h3>
        <p>Enforcement is opt-in per site, and there is a global kill switch. Actions fire only in protect mode, with the block opt-in set and the switch clear.</p>
      </div>
      <div class="contract">
        <p class="contract-num">03</p>
        <h3 class="contract-title">Explainable <span class="inv">I10</span></h3>
        <p>Every automated action stores its evidence: signals fired, weights, verdict, reason code, session key. Plain-English reason texts ship with the data.</p>
      </div>
      <div class="contract">
        <p class="contract-num">04</p>
        <h3 class="contract-title">Local-only hot path <span class="inv">I3</span></h3>
        <p>No network call, disk wait or LLM call while handling a request. Decisions come from an in-memory snapshot, under a hard deadline.</p>
      </div>
    </div>
  </div>
</section>

<section class="section">
  <div class="section-inner">
    <div class="section-head">
      <p class="section-kicker">How it works</p>
      <h2 class="section-title">One decision path, three outcomes</h2>
      <p class="section-lede">Every request walks the same path: score, verdict, action. No machine learning, no network calls on the hot path, no surprises.</p>
    </div>
    <div class="steps">
      <div class="step">
        <span class="step-num">1</span>
        <h3>Observe</h3>
        <p>Eleven deterministic signals — scanner paths, decoy leads followed, honeytoken use, tooling fingerprints — score each request against an in-memory session snapshot.</p>
      </div>
      <div class="step">
        <span class="step-num">2</span>
        <h3>Deceive</h3>
        <p>Suspicious sessions cross the decoy threshold and are routed into persona-correct decoy pages. If they touch a honeytoken, the verdict is ban.</p>
      </div>
      <div class="step">
        <span class="step-num">3</span>
        <h3>Enforce — only when you say so</h3>
        <p>Observe by default (I9). In protect mode, bans fan out to denyfiles, webhooks, CrowdSec and Cloudflare — behind a kill switch.</p>
      </div>
    </div>
  </div>
</section>

<section class="section">
  <div class="section-inner">
    <div class="section-head">
      <p class="section-kicker">The verdict ladder</p>
      <h2 class="section-title">Fixed weights, published thresholds</h2>
      <p class="section-lede">Every rung is specified, hand-computed and locked by golden vectors. The ladder, the weights and the gating rules are normative in <a href="{{ site.baseurl }}/spec/SIGNALS.html">SIGNALS v1.1.0</a>.</p>
    </div>
    <div class="ladder">
      <div class="rung rung-pass">
        <span class="rung-name">observe</span>
        <span class="rung-desc">Below every threshold. The request passes; the event still lands in the store.</span>
        <span class="rung-rule">score &lt; 15</span>
      </div>
      <div class="rung rung-tag">
        <span class="rung-name">tag</span>
        <span class="rung-desc">Marked, nothing more. History alone can never push a session past this rung.</span>
        <span class="rung-rule">req ≥ 15 or cum ≥ 25</span>
      </div>
      <div class="rung rung-decoy">
        <span class="rung-name">decoy_route</span>
        <span class="rung-desc">A high-confidence signal on a decoyable path: the attacker gets a persona page.</span>
        <span class="rung-rule">req ≥ 25 · high · decoyable</span>
      </div>
      <div class="rung rung-throttle">
        <span class="rung-name">throttle</span>
        <span class="rung-desc">Heavy request score: 429 with a fixed retry window.</span>
        <span class="rung-rule">req ≥ 40</span>
      </div>
      <div class="rung rung-ban">
        <span class="rung-name">ban</span>
        <span class="rung-desc">Honeytoken use, a followed lead on an unprotected route, or a heavy enough request. 30-minute TTL, renewable on repeat.</span>
        <span class="rung-rule">honeytoken · lead-follow · req ≥ 60 + high</span>
      </div>
    </div>
  </div>
</section>

<section class="section">
  <div class="section-inner">
    <div class="section-head">
      <p class="section-kicker">Design guarantees</p>
      <h2 class="section-title">Fifteen invariants, tested continuously</h2>
      <p class="section-lede">The properties the code must preserve are written down and enforced — by the race suite, the golden vectors, the pollution suite and the fault-injection matrix. Read them in <a href="{{ site.baseurl }}/invariants.html">Invariants</a>.</p>
    </div>
    <div class="feature-grid">
      <div class="feature">
        <h3>Fails open <span class="inv">I1</span></h3>
        <p>Store dead, connector wedged, budget overrun — every internal failure passes the request. Mirage cannot take your site down.</p>
      </div>
      <div class="feature">
        <h3>Deterministic scoring <span class="inv">I2</span></h3>
        <p>Fixed weights, fixed order, no ML. Every decision is reproducible and auditable, and the golden vectors prove it.</p>
      </div>
      <div class="feature">
        <h3>Local hot path <span class="inv">I3</span></h3>
        <p>The decision path touches in-memory state only. No disk, no network, no lock contention on the request path.</p>
      </div>
      <div class="feature">
        <h3>Observe by default <span class="inv">I9</span></h3>
        <p>Enforcement actions exist only in protect mode with the block opt-in set and the kill switch clear.</p>
      </div>
      <div class="feature">
        <h3>Explainable <span class="inv">I10</span></h3>
        <p>Every decision — renewals included — leaves an event with its reason code, verdict and score.</p>
      </div>
      <div class="feature">
        <h3>No public marker <span class="inv">ADR-0001</span></h3>
        <p>Decoys and denials carry nothing that fingerprints Mirage. Responses look like the origin, or like nothing at all.</p>
      </div>
    </div>
  </div>
</section>

<section class="section">
  <div class="section-inner">
    <div class="section-head">
      <p class="section-kicker">Numbers</p>
      <h2 class="section-title">Small surface, deep proof</h2>
    </div>
    <div class="stats">
      <div class="stat"><div class="stat-value">11</div><div class="stat-label">detection signals, fixed weights</div></div>
      <div class="stat"><div class="stat-value">3</div><div class="stat-label">decoy personas in the shipped catalog</div></div>
      <div class="stat"><div class="stat-value">20 / 68</div><div class="stat-label">golden vector cases / requests, hand-computed</div></div>
      <div class="stat"><div class="stat-value">0</div><div class="stat-label">runtime dependencies in the worker port</div></div>
    </div>
  </div>
</section>

<section class="section">
  <div class="section-inner">
    <div class="section-head">
      <p class="section-kicker">Deployment</p>
      <h2 class="section-title">Two supported shapes</h2>
      <p class="section-lede">The Go core runs anywhere you can run a binary; the worker port runs at Cloudflare's edge with zero runtime dependencies. Same signals, same vectors, same verdicts.</p>
    </div>
    <div class="deploy-grid">
      <div class="deploy-card">
        <h3>Go core — your origin</h3>
        <p>A single static binary fronting your upstream as a transparent proxy: <code>mirage serve --upstream …</code>. SQLite or in-memory store, loopback dashboard, connector fan-out on ban.</p>
        <div class="deploy-links">
          <a href="{{ site.baseurl }}/deploy/nginx.html">nginx topology</a>
          <a href="{{ site.baseurl }}/reference/cli.html">CLI reference</a>
        </div>
      </div>
      <div class="deploy-card">
        <h3>Cloudflare Worker — the edge</h3>
        <p>The same decision path compiled to a Worker: sync sha256, shared data generated from the same sources, fail-open handler, vector-parity tests in CI.</p>
        <div class="deploy-links">
          <a href="{{ site.baseurl }}/deploy/cloudflare-worker.html">Worker guide</a>
          <a href="{{ site.baseurl }}/guide/testing.html">How parity is proven</a>
        </div>
      </div>
    </div>
  </div>
</section>

<section class="section">
  <div class="section-inner">
    <div class="section-head">
      <p class="section-kicker">Start reading</p>
      <h2 class="section-title">For humans and for agents</h2>
      <p class="section-lede">The full guide walks every concept in order; the specs are normative; the agent surface exposes the same documentation to machines.</p>
    </div>
    <div class="hero-actions">
      <a class="btn btn-primary" href="{{ site.baseurl }}/guide/">Read the guide</a>
      <a class="btn btn-ghost" href="{{ site.baseurl }}/agent/">For AI agents</a>
      <a class="btn btn-ghost" href="{{ site.baseurl }}/llms.txt">llms.txt</a>
      <a class="btn btn-ghost" href="{{ site.baseurl }}/changelog.html">Changelog</a>
    </div>
  </div>
</section>
