// THE parity gate: replay spec/golden-vectors/vectors.json against the
// TypeScript engine and require EXACT agreement with the Go core's
// hand-computed expectations (signals in order, verdict, cumulative score,
// reason code, ban TTL on ban). vitest runs in Node, so the file is read
// with node:fs; a fresh Engine is created per case so session state never
// leaks between cases.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Engine, defaultRules } from "../src/engine";
import type { Request } from "../src/engine";

interface VectorRequest {
  method: string;
  path: string;
  ts_ms: number;
  user_agent: string;
  header_count: number;
  has_cookie: boolean;
  auth_hint?: string;
}

interface VectorExpectation {
  signals: string[];
  verdict: string;
  score: number;
  reason_code: string;
}

interface VectorCase {
  id: string;
  client_ip: string;
  allowlisted_ips: string[];
  requests: VectorRequest[];
  expected: VectorExpectation[];
}

interface VectorFile {
  spec_version: string;
  protocol_version: string;
  cases: VectorCase[];
}

const parsed: unknown = JSON.parse(
  // The vectors live at the repo root, three levels up from test/.
  readFileSync(new URL("../../../spec/golden-vectors/vectors.json", import.meta.url), "utf8"),
);
const vectors = parsed as VectorFile;

// Session-key anchors pinned by the spec (SIGNALS §2, HAND-COMPUTED v02/v20).
const ANCHOR_SESSION_KEYS: Record<string, string> = {
  "v02-scanner-path": "fec52565aa0cf18f57d7cf5b3ac72850",
  "v20-ip-spoof-rejected": "8959edf6884f2c2e223a9319e83a6982",
};

describe("golden vectors (spec 1.1.0)", () => {
  it("loads the full conformance corpus", () => {
    expect(vectors.spec_version).toBe("1.1.0");
    expect(vectors.protocol_version).toBe("1");
    expect(vectors.cases.length).toBe(20);
    expect(vectors.cases.reduce((n, c) => n + c.requests.length, 0)).toBe(68);
  });

  for (const c of vectors.cases) {
    describe(c.id, () => {
      const engine = new Engine(defaultRules());
      // Allowlist matching: compare the client IP against the address part
      // of each allowlisted_ips entry ("192.0.2.50/32" -> "192.0.2.50").
      const allowlisted = c.allowlisted_ips.some((entry) => entry.split("/")[0] === c.client_ip);
      const anchorKey = ANCHOR_SESSION_KEYS[c.id];

      c.requests.forEach((r, i) => {
        const expected = c.expected[i];
        if (expected === undefined) throw new Error(`${c.id}: missing expectation for request ${i + 1}`);

        it(`request ${i + 1}: ${r.method} ${r.path} -> ${expected.verdict} (score ${expected.score})`, () => {
          const req: Request = {
            method: r.method,
            path: r.path,
            clientIp: c.client_ip,
            userAgent: r.user_agent,
            headerCount: r.header_count,
            hasCookie: r.has_cookie,
            authHint: r.auth_hint,
            tsMs: r.ts_ms,
            allowlisted,
          };
          const decision = engine.decide(req);

          // Rich diffs: compare the full shapes, not just booleans.
          expect({
            signals: decision.signals.map((s) => s.id),
            verdict: decision.verdict,
            score: decision.score,
            reasonCode: decision.reasonCode,
          }).toEqual({
            signals: expected.signals,
            verdict: expected.verdict,
            score: expected.score,
            reasonCode: expected.reason_code,
          });

          // ban_ttl_ms is set only on ban verdicts (SIGNALS §8).
          expect(decision.banTtlMs).toBe(expected.verdict === "ban" ? 1_800_000 : null);

          // Internal consistency: the recorded score is cum_before + request
          // score, and the reason is one of the fired signals (or SIG-000).
          expect(decision.requestScore).toBe(decision.signals.reduce((n, s) => n + s.weight, 0));
          expect(decision.specVersion).toBe("1.1.0");

          if (anchorKey !== undefined) {
            // The two spec-pinned anchors: sha256("203.0.113.7") and
            // sha256("198.51.100.5") truncated to 32 hex chars (I6: the
            // spoofed X-Forwarded-For in v20 must never change identity).
            expect(decision.sessionKey).toBe(anchorKey);
          }
        });
      });
    });
  }
});
