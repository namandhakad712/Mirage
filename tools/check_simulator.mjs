#!/usr/bin/env node
/*
 * Parity harness for the verdict playground (docs/assets/js/simulator.js).
 *
 * Replays every golden vector case (spec/golden-vectors/vectors.json — 20
 * cases, 68 requests) through the SAME engine module the docs page loads,
 * maintaining session state exactly like the engine does: a fresh session
 * per case, requests in ts_ms (file) order, the never-scored flag derived
 * from the case's allowlisted_ips the way tools/gen_vectors.py does.
 *
 * Asserts, for every request: the fired signals list (exact order), the
 * verdict, the recorded cumulative score, and the reason code. Any
 * mismatch prints case id, request index, expected vs computed and exits
 * 1; CI runs this on every push, so the page can never drift from the
 * spec it teaches.
 *
 * Plain node (>= 20), zero dependencies.
 */

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..");
const enginePath = path.join(repo, "docs", "assets", "js", "simulator.js");
const vectorsPath = path.join(repo, "spec", "golden-vectors", "vectors.json");

for (const p of [enginePath, vectorsPath]) {
  if (!existsSync(p)) {
    console.error(`parity: missing ${path.relative(repo, p)}`);
    process.exit(1);
  }
}

/*
 * Import the engine module. The direct file import is the honest path
 * and the one node >= 22 uses (module syntax detection). On node 20 a
 * bare .js file still resolves as CommonJS, so the first import of the
 * ES-module simulator throws there; the fallback re-imports the exact
 * same bytes through a data: URL, which node always evaluates as an ES
 * module. Either way the code under test is the file on disk, byte for
 * byte — the page and this harness run one engine.
 */
let engine;
try {
  engine = await import(pathToFileURL(enginePath).href);
} catch (err) {
  const source = await readFile(enginePath, "utf8");
  try {
    engine = await import("data:text/javascript;base64," + Buffer.from(source, "utf8").toString("base64"));
  } catch (fallbackErr) {
    console.error(`parity: cannot import docs/assets/js/simulator.js`);
    console.error(`  direct import: ${err && err.message}`);
    console.error(`  data import:   ${fallbackErr && fallbackErr.message}`);
    process.exit(1);
  }
}

const { decide, newSession } = engine;
if (typeof decide !== "function" || typeof newSession !== "function") {
  console.error("parity: simulator.js does not export decide(newSession) — got", Object.keys(engine));
  process.exit(1);
}

const vectors = JSON.parse(await readFile(vectorsPath, "utf8"));

const FIELDS = ["signals", "verdict", "score", "reason_code"];
const failures = [];
let totalRequests = 0;
let totalCases = 0;

for (const c of vectors.cases) {
  totalCases += 1;
  const allowlisted = (c.allowlisted_ips || []).some(
    (ip) => ip.split("/")[0] === c.client_ip,
  );
  const session = newSession();
  c.requests.forEach((req, i) => {
    totalRequests += 1;
    const decision = decide({ ...req, client_ip: c.client_ip }, session, { allowlisted });
    const computed = {
      signals: decision.signals.map((s) => s.id),
      verdict: decision.verdict,
      score: decision.score,
      reason_code: decision.reasonCode,
    };
    const expected = c.expected[i];
    for (const field of FIELDS) {
      if (JSON.stringify(computed[field]) !== JSON.stringify(expected[field])) {
        failures.push({
          case: c.id,
          request: i + 1,
          field,
          expected: expected[field],
          computed: computed[field],
        });
      }
    }
    if (decision.verdict === "ban" && decision.banTtlMs !== vectors.policy.ban_ttl_ms) {
      failures.push({
        case: c.id,
        request: i + 1,
        field: "ban_ttl_ms",
        expected: vectors.policy.ban_ttl_ms,
        computed: decision.banTtlMs,
      });
    }
    if (decision.verdict !== "ban" && decision.banTtlMs !== null) {
      failures.push({
        case: c.id,
        request: i + 1,
        field: "ban_ttl_ms",
        expected: null,
        computed: decision.banTtlMs,
      });
    }
  });
}

if (failures.length > 0) {
  console.error(`parity: ${failures.length} mismatch(es) of ${totalRequests} requests — FAILING\n`);
  for (const f of failures) {
    console.error(
      `  ${f.case} request ${f.request} — ${f.field}\n` +
      `    expected: ${JSON.stringify(f.expected)}\n` +
      `    computed: ${JSON.stringify(f.computed)}`,
    );
  }
  process.exit(1);
}

console.log(`parity: ${totalCases}/${totalCases} cases, ${totalRequests}/${totalRequests} requests — exact`);
