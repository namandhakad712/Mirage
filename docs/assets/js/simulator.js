/*
 * Mirage verdict playground — the browser port of the decision engine.
 *
 * The engine half of this file is a line-by-line port of internal/detect
 * (spec/SIGNALS.md v1.1.0) to dependency-free JavaScript. It is the SAME
 * code the page runs and the parity harness replays: tools/check_simulator.mjs
 * feeds all 20 golden vector cases (spec/golden-vectors/vectors.json,
 * 68 requests) through decide() and fails CI on any divergence from the
 * hand-computed expectations. Every threshold below is normative — do not
 * tune one here without bumping the spec and regenerating the vectors.
 *
 * Layout of this file:
 *   1. Data snapshot (data/*.txt, spec/decoy-catalog/catalog.yaml, policy).
 *   2. SHA-256 (sync FIPS 180-4, ported from packages/mirage-worker/src/sha256.ts).
 *   3. Path handling (SIGNALS §3).
 *   4. Session state (§7).
 *   5. decide(request, session, opts) — the pure engine.
 *   6. Mode → action mapping (service layer, I9).
 *   7. UI wiring (browser only; every branch is guarded so the module
 *      also imports cleanly in node under the parity harness).
 *
 * Canon decisions this port follows (Go core + tools/gen_vectors.py agree;
 * the TypeScript worker port differs only on edges no vector covers):
 *   - tooling_curl matches a UA that STARTS WITH "curl/" (Go prefix test,
 *     not the worker's substring test).
 *   - no_cookie_persistence reads cookie_ever BEFORE this request's own
 *     cookie is recorded (a cookie on the current request does not gate it).
 *   - a protected path always records at least tag (the cap sets tag even
 *     from a zero-score observe), except honeytoken_use which still bans.
 *   - normalization drops trailing slashes ("/a/" scores as "/a"), so
 *     distinct-unknown-path counting joins them.
 */

/* ------------------------------------------------------------------ *
 * 1. Data snapshot — engine inputs, frozen copies of the canon files.
 * ------------------------------------------------------------------ */

export const SPEC_VERSION = "1.1.0";

/** Signal table, evaluation order 1..11 (SIGNALS §4). Fixed. */
export const SIGNAL_TABLE = [
  { id: "scanner_path", weight: 25, klass: "high", reason: "SIG-101" },
  { id: "decoy_hit", weight: 30, klass: "high", reason: "SIG-102" },
  { id: "decoy_lead_follow", weight: 40, klass: "high", reason: "SIG-103" },
  { id: "honeytoken_use", weight: 50, klass: "high", reason: "SIG-104" },
  { id: "path_enumeration", weight: 25, klass: "high", reason: "SIG-105" },
  { id: "ua_suspicious", weight: 15, klass: "medium", reason: "SIG-106" },
  { id: "ua_rotation", weight: 20, klass: "medium", reason: "SIG-107" },
  { id: "no_cookie_persistence", weight: 15, klass: "medium", reason: "SIG-108" },
  { id: "headers_sparse", weight: 10, klass: "medium", reason: "SIG-109" },
  { id: "ua_missing", weight: 10, klass: "medium", reason: "SIG-110" },
  { id: "tooling_curl", weight: 15, klass: "medium", reason: "SIG-111" },
];

/** Thresholds (SIGNALS §4–§7; the vectors.json policy block). */
export const POLICY = {
  tagScore: 15,
  tagCumBefore: 25,
  decoyRouteScore: 25,
  throttleScore: 40,
  banScore: 60,
  sessionTtlMs: 30 * 60 * 1000,
  uaWindowMs: 300 * 1000,
  enumWindowMs: 60 * 1000,
  enumThreshold: 8,
  uaRotationThreshold: 4,
  noCookieThreshold: 5,
  sparseHeaderBelow: 4,
  banTtlMs: 30 * 60 * 1000,
};

/** Protected routes (I4): a trailing "/" entry is a prefix, others match
 * exactly — internal/detect rules.go isProtected, line for line. */
export const PROTECTED_ROUTES = ["/wp-login.php", "/wp-admin/", "/checkout", "/cart", "/api/"];

/** data/scanner-paths.txt, verbatim. Matching is trailing-slash
 * insensitive in both directions (SIGNALS §3.3). */
export const SCANNER_PATHS = [
  "/.env", "/.env.local", "/.env.production", "/.git/config", "/.git/HEAD",
  "/.git/index", "/.aws/credentials", "/.ssh/id_rsa", "/.ssh/authorized_keys",
  "/.DS_Store", "/.svn/entries", "/.svn/wc.db", "/.htaccess.bak",
  "/.htpasswd", "/.bash_history", "/.mysql_history", "/wp-config.php.bak",
  "/wp-config.php.save", "/wp-config.php.old", "/phpmyadmin-old/",
  "/pma-old/", "/administrator/backups/", "/backup.sql", "/backup.zip",
  "/backup.tar.gz", "/db.sql", "/dump.sql", "/database.sql",
  "/database.sql.gz", "/site-backup.zip", "/web.config.bak",
  "/server-backup.tar.gz", "/.elastic/config/elasticsearch.yml",
  "/.docker/config.json", "/composer.lock.bak", "/package.json.bak",
  "/ids.sql", "/data.sql",
];

/** data/ua-suspicious.txt, lowercased for case-insensitive substring match. */
export const UA_SUSPICIOUS = [
  "sqlmap/", "nikto", "nuclei", "masscan", "zgrab", "nmap scripting engine",
  "python-requests/", "python-urllib/", "go-http-client/", "wget/",
  "libwww-perl", "acunetix", "dirbuster", "dirb", "gobuster", "ffuf/",
  "httpx/", "wpscan", "arachni", "wfuzz/", "havij", "hydra", "metasploit",
  "burpsuite", "sqlninja", "zap", "w3af",
];

/** data/ua-verified-bots.txt, lowercased. Never scored, never trapped (I12). */
export const UA_VERIFIED_BOTS = [
  "googlebot", "bingbot", "duckduckbot", "baiduspider", "yandexbot", "slurp",
];

/** spec/decoy-catalog/catalog.yaml — the path/lead/honeytoken graph the
 * engine consumes (ids, leads, mintable honeytoken slots; personas and
 * bodies belong to the renderer, not the scorer). */
export const DECOY_CATALOG = [
  { id: "env-file-staging", persona: "laravel-staging", path: "/.env",
    leads: ["/storage/logs/laravel-staging.log"], honeytokenIds: ["db_password"] },
  { id: "git-config-staging", persona: "laravel-staging", path: "/.git/config",
    leads: ["/.git/logs/refs/heads/main"], honeytokenIds: [] },
  { id: "admin-panel-legacy", persona: "legacy-cpanel", path: "/admin/login",
    leads: ["/admin/login/verify", "/admin/assets/style.css"], honeytokenIds: [] },
  { id: "debug-endpoint-legacy", persona: "legacy-cpanel", path: "/debug",
    leads: ["/debug/phpinfo"], honeytokenIds: [] },
  { id: "api-docs-dev", persona: "node-api-dev", path: "/api/docs",
    leads: ["/v1/admin/tokens"], honeytokenIds: [] },
  { id: "source-map-dev", persona: "node-api-dev", path: "/app.js.map",
    leads: ["/sources/secrets.js"], honeytokenIds: [] },
];

/** data/reason-texts.txt (I10): plain-English renderings every dashboard
 * shows next to the reason code. {path} interpolates the escaped subject. */
export const REASON_TEXTS = {
  "SIG-000": "Mirage stepped aside so your site could answer normally. Nothing was blocked and nothing was scored.",
  "SIG-101": "Someone asked for {path}, a file where apps keep secrets. Nothing real was exposed: Mirage served a fake.",
  "SIG-102": "Someone asked for {path}, a door that exists only as a decoy. Real visitors never see it.",
  "SIG-103": "Someone followed a link that exists only inside a decoy Mirage served them earlier. That is close to certain evidence of an automated scout.",
  "SIG-104": "A fake credential that Mirage planted in a decoy was just used. This is near-certain evidence, and it tells us exactly which decoy leaked it.",
  "SIG-105": "Someone requested many different unknown addresses in a short time, the pattern of an automated scanner mapping the site.",
  "SIG-106": "The visitor's software signature ({path} was the user agent) is a known attack tool.",
  "SIG-107": "The visitor changed its apparent software many times in a few minutes, together with other suspicious behavior.",
  "SIG-108": "Many requests in a row with no cookie jar at all, unlike any normal browser.",
  "SIG-109": "The requests are unusually bare, with far fewer headers than any real browser sends.",
  "SIG-110": "The requests carry no user agent at all, which no ordinary browser does.",
  "SIG-111": "The requests come from a command-line tool, combined with other suspicious behavior on the same request.",
};

const DECOY_BY_PATH = new Map(DECOY_CATALOG.map((e) => [e.path, e]));
const ALL_LEADS = new Set(DECOY_CATALOG.flatMap((e) => e.leads));
const SCANNER_LOOKUP = new Set(SCANNER_PATHS.map(stripTrailingSlash));
const REASON_NONE = "SIG-000";

export const VERDICTS = ["observe", "tag", "decoy_route", "throttle", "ban"];

/* ------------------------------------------------------------------ *
 * 2. SHA-256 — synchronous FIPS 180-4, ported from the worker's
 *    sha256.ts (crypto.subtle is async; every decision here is a sync
 *    function call). Correctness is pinned by the vectors: the v05/v19
 *    honeytoken expectations carry minted tokens derived through it.
 * ------------------------------------------------------------------ */

const SHA_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

/** SHA-256 of the UTF-8 encoding of input, as 64 lowercase hex characters. */
export function sha256Hex(input) {
  const bytes = new TextEncoder().encode(input);
  const bitLength = bytes.length * 8;

  const paddedLength = Math.ceil((bytes.length + 1 + 8) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000));
  view.setUint32(paddedLength - 4, bitLength >>> 0);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  const w = new Uint32Array(64);
  for (let offset = 0; offset < paddedLength; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
    for (let i = 16; i < 64; i++) {
      const w15 = w[i - 15];
      const w2 = w[i - 2];
      const s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3);
      const s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA_K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }

  let hex = "";
  for (const word of [h0, h1, h2, h3, h4, h5, h6, h7]) {
    hex += word.toString(16).padStart(8, "0");
  }
  return hex;
}

/** Session key: first 32 hex chars of sha256(client_ip) (SIGNALS §2). */
export function sessionKeyFor(clientIp) {
  return sha256Hex(clientIp).slice(0, 32);
}

/* ------------------------------------------------------------------ *
 * 3. Path handling (SIGNALS §3).
 * ------------------------------------------------------------------ */

/** Trim EVERY trailing "/" and map an emptied result back to "/". */
export function stripTrailingSlash(p) {
  const trimmed = p.replace(/\/+$/, "");
  return trimmed === "" ? "/" : trimmed;
}

/**
 * Strip the query string, then resolve "." and ".." segments left to
 * right. ".." at the root pops nothing — the path clamps at "/" — and
 * dotEscape is flagged (scanner-style fuzzing, fires SIG-101 via §4.1).
 * Empty segments and trailing slashes are dropped (the Go core resolves
 * "/a/" to "/a"; distinct-unknown counting joins the two spellings).
 */
export function normalizePath(rawPath) {
  let p = rawPath;
  const q = p.indexOf("?");
  if (q !== -1) p = p.slice(0, q);
  if (!p.startsWith("/")) p = "/" + p;

  const stack = [];
  let dotEscape = false;
  for (const seg of p.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (stack.length > 0) stack.pop();
      else dotEscape = true;
      continue;
    }
    stack.push(seg);
  }
  return { path: stack.length === 0 ? "/" : "/" + stack.join("/"), dotEscape };
}

/** Scanner-list match, trailing-slash-insensitive both ways (§3.3). */
export function isScanner(path) {
  return SCANNER_LOOKUP.has(stripTrailingSlash(path));
}

/** Protected route (I4): "/"-terminated entries are prefixes, the rest
 * match exactly — "/checkout2" and "/wp-login.php/extra" are NOT
 * protected, "/apiary" is not "/api/" (internal/detect rules.go). */
export function isProtected(path) {
  for (const route of PROTECTED_ROUTES) {
    if (route.endsWith("/")) {
      if (path.startsWith(route)) return true;
      continue;
    }
    if (path === route) return true;
  }
  return false;
}

/** The catalog entry served at the normalized path, if any. */
export function decoyAt(path) {
  return DECOY_BY_PATH.get(path) || null;
}

/** Unknown for enumeration purposes (§4.5 + HAND-COMPUTED canon 4): not
 * "/", not protected, not a scanner path, not a decoy, and not ANY
 * catalog lead (a lead is Mirage's territory, served or not). */
export function isUnknown(path) {
  return (
    path !== "/" &&
    !isProtected(path) &&
    !isScanner(path) &&
    !DECOY_BY_PATH.has(path) &&
    !ALL_LEADS.has(path)
  );
}

/** Verified-bot UA hint: case-insensitive substring (§2) — never scored. */
export function isVerifiedBotUA(userAgent) {
  const ua = userAgent.toLowerCase();
  return UA_VERIFIED_BOTS.some((s) => s !== "" && ua.includes(s));
}

/** Suspicious UA substring (§4.6). */
export function isSuspiciousUA(userAgent) {
  const ua = userAgent.toLowerCase();
  return UA_SUSPICIOUS.some((s) => ua.includes(s));
}

/** token_alnum_24 honeytoken (DECOY-CATALOG §4): names its session,
 * entry and slot without a database. */
export function mintHoneytoken(sessionKey, entryId, tokenId) {
  return "mrg_live_" + sha256Hex(sessionKey + ":" + entryId + ":" + tokenId).slice(0, 24);
}

/* ------------------------------------------------------------------ *
 * 4. Session state (SIGNALS §7).
 * ------------------------------------------------------------------ */

/** A fresh session epoch. decide() resets an expired session to this
 * shape in place, like the Go core. */
export function newSession() {
  return {
    lastTs: 0,          // timestamp of the last scored request
    requestCount: 0,    // scored requests in this epoch
    cumulative: 0,      // sum of request scores in this epoch
    cookieEver: false,  // a Cookie header was ever seen in this epoch
    uaSeen: [],         // [{ua, ts}] non-empty UAs, trailing 300 s
    unknownPaths: [],   // [{path, ts}] distinct-unknown history, trailing 60 s
    leadsKnown: new Set(), // lead paths of decoys served to this session
    tokensMinted: [],   // honeytokens embedded in served decoys
    decoysServed: [],   // decoy entry ids served (decoy_route verdicts)
  };
}

function resetSession(s) {
  s.lastTs = 0;
  s.requestCount = 0;
  s.cumulative = 0;
  s.cookieEver = false;
  s.uaSeen = [];
  s.unknownPaths = [];
  s.leadsKnown = new Set();
  s.tokensMinted = [];
  s.decoysServed = [];
}

/* ------------------------------------------------------------------ *
 * 5. decide — the pure engine (SIGNALS §3–§8).
 *
 *    request = { method, path, client_ip, user_agent, header_count,
 *                has_cookie, auth_hint, ts_ms }
 *    session = the mutable state object from newSession() (or a prior
 *    decide call); it is updated in place, exactly like the Go engine.
 *    opts    = { allowlisted } — loopback / link-local / owner-range
 *    addresses are never scored (I6): verdict observe, no signals, and
 *    the session is left untouched.
 *
 *    Returns a decision with a full trace (fired signals with weights,
 *    every gated signal with its one-line reason, the ladder rung
 *    evaluation, the score arithmetic, the normalized path, the session
 *    key). The trace exists for the playground page; the parity harness
 *    reads only signals/verdict/score/reasonCode.
 * ------------------------------------------------------------------ */

export function decide(request, session, opts) {
  const o = opts || {};
  const clientIp = request.client_ip;
  const ua = request.user_agent || "";
  const ts = request.ts_ms;
  const sessionKey = sessionKeyFor(clientIp);

  // Never-scored (§2): allowlisted addresses and verified-bot UAs
  // observe and leave session state untouched (I12 — bots never meet
  // a trap). The session key is still reported (display only).
  if (o.allowlisted || isVerifiedBotUA(ua)) {
    return {
      sessionKey, specVersion: SPEC_VERSION, neverScored: true,
      signals: [], gated: gateNotes.neverScored(),
      requestScore: 0, requestClass: null, score: 0,
      verdict: "observe", reasonCode: REASON_NONE, decoyId: null, banTtlMs: null,
      normalizedPath: null, dotEscape: false, pathProtected: false,
      ladder: neverScoredLadder(), arithmetic: null,
    };
  }

  // Session expiry (§7): a gap past the TTL starts a new epoch before
  // scoring. requestCount > 0 distinguishes "no request yet" from a
  // first request at ts 0.
  if (session.requestCount > 0 && ts - session.lastTs > POLICY.sessionTtlMs) {
    resetSession(session);
  }

  const norm = normalizePath(request.path);
  const path = norm.path;
  const dotEscape = norm.dotEscape;
  const pathProtected = isProtected(path);
  const decoyEntry = decoyAt(path);
  const cumBefore = session.cumulative;
  const headerCount = request.header_count;

  // fired: signal indices in evaluation order (§4).
  const fired = [];
  const fire = (i) => fired.push(i);

  // 1. scanner_path (§4.1) — scanner-list match or dot_escape.
  const scannerMatch = isScanner(path);
  if (scannerMatch || dotEscape) fire(0);

  // 2. decoy_hit (§4.2) — suppressed when scanner_path fired: a
  //    scanner-list hit is already fully explained.
  const decoyHitSuppressed = decoyEntry !== null && fired.includes(0);
  if (decoyEntry !== null && !fired.includes(0)) fire(1);

  // 3. decoy_lead_follow (§4.3) — a path that exists only inside a decoy
  //    served earlier to this session.
  const leadFollowed = session.leadsKnown.has(path);
  if (leadFollowed) fire(2);

  // 4. honeytoken_use (§4.4) — credential material equals or embeds a
  //    honeytoken minted for this session.
  const authHint = request.auth_hint || "";
  let honeytokenMatched = false;
  if (authHint !== "") {
    for (const tok of session.tokensMinted) {
      if (tok !== "" && (tok === authHint || authHint.includes(tok))) {
        honeytokenMatched = true;
        break;
      }
    }
  }
  if (honeytokenMatched) fire(3);

  // 5. path_enumeration (§4.5) — ≥ 8 distinct unknown paths in the
  //    trailing 60 s, the current path counted if unknown.
  const enumWindow = new Set();
  for (const p of session.unknownPaths) {
    if (ts - p.ts <= POLICY.enumWindowMs) enumWindow.add(p.path);
  }
  const pathUnknown = isUnknown(path);
  if (pathUnknown) enumWindow.add(path);
  if (enumWindow.size >= POLICY.enumThreshold) fire(4);

  // Ungating set for ua_rotation and tooling_curl: the five high signals
  // (HAND-COMPUTED canon 1). Medium signals never ungate, and prior
  // session score never ungates (§6.1).
  const ungated = fired.some((i) => i <= 4);

  // 6. ua_suspicious (§4.6) — case-insensitive substring.
  const uaLower = ua.toLowerCase();
  const suspiciousUA = isSuspiciousUA(ua);
  if (suspiciousUA) fire(5);

  // 7. ua_rotation (§4.7, gated §6.2) — ≥ 4 distinct non-empty UAs in
  //    the trailing 300 s including the current one, AND a same-request
  //    signal from 1–5.
  const uaWindow = new Set();
  for (const u of session.uaSeen) {
    if (ts - u.ts <= POLICY.uaWindowMs && u.ua !== "") uaWindow.add(u.ua);
  }
  if (ua !== "") uaWindow.add(ua);
  if (uaWindow.size >= POLICY.uaRotationThreshold && ungated) fire(6);

  // 8. no_cookie_persistence (§4.8, gated §6.3) — otherwise-clean session:
  //    request count ≥ 5 including this one, never a cookie (prior
  //    requests; this request's cookie is recorded after scoring, canon
  //    2 + 5), cumulative 0 before, and none of signals 1–7 fired.
  const countIncl = session.requestCount + 1;
  const noCookieEligible =
    countIncl >= POLICY.noCookieThreshold &&
    !session.cookieEver &&
    cumBefore === 0 &&
    fired.length === 0;
  if (noCookieEligible) fire(7);

  // 9. headers_sparse (§4.9) — fires on every sparse request.
  const headersSparse = headerCount < POLICY.sparseHeaderBelow;
  if (headersSparse) fire(8);

  // 10. ua_missing (§4.10).
  if (ua === "") fire(9);

  // 11. tooling_curl (§4.11, gated §6.1) — UA starts with "curl/" AND a
  //     same-request signal from 1–5. headers_sparse does NOT ungate.
  const curlUA = uaLower.startsWith("curl/");
  if (curlUA && ungated) fire(10);

  // Score and class of this request (§5).
  let requestScore = 0;
  let requestHigh = false;
  for (const i of fired) {
    requestScore += SIGNAL_TABLE[i].weight;
    if (SIGNAL_TABLE[i].klass === "high") requestHigh = true;
  }
  const requestClass = fired.length === 0 ? null : (requestHigh ? "high" : "medium");

  // Verdict ladder (§5): the highest rung whose condition holds.
  const tagHolds = requestScore >= POLICY.tagScore || cumBefore >= POLICY.tagCumBefore;
  const decoyHolds =
    decoyEntry !== null &&
    requestScore >= POLICY.decoyRouteScore &&
    requestHigh &&
    !pathProtected;
  const throttleHolds = requestScore >= POLICY.throttleScore;
  const banHolds =
    fired.includes(3) ||
    (fired.includes(2) && !pathProtected) ||
    (requestScore >= POLICY.banScore && requestHigh);

  let verdict = "observe";
  if (tagHolds) verdict = "tag";
  if (decoyHolds) verdict = "decoy_route";
  if (throttleHolds) verdict = "throttle";
  if (banHolds) verdict = "ban";

  // Protected-route cap (§5, I4): a protected path records at most tag —
  // the Go core and the vector generator set tag even from a zero-score
  // observe, so every protected-route request is at least recorded.
  // honeytoken_use survives the cap and still bans (R3: a leaked fake
  // credential in use is near-certain evidence regardless of route).
  let protectedCapped = false;
  if (pathProtected && !honeytokenMatched && verdict !== "tag") {
    verdict = "tag";
    protectedCapped = true;
  }

  // Session update (§7): the event records the cumulative score AFTER
  // this request.
  session.requestCount += 1;
  session.lastTs = ts;
  if (request.has_cookie) session.cookieEver = true;
  session.cumulative = cumBefore + requestScore;

  // Windows keep only entries inside their trailing span (§7).
  if (ua !== "") session.uaSeen.push({ ua, ts });
  session.uaSeen = session.uaSeen.filter((u) => ts - u.ts <= POLICY.uaWindowMs);
  if (pathUnknown) session.unknownPaths.push({ path, ts });
  session.unknownPaths = session.unknownPaths.filter((p) => ts - p.ts <= POLICY.enumWindowMs);

  // Decoy serving happens only on a decoy_route verdict (canon 6):
  // throttle and ban do not serve, so they register no leads and mint
  // no honeytokens.
  let decoyId = null;
  if (verdict === "decoy_route") {
    decoyId = decoyEntry.id;
    session.decoysServed.push(decoyEntry.id);
    for (const lead of decoyEntry.leads) session.leadsKnown.add(lead);
    for (const tokenId of decoyEntry.honeytokenIds) {
      session.tokensMinted.push(mintHoneytoken(sessionKey, decoyEntry.id, tokenId));
    }
  }

  // reason_code = highest-weight fired signal; a weight tie resolves to
  // the earliest in evaluation order (canon 3). fired is in evaluation
  // order, so strict > keeps the earlier signal on ties.
  let reasonCode = REASON_NONE;
  if (fired.length > 0) {
    let best = fired[0];
    for (const i of fired.slice(1)) {
      if (SIGNAL_TABLE[i].weight > SIGNAL_TABLE[best].weight) best = i;
    }
    reasonCode = SIGNAL_TABLE[best].reason;
  }

  return {
    sessionKey, specVersion: SPEC_VERSION, neverScored: false,
    signals: fired.map((i) => SIGNAL_TABLE[i]),
    gated: gateNotes.reasons({
      fired, scannerMatch, dotEscape, decoyEntry, decoyHitSuppressed,
      leadFollowed, honeytokenMatched, authHint, enumWindow, pathUnknown,
      ua, uaWindow, suspiciousUA, ungated, curlUA, countIncl, cumBefore,
      headerCount, session,
    }),
    requestScore, requestClass,
    score: session.cumulative,
    verdict, reasonCode, decoyId,
    banTtlMs: verdict === "ban" ? POLICY.banTtlMs : null,
    normalizedPath: path, dotEscape, pathProtected, protectedCapped,
    ladder: ladderTrace({ tagHolds, decoyHolds, throttleHolds, banHolds, verdict }),
    arithmetic: {
      terms: fired.map((i) => SIGNAL_TABLE[i].weight),
      requestScore, cumBefore, scoreAfter: session.cumulative,
    },
  };
}

/* ---- trace helpers (presentation only; no engine semantics) ---- */

function neverScoredLadder() {
  return [
    { verdict: "observe", holds: true, why: "never-scored address: observe, no signals, no session state" },
    { verdict: "tag", holds: false, why: "never scored" },
    { verdict: "decoy_route", holds: false, why: "never scored" },
    { verdict: "throttle", holds: false, why: "never scored" },
    { verdict: "ban", holds: false, why: "never scored" },
  ];
}

function ladderTrace(t) {
  return [
    { verdict: "observe", holds: !t.tagHolds, why: t.tagHolds ? "" : "no rung held (request below 15, cum_before below 25)" },
    { verdict: "tag", holds: t.tagHolds, why: t.tagHolds ? "" : "request score below 15 and cum_before below 25" },
    { verdict: "decoy_route", holds: t.decoyHolds, why: t.decoyHolds ? "" : "needs request ≥ 25 with a high-class signal on a decoyable, unprotected path" },
    { verdict: "throttle", holds: t.throttleHolds, why: t.throttleHolds ? "" : "request score below 40" },
    { verdict: "ban", holds: t.banHolds, why: t.banHolds ? "" : "no honeytoken_use, no unprotected lead follow, request below 60 with class high" },
  ];
}

/** One-line reasons for every signal that did NOT fire — the right-hand
 * half of the playground's signal panel. Purely descriptive. */
const gateNotes = {
  neverScored() {
    return SIGNAL_TABLE.map((s) => ({ id: s.id, reason: "loopback, owner-range or verified-bot client: never scored" }));
  },
  reasons(c) {
    const out = [];
    const n = (id, reason) => out.push({ id, reason });
    if (!c.fired.includes(0)) {
      n("scanner_path", c.dotEscape
        ? "a dot segment escaped the root — scanner_path fires on dot_escape"
        : "normalized path matches no scanner-list entry and no dot-segment escape");
    }
    if (!c.fired.includes(1)) {
      n("decoy_hit", c.decoyEntry === null
        ? "the normalized path is not a catalog decoy"
        : "suppressed: scanner_path fired the same request (a scanner hit already explains it)");
    }
    if (!c.fired.includes(2)) {
      n("decoy_lead_follow", "the path is not a lead of a decoy served earlier to this session");
    }
    if (!c.fired.includes(3)) {
      if (c.authHint === "") n("honeytoken_use", "no credential material visible to the adapter");
      else if (c.session.tokensMinted.length === 0) n("honeytoken_use", "credential material present, but this session was never served a honeytoken decoy");
      else n("honeytoken_use", "no honeytoken minted for this session appears in the credential material");
    }
    if (!c.fired.includes(4)) {
      n("path_enumeration", `${c.enumWindow.size} distinct unknown path${c.enumWindow.size === 1 ? "" : "s"} in the trailing 60 s window (${c.enumWindow.size < POLICY.enumThreshold ? "needs " + POLICY.enumThreshold : "threshold met"}; this path ${c.pathUnknown ? "counts as unknown" : "is known territory"})`);
    }
    if (!c.fired.includes(5)) {
      n("ua_suspicious", c.ua === "" ? "no user agent to match (see ua_missing)" : "the user agent matches no suspicious substring");
    }
    if (!c.fired.includes(6)) {
      if (c.uaWindow.size < POLICY.uaRotationThreshold) {
        n("ua_rotation", `${c.uaWindow.size} distinct non-empty user agent${c.uaWindow.size === 1 ? "" : "s"} in the trailing 300 s (needs ${POLICY.uaRotationThreshold}, counting this request)`);
      } else {
        n("ua_rotation", `${c.uaWindow.size} distinct user agents in window, but no signal 1\u20135 fired this request (gated, \u00a76.2)`);
      }
    }
    if (!c.fired.includes(7)) {
      if (c.countIncl < POLICY.noCookieThreshold) n("no_cookie_persistence", `request ${c.countIncl} of this session (fires on the ${POLICY.noCookieThreshold}th at the earliest)`);
      else if (c.session.cookieEver) n("no_cookie_persistence", "a Cookie header was seen earlier in this session");
      else if (c.cumBefore !== 0) n("no_cookie_persistence", `cum_before is ${c.cumBefore}, not 0 (the session already scored)`);
      else n("no_cookie_persistence", "suppressed: an earlier signal fired this request (gated, \u00a76.3)");
    }
    if (!c.fired.includes(8)) {
      n("headers_sparse", `${c.headerCount} headers (fires below ${POLICY.sparseHeaderBelow}, counting Host and User-Agent)`);
    }
    if (!c.fired.includes(9)) {
      n("ua_missing", "a user agent is present");
    }
    if (!c.fired.includes(10)) {
      if (!c.curlUA) n("tooling_curl", "the user agent does not start with curl/");
      else n("tooling_curl", "curl user agent, but no signal 1\u20135 fired this request (gated, \u00a76.1 \u2014 headers_sparse does not ungate)");
    }
    return out;
  },
};

/* ------------------------------------------------------------------ *
 * 6. Mode → action mapping (service layer, I9; internal/service).
 *
 *    Verdicts are computed by decide() and are mode-blind; the mode
 *    only shapes what the adapter does with them:
 *      look      — observe only: the RECORDED verdict caps at tag, no
 *                  decoy is named, every action passes;
 *      tripwires — decoys ARE the tripwires: decoy_route still serves,
 *                  throttle/ban stay recorded but pass;
 *      protect   — full enforcement: serve_decoy / throttle / ban.
 * ------------------------------------------------------------------ */

export const MODES = ["look", "tripwires", "protect"];

/** The wire-level answer per action (internal/edge edge.go and the
 * worker adapter — the two edges are byte-identical on purpose). */
export const ACTION_ANSWERS = {
  pass: "origin answers normally",
  serve_decoy: "decoy body, 200, X-Robots-Tag: noindex",
  throttle: "429 Too Many Requests \u00b7 Retry-After: 30",
  ban: "403 Request blocked.",
};

export function applyMode(decision, mode) {
  let verdict = decision.verdict;
  let decoyId = decision.decoyId;
  let banTtlMs = decision.banTtlMs;
  let action;
  if (mode === "look") {
    // observeOnly: the cap is honest about what the adapter may do — no
    // decoy is named and no TTL is proposed when nothing is enforced.
    if (verdict !== "observe" && verdict !== "tag") {
      verdict = "tag";
      decoyId = null;
      banTtlMs = null;
    }
    action = "pass";
  } else if (mode === "tripwires") {
    action = verdict === "decoy_route" ? "serve_decoy" : "pass";
  } else {
    action = "pass";
    if (verdict === "decoy_route") action = "serve_decoy";
    else if (verdict === "throttle") action = "throttle";
    else if (verdict === "ban") action = "ban";
  }
  return { mode, verdict, action, decoyId, banTtlMs };
}

/* ------------------------------------------------------------------ *
 * 7. UI wiring — browser only.
 *    The playground page (#sim-root) is the one consumer. Everything
 *    recomputes on the "Score it" button: the composer's session priors
 *    seed a fresh session, decide() runs once, and the panels render
 *    from the decision + the session object. No network, no storage.
 * ------------------------------------------------------------------ */

const UI = {
  IP_LOOPBACK: "127.0.0.1",
  IP_OWNER: "192.0.2.50",
  IP_REMOTE: "203.0.113.7",
  T0: 1780000000000,
  UA_BROWSER: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
  UA_CURL: "curl/8.5.0",
  UA_TOOL: "sqlmap/1.8.2#stable (http://sqlmap.org)",
  UA_EMPTY: "",
  FOREIGN_TOKEN: "mrg_live_000000000000000000000000",
};

function esc(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[ch]);
}

/** Escape every attacker-shaped string for the reason text {path}
 * interpolation (I7 — the same discipline the dashboards follow). */
function reasonTextFor(reasonCode, subject) {
  const text = REASON_TEXTS[reasonCode] || reasonCode;
  return esc(text.replace("{path}", subject));
}

function bootPlayground() {
  // The simulator and the stepper are independent widgets: a failure in
  // one must not take the other (or the page) down with it.
  const root = document.getElementById("sim-root");
  if (root) {
    try {
      wireSimulator(root);
    } catch (e) {
      const note = root.querySelector(".sim-fallback");
      if (note) note.hidden = false;
    }
  }
  const stepper = document.getElementById("sim-stepper");
  if (stepper) {
    try {
      wireStepper(stepper);
    } catch (e) {
      const out = stepper.querySelector("#sim-stepper-out");
      if (out) {
        out.innerHTML = '<p class="sim-note">The stepper could not start on this browser.</p>';
      }
    }
  }
}

function readComposer(root) {
  const num = (id, min, max, dflt) => {
    const el = root.querySelector("#" + id);
    const v = parseInt(el.value, 10);
    if (Number.isNaN(v)) return dflt;
    return Math.max(min, Math.min(max, v));
  };
  const clientClass = root.querySelector("#sim-client").value;
  const userAgent = root.querySelector("#sim-ua").value;
  const headerCount = num("sim-headers", 1, 12, 9);
  const hasCookie = root.querySelector("#sim-cookie").checked;
  const priors = {
    requests: num("sim-prior-requests", 0, 40, 0),
    cumBefore: num("sim-prior-cum", 0, 999, 0),
    uas: num("sim-prior-uas", 0, 6, 0),
    unknowns: num("sim-prior-unknowns", 0, 12, 0),
  };
  const events = {
    decoyEntry: root.querySelector("#sim-ev-decoy").checked,
    leadFollow: root.querySelector("#sim-ev-lead").checked,
    honeytoken: root.querySelector("#sim-ev-token").checked,
  };
  const mode = root.querySelector("#sim-mode").value;

  // Path precedence: the event toggles are shortcuts for canonical
  // scenarios; the plain input is the free-form path. Protected route
  // wins, then the lead follow, then the decoy entry, then the input.
  let path = root.querySelector("#sim-path").value.trim() || "/";
  if (events.decoyEntry) path = "/admin/login";
  if (events.leadFollow) path = "/storage/logs/laravel-staging.log";
  if (root.querySelector("#sim-ev-protected").checked) path = "/wp-login.php";

  const allowlisted = clientClass !== "remote";
  return {
    clientIp: clientClass === "loopback" ? UI.IP_LOOPBACK
      : clientClass === "owner" ? UI.IP_OWNER : UI.IP_REMOTE,
    allowlisted,
    userAgent,
    headerCount,
    hasCookie,
    path,
    priors,
    events,
    mode,
  };
}

/** Build a fresh session carrying the composer's priors. The synthetic
 * window entries are all distinct and inside their windows at T0, so the
 * engine's distinct-count arithmetic sees exactly what the panel says. */
function seedSession(priors, events, clientIp) {
  const session = newSession();
  session.requestCount = priors.requests;
  session.cumulative = priors.cumBefore;
  session.cookieEver = rootCookieMirror();
  session.lastTs = UI.T0 - 1000;
  for (let i = 0; i < priors.uas; i++) {
    session.uaSeen.push({ ua: "Session-UA-" + (i + 1) + "/1.0", ts: UI.T0 - 1000 });
  }
  for (let i = 0; i < priors.unknowns; i++) {
    session.unknownPaths.push({ path: "/session-unknown-" + (i + 1), ts: UI.T0 - 1000 });
  }
  // Following a lead or presenting a honeytoken both require that the
  // env-file-staging decoy was served earlier in this session — that is
  // the one catalog entry with a honeytoken, and its lead is the laravel
  // log. Seeds mirror decide()'s decoy_route bookkeeping exactly.
  if (events.leadFollow || events.honeytoken) {
    const entry = DECOY_CATALOG.find((e) => e.id === "env-file-staging");
    session.decoysServed.push(entry.id);
    for (const lead of entry.leads) session.leadsKnown.add(lead);
    for (const tokenId of entry.honeytokenIds) {
      session.tokensMinted.push(mintHoneytoken(sessionKeyFor(clientIp), entry.id, tokenId));
    }
  }
  return session;
}

function rootCookieMirror() {
  const el = document.getElementById("sim-cookie");
  return el ? el.checked : false;
}

function wireSimulator(root) {
  // Header-count slider: the live value badge tracks the thumb.
  const headers = root.querySelector("#sim-headers");
  const headersValue = root.querySelector("#sim-headers-value");
  if (headers && headersValue) {
    const sync = () => { headersValue.textContent = headers.value; };
    headers.addEventListener("input", sync);
    sync();
  }
  // Enter in any text field scores, like the button does.
  const form = root.querySelector("#sim-composer");
  if (form) {
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      renderSimulator(root);
    });
  }
  // Preset chips: they just fill the path input.
  for (const chip of root.querySelectorAll(".sim-chip")) {
    chip.addEventListener("click", () => {
      root.querySelector("#sim-path").value = chip.dataset.path;
      root.querySelector("#sim-ev-protected").checked = false;
      root.querySelector("#sim-ev-decoy").checked = false;
      root.querySelector("#sim-ev-lead").checked = false;
      renderSimulator(root);
    });
  }
  // Event toggles also drive the path (the shortcut scenarios), so a
  // toggle click recomputes immediately to show what it changed.
  for (const id of ["sim-ev-protected", "sim-ev-decoy", "sim-ev-lead", "sim-ev-token"]) {
    root.querySelector("#" + id).addEventListener("change", () => {
      if (id === "sim-ev-lead" || id === "sim-ev-decoy" || id === "sim-ev-protected") {
        root.querySelector("#sim-path").value = readComposer(root).path;
        root.querySelector("#" + id).checked = true;
      }
      renderSimulator(root);
    });
  }
  const scoreButton = root.querySelector("#sim-score");
  scoreButton.addEventListener("click", () => renderSimulator(root));
  renderSimulator(root); // initial render with the defaults
}

function renderSimulator(root) {
  const c = readComposer(root);
  const session = seedSession(c.priors, c.events, c.clientIp);
  const authHint = c.events.honeytoken
    ? "Bearer " + (session.tokensMinted[0] || UI.FOREIGN_TOKEN)
    : "";
  const request = {
    method: "GET",
    path: c.path,
    client_ip: c.clientIp,
    user_agent: c.userAgent,
    header_count: c.headerCount,
    has_cookie: c.hasCookie,
    auth_hint: authHint,
    ts_ms: UI.T0,
  };
  const decision = decide(request, session, { allowlisted: c.allowlisted });
  const applied = applyMode(decision, c.mode);

  const out = root.querySelector("#sim-decision");
  out.setAttribute("aria-busy", "false");
  out.innerHTML = [
    panel("REQUEST AS SCORED", requestPanel(request, decision, c)),
    panel("SIGNALS", signalsPanel(decision)),
    panel("SCORE ARITHMETIC", arithmeticPanel(decision)),
    panel("VERDICT LADDER", ladderPanel(decision)),
    panel("ACTION IN " + c.mode.toUpperCase() + " MODE", actionPanel(decision, applied, c)),
    panel("SESSION AFTER THE REQUEST", sessionPanel(session, decision, c)),
  ].join("");
  out.hidden = false;
}

function panel(plate, bodyHtml) {
  return (
    '<section class="sim-sub">' +
    '<p class="sim-plate">' + plate + "</p>" +
    bodyHtml +
    "</section>"
  );
}

function requestPanel(request, decision, c) {
  const rows = [
    ["client", esc(request.client_ip) + (c.allowlisted ? ' <span class="sim-dim">(never scored)</span>' : "")],
    ["session key", "sha256(ip)[:32] = <code>" + esc(decision.sessionKey) + "</code>"],
    ["path", esc(request.path) + " \u2192 <code>" + esc(decision.normalizedPath ?? "\u2014") + "</code>" + (decision.dotEscape ? ' <span class="sim-flag">dot_escape</span>' : "")],
    ["user agent", esc(request.user_agent === "" ? "(empty)" : request.user_agent)],
    ["headers", String(request.header_count) + " (incl. Host and User-Agent)"],
    ["cookie", request.has_cookie ? "present" : "absent"],
  ];
  if (request.auth_hint) rows.push(["credential material", esc(request.auth_hint)]);
  if (c.events.leadFollow || c.events.honeytoken) {
    rows.push(["prior serve", "env-file-staging was served earlier in this session"]);
  }
  return kvTable(rows);
}

function signalsPanel(decision) {
  if (decision.neverScored) {
    return '<p class="sim-note">Never-scored client (loopback, owner range or verified bot): the engine returns <code>observe</code> with no signals and records no session state (I6, I12).</p>';
  }
  let html = "";
  if (decision.signals.length === 0) {
    html += '<p class="sim-note">No signal fired. Every gate below explains the one condition that kept its signal off.</p>';
  } else {
    html += '<ul class="sim-fired">';
    for (const s of decision.signals) {
      html += (
        '<li><code>' + s.reason + "</code> <strong>" + s.id + "</strong>" +
        '<span class="sim-w">' + s.weight + "</span>" +
        '<span class="sim-c">' + s.klass + "</span></li>"
      );
    }
    html += "</ul>";
  }
  html += '<details class="sim-gated" open><summary>Gated off (' + decision.gated.length + ")</summary><ul>";
  for (const g of decision.gated) {
    html += "<li><span class=\"sim-dim\"><code>" + g.id + "</code> \u2014 " + esc(g.reason) + "</span></li>";
  }
  html += "</ul></details>";
  return html;
}

function arithmeticPanel(decision) {
  if (decision.neverScored) return '<p class="sim-note">Nothing is scored for a never-scored client; the session is left untouched.</p>';
  const a = decision.arithmetic;
  const terms = a.terms.length ? a.terms.join(" + ") : "0";
  return (
    '<p class="sim-math"><code>' + terms + " = " + a.requestScore + "</code> request score</p>" +
    '<p class="sim-math"><code>' + a.cumBefore + " + " + a.requestScore + " = " + a.scoreAfter + "</code> cumulative after this request</p>" +
    '<p class="sim-note">request_class ' + (a.terms.length ? "<code>" + decision.requestClass + "</code>" : "(no signal)") + " \u00b7 the verdict rung reads the request's own score and class; history alone can tag (cum_before \u2265 25) but never escalates (I5).</p>"
  );
}

const RUNG_ORDER = ["observe", "tag", "decoy_route", "throttle", "ban"];
const RUNG_CLASS = { observe: "pass", tag: "tag", decoy_route: "decoy", throttle: "throttle", ban: "ban" };

function ladderPanel(decision) {
  let html = '<ol class="sim-ladder">';
  for (const rung of decision.ladder) {
    const isCurrent = rung.verdict === decision.verdict;
    const cls = "sim-rung sim-r-" + RUNG_CLASS[rung.verdict] + (isCurrent ? " is-current" : "") + (rung.holds && !isCurrent ? " is-held" : "");
    const why = rung.holds ? (isCurrent ? "chosen rung" : "condition held") : rung.why;
    html += (
      '<li class="' + cls + '">' +
      '<span class="sim-rung-name">' + rung.verdict + "</span>" +
      '<span class="sim-rung-why">' + esc(why) + "</span>" +
      (isCurrent ? '<span class="sim-rung-mark">VERDICT</span>' : "") +
      "</li>"
    );
  }
  html += "</ol>";
  if (decision.protectedCapped) {
    html += '<p class="sim-note">Protected-route cap (I4): the path is protected, so the verdict records at tag. honeytoken_use is the one exception that still bans.</p>';
  } else if (decision.pathProtected && decision.verdict === "ban") {
    html += '<p class="sim-note">Protected route, but honeytoken_use survives the cap (R3): a leaked fake credential in use is near-certain evidence regardless of route.</p>';
  }
  return html;
}

function actionPanel(decision, applied, c) {
  const answer = ACTION_ANSWERS[applied.action];
  let html =
    '<p class="sim-action"><span class="badge badge-' + RUNG_CLASS[applied.verdict] + '">' + applied.verdict + "</span> " +
    "<code>" + applied.action + "</code> \u2014 " + esc(answer) + "</p>";
  if (applied.decoyId) {
    html += '<p class="sim-note">Serves catalog entry <code>' + esc(applied.decoyId) + "</code>; its leads become known to the session and its honeytokens are minted.</p>";
  }
  if (applied.banTtlMs) {
    html += '<p class="sim-note">Ban TTL ' + applied.banTtlMs + " ms (30 minutes), single address, reversible (I5).</p>";
  }
  if (c.mode === "look" && decision.verdict !== applied.verdict) {
    html += '<p class="sim-note">The engine verdict was <code>' + decision.verdict + "</code>; in look mode the recorded verdict caps at tag (I9 \u2014 observe only).</p>";
  }
  if (c.mode === "tripwires" && (decision.verdict === "throttle" || decision.verdict === "ban")) {
    html += '<p class="sim-note">Tripwires mode baits and records: the <code>' + decision.verdict + "</code> verdict is kept as evidence, but the action passes.</p>";
  }
  if (c.mode === "protect" && decision.verdict !== "observe" && decision.verdict !== "tag") {
    html += '<p class="sim-note">Protect mode with the enforcement opt-in: verdicts act (a kill switch or missing opt-in drops every action to pass, I9).</p>';
  }
  return html;
}

function sessionPanel(session, decision, c) {
  if (decision.neverScored) {
    return '<p class="sim-note">No session state is recorded for a never-scored client (I12).</p>';
  }
  const distinctUas = new Set(session.uaSeen.map((u) => u.ua)).size;
  const distinctUnknowns = new Set(session.unknownPaths.map((p) => p.path)).size;
  const rows = [
    ["requests this epoch", String(session.requestCount)],
    ["cumulative score", String(session.cumulative)],
    ["cookie ever", session.cookieEver ? "yes" : "no"],
    ["distinct UAs in 300 s", String(distinctUas)],
    ["distinct unknown paths in 60 s", String(distinctUnknowns)],
    ["decoys served", session.decoysServed.length ? session.decoysServed.map(esc).join(", ") : "none"],
    ["leads known", session.leadsKnown.size ? session.leadsKnown.size + " path" + (session.leadsKnown.size === 1 ? "" : "s") : "none"],
    ["honeytokens minted", session.tokensMinted.length ? "<code>" + session.tokensMinted.map(esc).join("</code>, <code>") + "</code>" : "none"],
  ];
  if (c.events.honeytoken && session.tokensMinted.length && decision.verdict !== "decoy_route") {
    rows.push(["presented token", "matches the minted db_password honeytoken \u2192 honeytoken_use"]);
  }
  return kvTable(rows);
}

function kvTable(rows) {
  let html = '<dl class="sim-kv">';
  for (const [k, v] of rows) {
    html += "<dt>" + esc(k) + "</dt><dd>" + v + "</dd>";
  }
  return html + "</dl>";
}

/* ---- Golden vector stepper (demo sugar over the same engine) ---- */

function wireStepper(root) {
  const holder = root.querySelector("#sim-vectors");
  if (!holder) return;
  const vectors = JSON.parse(holder.textContent);
  const select = root.querySelector("#sim-case");
  const stepLabel = root.querySelector("#sim-step-label");
  const stepPrev = root.querySelector("#sim-prev");
  const stepNext = root.querySelector("#sim-next");
  const out = root.querySelector("#sim-stepper-out");
  let index = 0; // request index within the case

  const cases = vectors.cases;
  for (const c of cases) {
    const opt = document.createElement("option");
    opt.value = c.id;
    opt.textContent = c.id + " (" + c.requests.length + " req)";
    select.appendChild(opt);
  }

  const replayTo = (caseIdx, reqIdx) => {
    const c = cases[caseIdx];
    const session = newSession();
    const allow = (c.allowlisted_ips || []).some((ip) => ip.split("/")[0] === c.client_ip);
    let current = null;
    for (let i = 0; i <= reqIdx; i++) {
      const r = c.requests[i];
      const d = decide({ ...r, client_ip: c.client_ip }, session, { allowlisted: allow });
      if (i === reqIdx) current = { i, r, d, exp: c.expected[i] };
    }
    return { c, current };
  };

  const render = () => {
    const caseIdx = select.selectedIndex < 0 ? 0 : select.selectedIndex;
    if (index >= cases[caseIdx].requests.length) index = cases[caseIdx].requests.length - 1;
    if (index < 0) index = 0;
    const { c, current } = replayTo(caseIdx, index);
    const { i, r, d, exp } = current;
    const match =
      JSON.stringify(d.signals.map((s) => s.id)) === JSON.stringify(exp.signals) &&
      d.verdict === exp.verdict && d.score === exp.score && d.reasonCode === exp.reason_code;
    stepLabel.textContent = "request " + (i + 1) + " of " + c.requests.length + " \u00b7 " + c.client_ip;
    stepPrev.disabled = index === 0;
    stepNext.disabled = index === c.requests.length - 1;
    const cell = (label, value, ok) =>
      '<div class="sim-cmp' + (ok ? "" : " is-bad") + '"><p class="sim-cmp-k">' + label + "</p><p>" + value + "</p></div>";
    out.innerHTML =
      '<p class="sim-reqline"><code>' + esc(r.method) + " " + esc(r.path) + "</code> \u00b7 UA <code>" + esc(r.user_agent === "" ? "(empty)" : r.user_agent) + "</code> \u00b7 " + r.header_count + " headers" + (r.auth_hint ? " \u00b7 credential material" : "") + "</p>" +
      '<div class="sim-cmp-grid">' +
      cell("expected", esc(exp.signals.join(", ") || "\u2014") + "<br>" + esc(exp.verdict) + " \u00b7 score " + exp.score + " \u00b7 " + esc(exp.reason_code), true) +
      cell("computed", esc(d.signals.map((s) => s.id).join(", ") || "\u2014") + "<br>" + esc(d.verdict) + " \u00b7 score " + d.score + " \u00b7 " + esc(d.reasonCode), match) +
      "</div>" +
      '<p class="sim-note">' + (match ? "match" : "MISMATCH") + " \u2014 session state is replayed request by request, exactly like the harness does.</p>";
  };

  select.addEventListener("change", () => { index = 0; render(); });
  stepPrev.addEventListener("click", () => { index -= 1; render(); });
  stepNext.addEventListener("click", () => { index += 1; render(); });
  render();
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootPlayground);
  } else {
    bootPlayground();
  }
}
