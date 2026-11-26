// Mirage decision engine — the TypeScript port of spec/SIGNALS.md v1.1.0.
//
// This module mirrors the Go core engine semantics EXACTLY: the golden
// vectors (spec/golden-vectors/vectors.json) are the conformance gate and any
// divergence is a bug in this port, never in the vectors. The engine is
// deterministic, synchronous and side-effect free apart from its per-IP
// session map (see the known-limits note at MAX_SESSIONS below).

import { sha256Hex } from "./sha256";
import { CATALOG, PROTECTED_ROUTES, SCANNER_PATHS, UA_SUSPICIOUS, UA_VERIFIED_BOTS } from "./generated/data";
import type { Catalog, CatalogEntry } from "./generated/data";

export const SPEC_VERSION = "1.1.0";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SignalId =
  | "scanner_path"
  | "decoy_hit"
  | "decoy_lead_follow"
  | "honeytoken_use"
  | "path_enumeration"
  | "ua_suspicious"
  | "ua_rotation"
  | "no_cookie_persistence"
  | "headers_sparse"
  | "ua_missing"
  | "tooling_curl";

export type SignalClass = "high" | "medium";

export interface Signal {
  readonly id: SignalId;
  readonly weight: number;
  readonly class: SignalClass;
  readonly reason: string;
}

export type Verdict = "observe" | "tag" | "decoy_route" | "throttle" | "ban";

export interface Decision {
  readonly sessionKey: string;
  readonly specVersion: string;
  /** Fired signals in evaluation order (SIGNALS §4 table order). */
  readonly signals: readonly Signal[];
  readonly requestScore: number;
  /** Session cumulative score AFTER this request (SIGNALS §7). */
  readonly score: number;
  readonly verdict: Verdict;
  readonly reasonCode: string;
  readonly banTtlMs: number | null;
  /** Catalog entry to serve; set only when verdict === "decoy_route". */
  readonly decoyId: string | null;
}

/** One scored request (SIGNALS §1). Adapters pass neutral values for fields they cannot see. */
export interface Request {
  readonly method: string;
  /** Raw path including dot segments and query string. */
  readonly path: string;
  readonly clientIp: string;
  readonly userAgent: string;
  /** Count of ALL request headers, including Host and User-Agent. */
  readonly headerCount: number;
  readonly hasCookie: boolean;
  /** Optional credential material (query, Authorization header, body keys). */
  readonly authHint?: string;
  readonly tsMs: number;
  readonly allowlisted: boolean;
}

/** Tunables + data snapshots. Injected by tests; built by defaultRules() for production. */
export interface Rules {
  readonly protectedRoutes: readonly string[];
  readonly scannerPaths: readonly string[];
  readonly uaSuspicious: readonly string[];
  readonly uaVerifiedBots: readonly string[];
  readonly catalog: Catalog;
  readonly sessionTtlMs: number;
  readonly uaWindowMs: number;
  readonly enumWindowMs: number;
  readonly enumThreshold: number;
  readonly uaRotationThreshold: number;
  readonly banTtlMs: number;
}

// ---------------------------------------------------------------------------
// Signal table (SIGNALS §4) — fixed order, weights, classes and reason codes.
// ---------------------------------------------------------------------------

const SIGNAL_TABLE: readonly Signal[] = [
  { id: "scanner_path", weight: 25, class: "high", reason: "SIG-101" },
  { id: "decoy_hit", weight: 30, class: "high", reason: "SIG-102" },
  { id: "decoy_lead_follow", weight: 40, class: "high", reason: "SIG-103" },
  { id: "honeytoken_use", weight: 50, class: "high", reason: "SIG-104" },
  { id: "path_enumeration", weight: 25, class: "high", reason: "SIG-105" },
  { id: "ua_suspicious", weight: 15, class: "medium", reason: "SIG-106" },
  { id: "ua_rotation", weight: 20, class: "medium", reason: "SIG-107" },
  { id: "no_cookie_persistence", weight: 15, class: "medium", reason: "SIG-108" },
  { id: "headers_sparse", weight: 10, class: "medium", reason: "SIG-109" },
  { id: "ua_missing", weight: 10, class: "medium", reason: "SIG-110" },
  { id: "tooling_curl", weight: 15, class: "medium", reason: "SIG-111" },
];

const REASON_NONE = "SIG-000";

/**
 * Honeytoken string for a (session, decoy entry, token id) triple. The engine
 * registers this exact string when it serves a decoy and later fires SIG-104
 * when it sees it in credential material. render.ts embeds the SAME formula
 * in {{TOKEN:id}} placeholders, so what the attacker reads is what the
 * engine detects.
 */
export function mintHoneytoken(sessionKey: string, entryId: string, tokenId: string): string {
  return "mrg_live_" + sha256Hex(`${sessionKey}:${entryId}:${tokenId}`).slice(0, 24);
}

// ---------------------------------------------------------------------------
// Path handling (SIGNALS §3)
// ---------------------------------------------------------------------------

function stripTrailingSlash(p: string): string {
  return p.length > 1 && p.endsWith("/") ? p.slice(0, -1) : p;
}

/**
 * Strip the query string and resolve dot segments left to right (SIGNALS §3).
 * `..` at the root pops nothing: the path clamps at "/" and dot_escape is
 * flagged (scanner-style path fuzzing). Everything else — including a
 * trailing slash — is preserved verbatim, because matching against the decoy
 * and protected lists is exact on the normalized path; the one documented
 * exception (scanner-list trailing-slash insensitivity, §3.3) is applied at
 * match time in matchesScanner.
 */
export function normalizePath(rawPath: string): { path: string; dotEscape: boolean } {
  let p = rawPath;
  const q = p.indexOf("?");
  if (q !== -1) p = p.slice(0, q);
  if (!p.startsWith("/")) p = "/" + p; // defensive: Workers URLs are always absolute

  const segments = p.split("/"); // "" head, then one per segment ("" tail if trailing slash)
  const out: string[] = [];
  let dotEscape = false;
  for (let i = 1; i < segments.length; i++) {
    const seg = segments[i] ?? "";
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (out.length === 0) dotEscape = true; // clamped at the root
      else out.pop();
      continue;
    }
    out.push(seg);
  }
  let normalized = "/" + out.join("/");
  if (out.length > 0 && p.endsWith("/")) normalized += "/";
  return { path: normalized, dotEscape };
}

// ---------------------------------------------------------------------------
// Session state (SIGNALS §7)
// ---------------------------------------------------------------------------

interface Timestamped<T> {
  readonly value: T;
  readonly ts: number;
}

interface SessionState {
  lastTs: number;
  requestCount: number;
  cumulativeScore: number;
  cookieEver: boolean;
  uaSeen: Timestamped<string>[];
  unknownPaths: Timestamped<string>[];
  decoysServed: string[];
  leadsKnown: Set<string>;
  tokensMinted: string[];
}

function newSessionState(): SessionState {
  return {
    lastTs: 0,
    requestCount: 0,
    cumulativeScore: 0,
    cookieEver: false,
    uaSeen: [],
    unknownPaths: [],
    decoysServed: [],
    leadsKnown: new Set(),
    tokensMinted: [],
  };
}

/** Keep only entries inside the trailing window relative to `tsMs` (inclusive, SIGNALS §7). */
function pruneWindow<T>(entries: Timestamped<T>[], tsMs: number, windowMs: number): void {
  while (entries.length > 0 && tsMs - (entries[0]?.ts ?? tsMs) > windowMs) {
    entries.shift();
  }
}

/** reason_code = highest-weight signal; ties resolve to the earliest in evaluation order (canon 3). */
function reasonCodeOf(signals: readonly Signal[]): string {
  let best = 0;
  for (let i = 1; i < signals.length; i++) {
    if ((signals[i]?.weight ?? 0) > (signals[best]?.weight ?? 0)) best = i;
  }
  return signals[best]?.reason ?? REASON_NONE;
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/**
 * Hard cap on tracked sessions. KNOWN LIMIT: this map is isolate-local — a
 * Worker isolate is ephemeral, per-colo and may be recycled at any time, so
 * session state here is best-effort and always a subset of what the Go core
 * sees. Durable enforcement and cross-colo state belong to the core; the
 * worker only needs enough memory to catch in-flight scanning sessions.
 * Oldest-lastSeen sessions are evicted first: Map iteration order doubles as
 * the LRU order because every request re-inserts its key.
 */
const MAX_SESSIONS = 50_000;

export class Engine {
  private readonly rules: Rules;
  private readonly sessions = new Map<string, SessionState>();
  // Precomputed lookups (Rules is treated as immutable).
  private readonly scannerPaths: Set<string>;
  private readonly decoyByPath: Map<string, CatalogEntry>;
  private readonly allLeads: Set<string>;
  private readonly uaSuspiciousLower: string[];
  private readonly uaVerifiedBotsLower: string[];

  constructor(rules: Rules) {
    this.rules = rules;
    // Trailing-slash-insensitive compare (SIGNALS §3.3): both sides are
    // matched with the trailing slash stripped, so the list entry
    // "/phpmyadmin-old/" matches the request path "/phpmyadmin-old" and vice
    // versa. List entries are otherwise kept exactly as in the data file.
    this.scannerPaths = new Set(rules.scannerPaths.map(stripTrailingSlash));
    this.decoyByPath = new Map(rules.catalog.entries.map((e) => [e.path, e]));
    // Canon decision 4: unknown-path counting excludes ALL catalog lead
    // paths, not only the ones already served — a lead is Mirage territory.
    this.allLeads = new Set(rules.catalog.entries.flatMap((e) => e.leads));
    this.uaSuspiciousLower = rules.uaSuspicious.map((s) => s.toLowerCase());
    this.uaVerifiedBotsLower = rules.uaVerifiedBots.map((s) => s.toLowerCase());
  }

  decide(req: Request): Decision {
    // Session key: first 32 hex chars of sha256(client_ip) (SIGNALS §2).
    const sessionKey = sha256Hex(req.clientIp).slice(0, 32);

    // Never-scored identities (SIGNALS §2): allowlisted addresses and
    // verified-bot user agents produce observe with NO session state, so a
    // bot never meets a trap (I12) and an owner IP never accrues score.
    if (req.allowlisted || this.isVerifiedBot(req.userAgent)) {
      return this.noSignalDecision(sessionKey);
    }

    const { path: normPath, dotEscape } = normalizePath(req.path);
    const state = this.stateFor(sessionKey, req.tsMs);
    const cumBefore = state.cumulativeScore;

    // --- session bookkeeping, then window pruning (SIGNALS §7) ---
    state.requestCount += 1;
    if (req.hasCookie) state.cookieEver = true;
    if (req.userAgent !== "") {
      state.uaSeen.push({ value: req.userAgent, ts: req.tsMs });
      pruneWindow(state.uaSeen, req.tsMs, this.rules.uaWindowMs);
    }
    if (this.isUnknownPath(normPath)) {
      state.unknownPaths.push({ value: normPath, ts: req.tsMs });
      pruneWindow(state.unknownPaths, req.tsMs, this.rules.enumWindowMs);
    }

    // --- signals, in table order 1→11 (SIGNALS §4). A later signal may
    //     read, but never change, the outcome of an earlier one. ---
    const fired: boolean[] = new Array<boolean>(SIGNAL_TABLE.length).fill(false);

    // 1. scanner_path: list match OR dot_escape (SIG-101).
    fired[0] = this.matchesScanner(normPath) || dotEscape;

    // 2. decoy_hit, suppressed when scanner_path fired (SIG-102, §4.2): a
    //    scanner-list hit already fully explains the request.
    const decoyEntry = this.decoyByPath.get(normPath) ?? null;
    fired[1] = decoyEntry !== null && !fired[0];

    // 3. decoy_lead_follow (SIG-103): a path that exists only inside a decoy
    //    served earlier to this session.
    fired[2] = state.leadsKnown.has(normPath);

    // 4. honeytoken_use (SIG-104): a token minted for this session appears
    //    in the credential material visible to the adapter.
    const authHint = req.authHint ?? "";
    fired[3] = authHint !== "" && state.tokensMinted.some((t) => authHint.includes(t));

    // 5. path_enumeration (SIG-105): >= 8 distinct unknown paths in the
    //    trailing 60 s window. The window already includes this request's
    //    path (recorded above), matching the hand-computed derivations.
    fired[4] = new Set(state.unknownPaths.map((e) => e.value)).size >= this.rules.enumThreshold;

    // Ungating set for tooling_curl and ua_rotation: the five high signals
    // (canon decision 1). Medium signals never ungate, and prior session
    // score never ungates (§6.1).
    const ungated = fired[0] || fired[1] || fired[2] || fired[3] || fired[4];

    // 6. ua_suspicious (SIG-106): case-insensitive substring match.
    const uaLower = req.userAgent.toLowerCase();
    fired[5] = this.uaSuspiciousLower.some((s) => s !== "" && uaLower.includes(s));

    // 7. ua_rotation (SIG-107): >= 4 distinct non-empty UAs in the trailing
    //    300 s AND a same-request high signal (gated, §6.2). A session that
    //    merely rotates UAs is never scored on rotation alone.
    const distinctUas = new Set(state.uaSeen.map((e) => e.value)).size;
    fired[6] = distinctUas >= this.rules.uaRotationThreshold && ungated;

    // 8. no_cookie_persistence (SIG-108, gated §6.3): fires only in an
    //    otherwise-clean session — request count >= 5 including this request
    //    (canon 5), never a cookie (this one included), cumulative score 0
    //    before this request, and none of signals 1-7 fired (canon 2).
    //    headers_sparse / ua_missing / tooling_curl may co-fire with it.
    const predecessorsFired = fired[0] || fired[1] || fired[2] || fired[3] || fired[4] || fired[5] || fired[6];
    fired[7] = state.requestCount >= 5 && !state.cookieEver && cumBefore === 0 && !predecessorsFired;

    // 9. headers_sparse (SIG-109): fires on every sparse request.
    fired[8] = req.headerCount < 4;

    // 10. ua_missing (SIG-110): header absent or empty string.
    fired[9] = req.userAgent === "";

    // 11. tooling_curl (SIG-111, gated §6.1): curl/ UA plus an earlier
    //     same-request high signal; headers_sparse does NOT ungate.
    fired[10] = uaLower.includes("curl/") && ungated;

    const signals = SIGNAL_TABLE.filter((_, i) => fired[i]);
    const requestScore = signals.reduce((sum, s) => sum + s.weight, 0);
    const requestClassHigh = signals.some((s) => s.class === "high");
    const pathProtected = this.isProtected(normPath);

    // --- verdict ladder (SIGNALS §5): the highest rung whose condition
    //     holds wins. Rungs 2-4 use only the request's own score and class;
    //     history alone can tag (rung 1) but never escalates (§7). ---
    let verdict: Verdict = "observe";
    if (requestScore >= 15 || cumBefore >= 25) verdict = "tag";
    if (requestScore >= 25 && requestClassHigh && decoyEntry !== null && !pathProtected) verdict = "decoy_route";
    if (requestScore >= 40) verdict = "throttle";
    const honeytokenFired = fired[3];
    if (honeytokenFired || (fired[2] && !pathProtected) || (requestScore >= 60 && requestClassHigh)) {
      verdict = "ban";
    }
    // Protected-route cap (I4): at most tag, except honeytoken_use which
    // survives the cap and produces ban (R3 exception: a leaked fake
    // credential in use is near-certain evidence regardless of route).
    if (pathProtected && verdict !== "observe") {
      verdict = honeytokenFired ? "ban" : "tag";
    }

    // --- record ---
    state.cumulativeScore += requestScore;
    // Canon decision 6: decoy serving (lead registration + honeytoken
    // minting) happens only on decoy_route; throttle and ban do not serve.
    if (verdict === "decoy_route" && decoyEntry !== null) {
      state.decoysServed.push(decoyEntry.id);
      for (const lead of decoyEntry.leads) state.leadsKnown.add(lead);
      for (const token of decoyEntry.honeytokens) {
        state.tokensMinted.push(mintHoneytoken(sessionKey, decoyEntry.id, token.id));
      }
    }

    return {
      sessionKey,
      specVersion: SPEC_VERSION,
      signals,
      requestScore,
      score: state.cumulativeScore,
      verdict,
      reasonCode: reasonCodeOf(signals),
      banTtlMs: verdict === "ban" ? this.rules.banTtlMs : null,
      decoyId: verdict === "decoy_route" ? (decoyEntry?.id ?? null) : null,
    };
  }

  private noSignalDecision(sessionKey: string): Decision {
    return {
      sessionKey,
      specVersion: SPEC_VERSION,
      signals: [],
      requestScore: 0,
      score: 0,
      verdict: "observe",
      reasonCode: REASON_NONE,
      banTtlMs: null,
      decoyId: null,
    };
  }

  /** Expiry check (§7) + LRU touch + hard-cap eviction. */
  private stateFor(sessionKey: string, tsMs: number): SessionState {
    let state = this.sessions.get(sessionKey);
    if (state !== undefined && tsMs - state.lastTs > this.rules.sessionTtlMs) {
      this.sessions.delete(sessionKey); // expired: a new session epoch begins
      state = undefined;
    }
    if (state === undefined) state = newSessionState();
    state.lastTs = tsMs;
    // LRU touch: re-insert so Map order mirrors lastSeen recency.
    this.sessions.delete(sessionKey);
    this.sessions.set(sessionKey, state);
    while (this.sessions.size > MAX_SESSIONS) {
      const oldest = this.sessions.keys().next().value;
      if (oldest === undefined) break;
      this.sessions.delete(oldest);
    }
    return state;
  }

  private isVerifiedBot(userAgent: string): boolean {
    const ua = userAgent.toLowerCase();
    return this.uaVerifiedBotsLower.some((s) => s !== "" && ua.includes(s));
  }

  private matchesScanner(normPath: string): boolean {
    return this.scannerPaths.has(stripTrailingSlash(normPath));
  }

  /**
   * Protected routes (I4): exact match, or prefix match when the route is a
   * directory form ("/wp-admin/", "/api/") or the path extends it with a
   * segment ("/wp-login.php/…"). "/checkout2" does NOT match "/checkout".
   */
  private isProtected(normPath: string): boolean {
    for (const route of this.rules.protectedRoutes) {
      if (normPath === route) return true;
      if (normPath.startsWith(route) && (route.endsWith("/") || normPath[route.length] === "/")) {
        return true;
      }
    }
    return false;
  }

  /** Unknown = not "/", not protected, not a scanner path, not a decoy, not a catalog lead (§4.5 + canon 4). */
  private isUnknownPath(normPath: string): boolean {
    return (
      normPath !== "/" &&
      !this.isProtected(normPath) &&
      !this.matchesScanner(normPath) &&
      !this.decoyByPath.has(normPath) &&
      !this.allLeads.has(normPath)
    );
  }
}

/** Policy + data defaults mirroring spec/golden-vectors/vectors.json (policy block). */
export function defaultRules(): Rules {
  return {
    protectedRoutes: PROTECTED_ROUTES,
    scannerPaths: SCANNER_PATHS,
    uaSuspicious: UA_SUSPICIOUS,
    uaVerifiedBots: UA_VERIFIED_BOTS,
    catalog: CATALOG,
    sessionTtlMs: 30 * 60 * 1000,
    uaWindowMs: 300_000,
    enumWindowMs: 60_000,
    enumThreshold: 8,
    uaRotationThreshold: 4,
    banTtlMs: 30 * 60 * 1000,
  };
}
