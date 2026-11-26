// Mirage Cloudflare Worker adapter (ADAPTER-PROTOCOL v1).
//
// In-process transport (§1): the engine is bundled into the Worker and the
// decision is a synchronous function call. The handler is fail-open by
// construction (§3, §5.1): any internal error — engine throw, deadline
// overrun, decoy render failure — passes the request to the origin
// unmodified. Enforcement is opt-in and stateless here: Workers are
// stateless across isolates, so durable bans/throttles belong to the Go
// core; this adapter only applies per-request local actions.
//
// Zero runtime dependencies: imports are this package's own modules and the
// generated data snapshot only.

import { Engine, defaultRules } from "./engine";
import type { Decision, Request as MirageRequest, Verdict } from "./engine";
import { renderDecoy } from "./render";
import { CATALOG } from "./generated/data";
import type { CatalogEntry, CatalogPersona } from "./generated/data";

export interface Env {
  /**
   * v1: no bindings required. MIRAGE_TOKENS is reserved for a future
   * honeytoken-registry binding; absent or present, it changes nothing in
   * the decision path today.
   */
  MIRAGE_TOKENS?: string;
}

export const PROTOCOL_VERSION = "1";

/** ADAPTER-PROTOCOL §2 recommends a 5 ms decision budget; overrun ⇒ fail-open. */
const DECISION_DEADLINE_MS = 5;
/** ADAPTER-PROTOCOL §4: ring cap defaults to 10 000 events, oldest dropped. */
const DEFAULT_EVENT_CAPACITY = 10_000;

// Static bodies: never reflect attacker input into a response (I7).
const THROTTLE_BODY = "Too many requests. Please retry later.";
const BAN_BODY = "Request blocked.";

const ENTRY_BY_ID = new Map<string, CatalogEntry>(CATALOG.entries.map((e) => [e.id, e]));
const PERSONA_BY_ID = new Map<string, CatalogPersona>(CATALOG.personas.map((p) => [p.id, p]));

// ---------------------------------------------------------------------------
// Protocol wire shapes (ADAPTER-PROTOCOL §3/§4)
// ---------------------------------------------------------------------------

export type ProtocolAction = "pass" | "serve_decoy" | "throttle" | "ban";

export interface ProtocolDecision {
  readonly protocolVersion: string;
  readonly specVersion?: string;
  readonly verdict: Verdict;
  readonly action: ProtocolAction;
  readonly decoyId: string | null;
  readonly sessionKey: string | null;
  readonly reasonCode: string;
  readonly requestScore: number;
  readonly score: number;
  readonly signals: readonly string[];
  readonly banTtlMs: number | null;
}

export interface AdapterEvent {
  readonly protocolVersion: string;
  readonly tsMs: number;
  readonly sessionKey: string | null;
  readonly clientIp: string;
  readonly method: string;
  readonly path: string;
  readonly decision: ProtocolDecision;
}

export interface EventStats {
  readonly capacity: number;
  readonly size: number;
  readonly dropped: number;
  readonly failOpen: number;
}

/** The fixed fail-open decision (ADAPTER-PROTOCOL §3). */
function failOpenDecision(): ProtocolDecision {
  return {
    protocolVersion: PROTOCOL_VERSION,
    verdict: "observe",
    action: "pass",
    decoyId: null,
    sessionKey: null,
    reasonCode: "SIG-000",
    requestScore: 0,
    score: 0,
    signals: [],
    banTtlMs: null,
  };
}

function toProtocolDecision(d: Decision): ProtocolDecision {
  const action: ProtocolAction =
    d.verdict === "observe" || d.verdict === "tag"
      ? "pass"
      : d.verdict === "decoy_route"
        ? "serve_decoy"
        : d.verdict;
  return {
    protocolVersion: PROTOCOL_VERSION,
    specVersion: d.specVersion,
    verdict: d.verdict,
    action,
    decoyId: d.decoyId,
    sessionKey: d.sessionKey,
    reasonCode: d.reasonCode,
    requestScore: d.requestScore,
    score: d.score,
    signals: d.signals.map((s) => s.id),
    banTtlMs: d.banTtlMs,
  };
}

// ---------------------------------------------------------------------------
// Bounded event ring (ADAPTER-PROTOCOL §4)
// ---------------------------------------------------------------------------

/**
 * Fixed-capacity ring with drop-oldest semantics. Pushing is a plain array
 * write, so emission can never block the hot path. KNOWN LIMIT: events live
 * only in the isolate's memory; durable shipping (Analytics Engine / Queues
 * binding) is a config-later feature. The ring exists so the conformance
 * contract — bounded, non-blocking, drop-counter visible — is honored from
 * day one.
 */
class EventRing {
  private readonly slots: Array<AdapterEvent | undefined>;
  private head = 0;
  private size = 0;
  dropped = 0;

  constructor(readonly capacity: number) {
    this.slots = new Array<AdapterEvent | undefined>(capacity).fill(undefined);
  }

  push(event: AdapterEvent): void {
    if (this.capacity === 0) {
      this.dropped++;
      return;
    }
    const tail = (this.head + this.size) % this.capacity;
    this.slots[tail] = event;
    if (this.size < this.capacity) {
      this.size++;
    } else {
      // Full: the write above replaced the oldest event.
      this.head = (this.head + 1) % this.capacity;
      this.dropped++;
    }
  }

  get length(): number {
    return this.size;
  }
}

// ---------------------------------------------------------------------------
// Request translation
// ---------------------------------------------------------------------------

/**
 * Extract the raw path (dot segments + query) from an absolute URL without
 * URL-path normalization: WHATWG URL parsing resolves ".." segments, which
 * would erase exactly the evidence dot_escape (SIGNALS §3.2) must see.
 * Exported so tests can pin the no-normalization property — note that some
 * runtimes (e.g. Node's undici) already normalize inside the Request
 * constructor; this function guarantees the Worker never adds more.
 */
export function rawPathFromUrl(url: string): string {
  const schemeEnd = url.indexOf("://");
  const pathStart = schemeEnd === -1 ? url.indexOf("/") : url.indexOf("/", schemeEnd + 3);
  return pathStart === -1 ? "/" : url.slice(pathStart);
}

function toEngineRequest(request: Request, tsMs: number): MirageRequest {
  // Client identity (SIGNALS §2): on Cloudflare the edge itself is the
  // trusted proxy — CF-Connecting-IP is set by the platform and cannot be
  // spoofed by clients. When it is absent (local dev, non-CF deployments)
  // the empty string is used as an opaque identity; spoofable headers like
  // X-Forwarded-For are deliberately never scored (I6).
  const clientIp = request.headers.get("CF-Connecting-IP") ?? "";
  const userAgent = request.headers.get("User-Agent") ?? "";
  const cookie = request.headers.get("Cookie") ?? "";
  const authorization = request.headers.get("Authorization");
  const path = rawPathFromUrl(request.url);
  const q = path.indexOf("?");
  const query = q === -1 ? "" : path.slice(q + 1);

  // header_count contract: ALL request headers of the incoming request,
  // including Host and User-Agent (SIGNALS §1).
  let headerCount = 0;
  request.headers.forEach(() => {
    headerCount++;
  });

  // auth_hint: the credential material this adapter can see without reading
  // the body — the Authorization header and the query string (SIGNALS §1).
  // Body keys would require cloning the request; that cost/benefit tradeoff
  // is documented as a v1 reduction (the Go core sees bodies when deployed
  // as middleware).
  const authHint = [authorization, query].filter((s) => s !== undefined && s !== "").join(" ");

  return {
    method: request.method,
    path,
    clientIp,
    userAgent,
    headerCount,
    hasCookie: cookie !== "",
    authHint: authHint === "" ? undefined : authHint,
    tsMs,
    // v1 worker has no allowlist: owner-IP allowlists live in the Go core
    // config where the authoritative client-IP walk happens.
    allowlisted: false,
  };
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export interface HandlerDeps {
  /** Decision function; defaults to a fresh Engine over defaultRules(). */
  decide?: (req: MirageRequest) => Decision;
  /** Injectable clock for tests. */
  now?: () => number;
  /** Injectable origin fetch for tests; defaults to the runtime's fetch. */
  originFetch?: (request: Request) => Promise<Response>;
  /** Ring capacity override for tests; defaults to 10 000 (protocol default). */
  eventCapacity?: number;
}

export interface MirageHandler {
  fetch(request: Request, env?: Env): Promise<Response>;
  getEventStats(): EventStats;
}

/** Build a handler. `createHandler()` gives the production wiring; tests inject deps. */
export function createHandler(deps: HandlerDeps = {}): MirageHandler {
  const engine = new Engine(defaultRules());
  const decide = deps.decide ?? ((req: MirageRequest) => engine.decide(req));
  const now = deps.now ?? Date.now;
  const originFetch = deps.originFetch ?? ((request: Request) => fetch(request));
  const ring = new EventRing(deps.eventCapacity ?? DEFAULT_EVENT_CAPACITY);
  let failOpenCount = 0;

  function emit(engineReq: MirageRequest, decision: ProtocolDecision, tsMs: number): void {
    ring.push({
      protocolVersion: PROTOCOL_VERSION,
      tsMs,
      sessionKey: decision.sessionKey,
      clientIp: engineReq.clientIp,
      method: engineReq.method,
      path: engineReq.path,
      decision,
    });
  }

  function recordFailOpen(engineReq: MirageRequest, tsMs: number): void {
    failOpenCount++;
    emit(engineReq, failOpenDecision(), tsMs);
  }

  /** Translate a verdict into the adapter's local action; null means pass to origin. */
  function act(decision: Decision): Response | null {
    switch (decision.verdict) {
      case "observe":
      case "tag":
        return null;
      case "decoy_route": {
        const entry = decision.decoyId === null ? undefined : ENTRY_BY_ID.get(decision.decoyId);
        const persona = entry === undefined ? undefined : PERSONA_BY_ID.get(entry.persona);
        if (entry === undefined || persona === undefined) {
          throw new Error(`decoy "${decision.decoyId}" missing from catalog snapshot`);
        }
        // Render locally from the snapshot; NEVER a network fetch and never
        // a redirect (I3, I2, I8).
        const rendered = renderDecoy(entry, persona, decision.sessionKey);
        return new Response(rendered.body, { status: rendered.status, headers: rendered.headers });
      }
      case "throttle":
        // Local throttle only; the origin is protected but never hard-failed
        // by Mirage itself (§3). no-store so shared caches don't extend it.
        return new Response(THROTTLE_BODY, {
          status: 429,
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "Retry-After": "30",
            "Cache-Control": "no-store",
          },
        });
      case "ban":
        // Local block with the short TTL; no state is persisted (the Go core
        // owns enforcement). TTL is reported in seconds, matching the
        // Retry-After convention; the decision itself carries milliseconds.
        return new Response(BAN_BODY, {
          status: 403,
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "X-Mirage-Ban-Ttl": String(Math.floor((decision.banTtlMs ?? 0) / 1000)),
            "Cache-Control": "no-store",
          },
        });
    }
  }

  async function handleRequest(request: Request): Promise<Response> {
    const engineReq = toEngineRequest(request, now());
    const start = now();
    let direct: Response | null = null;
    try {
      const decision = decide(engineReq);
      if (now() - start <= DECISION_DEADLINE_MS) {
        direct = act(decision);
        emit(engineReq, toProtocolDecision(decision), now());
      } else {
        recordFailOpen(engineReq, now());
      }
    } catch {
      // Any internal error → fail-open decision + pass-through (§3, §5.1).
      recordFailOpen(engineReq, now());
    }
    // Fail-open and observe/tag all land here: the request reaches the
    // origin unmodified. originFetch stays outside the try so an origin
    // network error is never mistaken for a Mirage error (and never retried).
    return direct ?? originFetch(request);
  }

  return {
    fetch: handleRequest,
    getEventStats: () => ({ capacity: ring.capacity, size: ring.length, dropped: ring.dropped, failOpen: failOpenCount }),
  };
}

const defaultHandler = createHandler();

/** Stats of the module-level (default export) handler's event ring; for tests and ops probes. */
export function getEventStats(): EventStats {
  return defaultHandler.getEventStats();
}

export default {
  fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    // env (MIRAGE_TOKENS) is accepted for the Workers contract but has no
    // decision effect in v1; see the Env comment.
    return defaultHandler.fetch(request, env);
  },
} satisfies ExportedHandler<Env>;
