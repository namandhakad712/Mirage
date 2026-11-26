// Worker behavior tests: verdict-to-action mapping, decoy serving (rendered
// locally, never a network fetch), throttle/ban responses, fail-open
// pass-through on engine error and deadline overrun, the bounded event ring
// with drop counter, and the adapter's request translation (header_count,
// empty UA, auth_hint).
//
// The engine (or a decide stub) and the origin fetch are injected via
// createHandler(deps) so no test depends on the network or shared state.
import { describe, expect, it } from "vitest";
import workerDefault, { createHandler, rawPathFromUrl } from "../src/worker";
import type { Decision, Request as MirageRequest, Verdict } from "../src/engine";
import { mintHoneytoken } from "../src/engine";
import { sha256Hex } from "../src/sha256";

function makeDecision(verdict: Verdict, overrides: Partial<Decision> = {}): Decision {
  return {
    sessionKey: "fec52565aa0cf18f57d7cf5b3ac72850",
    specVersion: "1.1.0",
    signals: [],
    requestScore: 0,
    score: 0,
    verdict,
    reasonCode: "SIG-000",
    banTtlMs: null,
    decoyId: null,
    ...overrides,
  };
}

/** Origin stub: records what it received and returns a sentinel response. */
function originStub() {
  const calls: Request[] = [];
  const fetch = (request: Request): Promise<Response> => {
    calls.push(request);
    return Promise.resolve(new Response("origin-ok", { status: 200 }));
  };
  return { fetch, calls, get called(): boolean { return calls.length > 0; } };
}

describe("mirage worker handler", () => {
  it("serves the rendered decoy on decoy_route (real engine, no origin fetch)", async () => {
    const origin = originStub();
    const handler = createHandler({ originFetch: origin.fetch });
    const request = new Request("https://example.test/.env", {
      method: "GET",
      headers: {
        "CF-Connecting-IP": "203.0.113.7",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
      },
    });
    const response = await handler.fetch(request);

    expect(origin.called).toBe(false);
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("text/plain");
    expect(response.headers.get("X-Robots-Tag")).toBe("noindex, nofollow, noarchive");
    expect(response.headers.get("Server")).toBe("nginx/1.24.0");
    expect(response.headers.get("X-Powered-By")).toBe("PHP/8.2.12");
    const body = await response.text();
    expect(body).toContain("APP_NAME=staging");
    expect(body).toContain("postgres://deploy:mrg_live_");
    expect(body).not.toContain("{{");
  });

  it("passes clean requests through to the origin (real engine)", async () => {
    const origin = originStub();
    const handler = createHandler({ originFetch: origin.fetch });
    const request = new Request("https://example.test/about", {
      method: "GET",
      headers: {
        "CF-Connecting-IP": "203.0.113.20",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
        Cookie: "sid=abc",
        "Accept-Language": "en",
        "Accept-Encoding": "gzip",
      },
    });
    const response = await handler.fetch(request);
    expect(origin.calls.length).toBe(1);
    expect(origin.calls[0]).toBe(request);
    expect(await response.text()).toBe("origin-ok");
  });

  it("bans honeytoken reuse end-to-end (golden v05 flow: decoy served, token replayed)", async () => {
    const origin = originStub();
    const handler = createHandler({ originFetch: origin.fetch });
    const ip = "203.0.113.10";
    const sessionKey = sha256Hex(ip).slice(0, 32);
    const token = mintHoneytoken(sessionKey, "env-file-staging", "db_password");
    // The exact token the golden vector replays as a Bearer credential.
    expect(token).toBe("mrg_live_63e36e2d68663c27f6841a68");

    // Request 1: /.env -> decoy_route, rendered locally (token minted + lead registered).
    const decoy = await handler.fetch(
      new Request("https://example.test/.env", {
        headers: { "CF-Connecting-IP": ip, "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)" },
      }),
    );
    expect(decoy.status).toBe(200);
    expect(await decoy.text()).toContain(token);

    // Request 2: the leaked token on a protected route -> ban (survives the cap).
    const blocked = await handler.fetch(
      new Request("https://example.test/api/v1/auth", {
        method: "POST",
        headers: { "CF-Connecting-IP": ip, "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)", Authorization: `Bearer ${token}` },
      }),
    );
    expect(origin.called).toBe(false);
    expect(blocked.status).toBe(403);
    // ADR-0001: nothing on the wire names Mirage — no TTL header, no marker.
    expect(blocked.headers.get("X-Mirage-Ban-Ttl")).toBeNull();
    expect([...blocked.headers.keys()].every((k) => !k.toLowerCase().startsWith("x-mirage"))).toBe(true);
  });

  it("returns 429 + Retry-After on throttle (origin untouched)", async () => {
    const origin = originStub();
    const handler = createHandler({ decide: () => makeDecision("throttle", { requestScore: 40, score: 40 }), originFetch: origin.fetch });
    const response = await handler.fetch(new Request("https://example.test/x"));

    expect(origin.called).toBe(false);
    expect(response.status).toBe(429);
    expect(response.headers.get("Retry-After")).toBe("30");
    // Header set matches the Go edge exactly: no Cache-Control, no marker.
    expect(response.headers.get("Cache-Control")).toBeNull();
    expect([...response.headers.keys()].every((k) => !k.toLowerCase().startsWith("x-mirage"))).toBe(true);
    expect(await response.text()).toBe("Too many requests. Please retry later.");
  });

  it("returns a marker-free 403 on ban (no persisted state)", async () => {
    const origin = originStub();
    const handler = createHandler({
      decide: () => makeDecision("ban", { requestScore: 50, score: 50, banTtlMs: 1_800_000, reasonCode: "SIG-104" }),
      originFetch: origin.fetch,
    });
    const response = await handler.fetch(new Request("https://example.test/x"));

    expect(origin.called).toBe(false);
    expect(response.status).toBe(403);
    expect(response.headers.get("X-Mirage-Ban-Ttl")).toBeNull();
    expect([...response.headers.keys()].every((k) => !k.toLowerCase().startsWith("x-mirage"))).toBe(true);
    expect(await response.text()).toBe("Request blocked.");
  });

  it("fails open and passes through when the engine throws", async () => {
    const origin = originStub();
    const handler = createHandler({
      decide: () => {
        throw new Error("engine removed");
      },
      originFetch: origin.fetch,
    });
    const request = new Request("https://example.test/anything");
    const response = await handler.fetch(request);

    expect(origin.calls.length).toBe(1);
    expect(await response.text()).toBe("origin-ok");
    expect(handler.getEventStats().failOpen).toBe(1);
    expect(handler.getEventStats().dropped).toBe(0);
  });

  it("fails open when the decision budget (5 ms) is exceeded", async () => {
    const origin = originStub();
    const ticks = [1000, 1000, 1006]; // tsMs, start, post-decision: overrun by 1 ms
    let tick = 0;
    const handler = createHandler({
      decide: () => makeDecision("throttle", { requestScore: 40, score: 40 }),
      now: () => ticks[tick++] ?? 9999,
      originFetch: origin.fetch,
    });
    const response = await handler.fetch(new Request("https://example.test/x"));

    expect(origin.calls.length).toBe(1);
    expect(await response.text()).toBe("origin-ok");
    expect(handler.getEventStats().failOpen).toBe(1);
  });

  it("keeps the event ring bounded and counts dropped events", async () => {
    const origin = originStub();
    const handler = createHandler({ decide: () => makeDecision("observe"), originFetch: origin.fetch, eventCapacity: 3 });
    for (let i = 0; i < 5; i++) {
      await handler.fetch(new Request(`https://example.test/page-${i}`));
    }
    const stats = handler.getEventStats();
    expect(stats.capacity).toBe(3);
    expect(stats.size).toBe(3);
    expect(stats.dropped).toBe(2);
    expect(stats.failOpen).toBe(0);
  });

  it("translates the incoming request: header_count, empty UA, auth_hint, CF-Connecting-IP", async () => {
    const origin = originStub();
    let captured: MirageRequest | undefined;
    const handler = createHandler({
      decide: (req) => {
        captured = req;
        return makeDecision("observe");
      },
      originFetch: origin.fetch,
    });
    // No User-Agent and no CF-Connecting-IP on purpose: the neutral values.
    await handler.fetch(
      new Request("https://example.test/about?debug=1&token=abc", {
        headers: {
          "X-One": "1",
          "X-Two": "2",
          "X-Three": "3",
          "X-Four": "4",
          Authorization: "Bearer xyz",
        },
      }),
    );

    expect(captured).toBeDefined();
    const req = captured as MirageRequest;
    expect(req.headerCount).toBe(5);
    expect(req.userAgent).toBe("");
    expect(req.clientIp).toBe("");
    expect(req.hasCookie).toBe(false);
    expect(req.allowlisted).toBe(false);
    expect(req.path).toBe("/about?debug=1&token=abc");
    expect(req.authHint).toContain("Bearer xyz");
    expect(req.authHint).toContain("debug=1&token=abc");
  });

  it("keeps the raw dot-segment path (WHATWG URL normalization must not erase it)", async () => {
    // Node's Request constructor already normalizes dot segments inside its
    // URL, so the no-normalization property is pinned on the extractor the
    // handler uses; a plain request through the handler is asserted too.
    expect(rawPathFromUrl("https://example.test/a/../../..?x=1")).toBe("/a/../../..?x=1");
    expect(rawPathFromUrl("https://example.test/shop/../wp-config.php.bak?debug=1")).toBe(
      "/shop/../wp-config.php.bak?debug=1",
    );
    expect(rawPathFromUrl("https://example.test")).toBe("/");

    const origin = originStub();
    let captured: MirageRequest | undefined;
    const handler = createHandler({
      decide: (req) => {
        captured = req;
        return makeDecision("observe");
      },
      originFetch: origin.fetch,
    });
    await handler.fetch(new Request("https://example.test/about?keep=1"));
    expect((captured as MirageRequest).path).toBe("/about?keep=1");
  });

  it("counts a Cookie header as has_cookie", async () => {
    const origin = originStub();
    let captured: MirageRequest | undefined;
    const handler = createHandler({
      decide: (req) => {
        captured = req;
        return makeDecision("observe");
      },
      originFetch: origin.fetch,
    });
    await handler.fetch(new Request("https://example.test/", { headers: { Cookie: "sid=1" } }));
    expect((captured as MirageRequest).hasCookie).toBe(true);
  });

  it("exposes a default export with a fetch handler and module-level stats", () => {
    expect(typeof workerDefault.fetch).toBe("function");
  });
});
