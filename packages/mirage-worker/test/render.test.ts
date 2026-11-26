// Decoy rendering tests: determinism per session, the honeytoken formula
// (cross-checked against the v05 golden vector), the noindex header set
// exactly once (I12), persona headers, placeholder shapes and the size cap
// (I12 bounded footprint) including the UTF-8 boundary rule.
import { describe, expect, it } from "vitest";
import { renderDecoy } from "../src/render";
import { mintHoneytoken } from "../src/engine";
import { sha256Hex } from "../src/sha256";
import { CATALOG } from "../src/generated/data";
import type { CatalogEntry, CatalogPersona } from "../src/generated/data";

const ENV_ENTRY = CATALOG.entries.find((e) => e.id === "env-file-staging");
const LARAVEL_PERSONA = CATALOG.personas.find((p) => p.id === "laravel-staging");
if (ENV_ENTRY === undefined || LARAVEL_PERSONA === undefined) throw new Error("catalog snapshot missing env-file-staging");

// Session key of 203.0.113.10 (golden vector v05) — the token minted here
// must equal the one the vector later presents as a Bearer credential.
const SESSION_KEY = sha256Hex("203.0.113.10").slice(0, 32);

function headerValues(headers: readonly (readonly [string, string])[], name: string): string[] {
  return headers.filter(([n]) => n.toLowerCase() === name).map(([, v]) => v);
}

describe("renderDecoy", () => {
  it("is deterministic: same session renders byte-identical decoys", () => {
    const a = renderDecoy(ENV_ENTRY, LARAVEL_PERSONA, SESSION_KEY);
    const b = renderDecoy(ENV_ENTRY, LARAVEL_PERSONA, SESSION_KEY);
    expect(a.body).toBe(b.body);
    expect(a.headers).toEqual(b.headers);
    expect(a.status).toBe(b.status);
  });

  it("differs per session (seeded generation, DECOY-CATALOG §4)", () => {
    const other = sha256Hex("203.0.113.24").slice(0, 32);
    expect(renderDecoy(ENV_ENTRY, LARAVEL_PERSONA, SESSION_KEY).body).not.toBe(
      renderDecoy(ENV_ENTRY, LARAVEL_PERSONA, other).body,
    );
  });

  it("resolves every placeholder (no {{ left) with the right shapes", () => {
    const { body } = renderDecoy(ENV_ENTRY, LARAVEL_PERSONA, SESSION_KEY);
    expect(body).not.toContain("{{");
    expect(body).toContain("APP_NAME=staging");
    // {{SEED:44_B64}} -> 44 base64 characters.
    expect(body).toMatch(/^APP_KEY=base64:[A-Za-z0-9+/]{44}$/m);
    // {{SEED:13_UPPER}} -> 13 uppercase letters after the fixed prefix.
    expect(body).toMatch(/^AWS_ACCESS_KEY_ID=AKIAMRG[A-Z]{13}$/m);
  });

  it("mints the honeytoken with the engine formula (v05 golden token)", () => {
    const expected = mintHoneytoken(SESSION_KEY, "env-file-staging", "db_password");
    // The formula pinned by the spec: mrg_live_ + first 24 hex of
    // sha256(sessionKey:entryId:tokenId) — and the v05 vector replays this
    // exact string as a Bearer credential later in its session.
    expect(expected).toBe("mrg_live_" + sha256Hex(`${SESSION_KEY}:env-file-staging:db_password`).slice(0, 24));
    expect(expected).toBe("mrg_live_63e36e2d68663c27f6841a68");

    const { body } = renderDecoy(ENV_ENTRY, LARAVEL_PERSONA, SESSION_KEY);
    const inUrl = body.match(/postgres:\/\/deploy:(mrg_live_[0-9a-f]{24})@db\.test/);
    expect(inUrl?.[1]).toBe(expected);
    // The same token id used twice in one body yields the same string.
    expect(body).toContain(`DB_PASSWORD=${expected}`);
  });

  it("sets the noindex header exactly once (I12)", () => {
    const rendered = renderDecoy(ENV_ENTRY, LARAVEL_PERSONA, SESSION_KEY);
    const noindex = headerValues(rendered.headers, "x-robots-tag");
    expect(noindex).toEqual(["noindex, nofollow, noarchive"]);
  });

  it("carries persona headers, status and content type from the catalog", () => {
    const rendered = renderDecoy(ENV_ENTRY, LARAVEL_PERSONA, SESSION_KEY);
    expect(headerValues(rendered.headers, "server")).toEqual(["nginx/1.24.0"]);
    expect(headerValues(rendered.headers, "x-powered-by")).toEqual(["PHP/8.2.12"]);
    expect(headerValues(rendered.headers, "content-type")).toEqual(["text/plain"]);
    expect(rendered.status).toBe(200);
  });

  describe("size cap (I12)", () => {
    const persona: CatalogPersona = { id: "test-persona", story: "test", headers: [] };

    it("truncates ASCII bodies under the cap with the marker", () => {
      const entry: CatalogEntry = {
        id: "trunc-ascii",
        persona: "test-persona",
        path: "/trunc-ascii",
        status: 200,
        contentType: "text/plain",
        sizeCapBytes: 64,
        body: "A".repeat(200),
        leads: [],
        honeytokens: [],
      };
      const { body } = renderDecoy(entry, persona, SESSION_KEY);
      expect(new TextEncoder().encode(body).byteLength).toBeLessThanOrEqual(64);
      expect(body.endsWith("\n[truncated]")).toBe(true);
    });

    it("never splits a multi-byte UTF-8 character at the cut", () => {
      const entry: CatalogEntry = {
        id: "trunc-utf8",
        persona: "test-persona",
        path: "/trunc-utf8",
        status: 200,
        contentType: "text/plain",
        sizeCapBytes: 61, // odd cap: the naive cut lands inside a 2-byte é
        body: "é".repeat(100), // 200 UTF-8 bytes
        leads: [],
        honeytokens: [],
      };
      const { body } = renderDecoy(entry, persona, SESSION_KEY);
      const bytes = new TextEncoder().encode(body);
      expect(bytes.byteLength).toBeLessThanOrEqual(61);
      expect(body.endsWith("\n[truncated]")).toBe(true);
      // The truncated prefix must still be valid UTF-8 (fatal decoder throws otherwise).
      const prefix = body.slice(0, body.length - "\n[truncated]".length);
      expect(() => new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(new TextEncoder().encode(prefix))).not.toThrow();
      // 61 - 12 ("\n[truncated]") = 49 bytes budget; "é" is 2 bytes, so 24 whole chars.
      expect(prefix).toBe("é".repeat(24));
    });

    it("leaves short bodies untouched", () => {
      const entry: CatalogEntry = {
        id: "short",
        persona: "test-persona",
        path: "/short",
        status: 200,
        contentType: "text/plain",
        sizeCapBytes: 2048,
        body: "short body\n",
        leads: [],
        honeytokens: [],
      };
      expect(renderDecoy(entry, persona, SESSION_KEY).body).toBe("short body\n");
    });
  });
});
