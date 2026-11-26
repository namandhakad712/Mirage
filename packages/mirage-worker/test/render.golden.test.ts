// Cross-engine render parity: spec/golden-vectors/renders.json pins the
// exact rendered body of every catalog entry for two fixed session keys.
// This suite and the Go test (internal/decoy/render_golden_test.go) both
// consume the same file — CI fails if either engine drifts from it.
// Regen: REGEN=1 go test ./internal/decoy/ -run TestRegenRenderGolden
// then re-run this suite.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { renderDecoy } from "../src/render";
import { sha256Hex } from "../src/sha256";
import { CATALOG } from "../src/generated/data";
import type { CatalogEntry, CatalogPersona } from "../src/generated/data";

// Resolved from this file's own location (vitest's cwd is the package dir).
const RENDERS_PATH = fileURLToPath(new URL("../../../spec/golden-vectors/renders.json", import.meta.url));

interface RenderGoldenFile {
  spec_version: string;
  decoy_catalog_version: string;
  sessions: string[];
  entries: Record<string, Record<string, string>>;
}

const golden: RenderGoldenFile = JSON.parse(
  readFileSync(RENDERS_PATH, "utf8"),
) as RenderGoldenFile;

function personaOf(entry: CatalogEntry): CatalogPersona {
  const persona = CATALOG.personas.find((p) => p.id === entry.persona);
  if (persona === undefined) throw new Error(`entry ${entry.id}: unknown persona "${entry.persona}"`);
  return persona;
}

describe("render golden vectors (renders.json)", () => {
  it("pins the fixture's spec and catalog versions", () => {
    expect(golden.spec_version).toBe("1.1.0");
    // catalog_version: "1" in spec/decoy-catalog/catalog.yaml — the version
    // the personas and entries below are generated from.
    expect(golden.decoy_catalog_version).toBe("1");
  });

  it("covers every catalog entry for every golden session", () => {
    expect(Object.keys(golden.entries).sort()).toEqual(CATALOG.entries.map((e) => e.id).sort());
    for (const bodies of Object.values(golden.entries)) {
      expect(Object.keys(bodies).sort()).toEqual([...golden.sessions].sort());
    }
  });

  for (const entry of CATALOG.entries) {
    const persona = personaOf(entry);
    for (const sessionKey of golden.sessions) {
      it(`renders ${entry.id} for session ${sessionKey} byte-identical to the golden body`, () => {
        const rendered = renderDecoy(entry, persona, sessionKey);
        expect(rendered.body).toBe(golden.entries[entry.id]![sessionKey]!);
        // I12: the noindex set rides along on every decoy response.
        const noindex = rendered.headers.filter(
          ([name, value]) =>
            name.toLowerCase() === "x-robots-tag" && value === "noindex, nofollow, noarchive",
        );
        expect(noindex.length).toBe(1);
      });
    }
  }

  it("differs per session (seeded generation, DECOY-CATALOG §4)", () => {
    const entry = CATALOG.entries.find((e) => e.id === "env-file-staging")!;
    const persona = personaOf(entry);
    expect(renderDecoy(entry, persona, golden.sessions[0]!).body).not.toBe(
      renderDecoy(entry, persona, golden.sessions[1]!).body,
    );
  });

  it("mints the same honeytoken the Go engine mints for the v05 vector session", () => {
    // Cross-anchor with vectors.json: v05's attacker is 203.0.113.10, so
    // the .env body must carry the token the vector later replays.
    const entry = CATALOG.entries.find((e) => e.id === "env-file-staging")!;
    const persona = personaOf(entry);
    const sessionKey = sha256Hex("203.0.113.10").slice(0, 32);
    const { body } = renderDecoy(entry, persona, sessionKey);
    expect(body).toContain("mrg_live_63e36e2d68663c27f6841a68");
  });
});
