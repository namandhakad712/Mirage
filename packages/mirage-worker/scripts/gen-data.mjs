#!/usr/bin/env node
// Generates src/generated/data.ts from the shared Mirage data files and the
// decoy catalog. BUILD-TIME ONLY: js-yaml is a devDependency used exclusively
// here, so the runtime Worker bundle stays zero-dependency (ADAPTER-PROTOCOL
// §1, in-process transport). The emitted module has no imports and is
// deterministic (no timestamps), so regeneration never produces spurious
// diffs. Run via `npm run gen`.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import yaml from "js-yaml";

// Anchor all paths at the package root so the documented relative paths
// (../../data/..., ../../spec/...) hold regardless of the caller's cwd.
const PKG_ROOT = new URL("../", import.meta.url);
const here = (p) => new URL(p, PKG_ROOT);

/** Read a data file: one entry per line, # comments (full-line and inline) stripped. */
function readLines(url) {
  return readFileSync(url, "utf8")
    .split("\n")
    .map((line) => {
      const hash = line.indexOf("#");
      return (hash === -1 ? line : line.slice(0, hash)).trim();
    })
    .filter((line) => line !== "");
}

function requireString(obj, key, ctx) {
  const v = obj[key];
  if (typeof v !== "string" || v === "") {
    throw new Error(`catalog ${ctx}: field "${key}" must be a non-empty string`);
  }
  return v;
}

function requireStringArray(obj, key, ctx) {
  const v = obj[key];
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string" || x === "")) {
    throw new Error(`catalog ${ctx}: field "${key}" must be a string array`);
  }
  return v;
}

// --- decoy catalog (spec/decoy-catalog/catalog.yaml, DECOY-CATALOG.md v1) ---
const raw = yaml.load(readFileSync(here("../../spec/decoy-catalog/catalog.yaml"), "utf8"));
if (raw === null || typeof raw !== "object") throw new Error("catalog.yaml: not a mapping");

const personas = [];
const personaIds = new Set();
for (const p of raw.personas ?? []) {
  const id = requireString(p, "id", "persona");
  if (personaIds.has(id)) throw new Error(`catalog: duplicate persona id "${id}"`);
  personaIds.add(id);
  personas.push({
    id,
    story: requireString(p, "story", `persona ${id}`),
    headers: requireStringArray(p, "headers", `persona ${id}`),
  });
}

const entries = [];
const entryIds = new Set();
const entryPaths = new Set();
for (const e of raw.entries ?? []) {
  const id = requireString(e, "id", "entry");
  if (entryIds.has(id)) throw new Error(`catalog: duplicate entry id "${id}"`);
  entryIds.add(id);
  const path = requireString(e, "path", `entry ${id}`);
  if (entryPaths.has(path)) throw new Error(`catalog: duplicate entry path "${path}"`);
  entryPaths.add(path);
  const persona = requireString(e, "persona", `entry ${id}`);
  if (!personaIds.has(persona)) throw new Error(`catalog: entry ${id} references unknown persona "${persona}"`);
  if (typeof e.status !== "number" || typeof e.size_cap_bytes !== "number") {
    throw new Error(`catalog entry ${id}: status and size_cap_bytes must be numbers`);
  }
  const honeytokens = [];
  for (const t of e.honeytokens ?? []) {
    honeytokens.push({
      id: requireString(t, "id", `entry ${id} honeytoken`),
      format: requireString(t, "format", `entry ${id} honeytoken`),
    });
  }
  entries.push({
    id,
    persona,
    path,
    status: e.status,
    contentType: requireString(e, "content_type", `entry ${id}`),
    sizeCapBytes: e.size_cap_bytes,
    body: typeof e.body === "string" ? e.body : "",
    leads: requireStringArray(e, "leads", `entry ${id}`),
    honeytokens,
  });
}

// --- flat data files (kept verbatim; normalization happens at match time) ---
const scannerPaths = readLines(here("../../data/scanner-paths.txt"));
const uaSuspicious = readLines(here("../../data/ua-suspicious.txt"));
const uaVerifiedBots = readLines(here("../../data/ua-verified-bots.txt"));
const reservedHosts = readLines(here("../../data/reserved-hosts.txt"));

const catalog = { entries, personas };

const out = `// GENERATED — do not edit; run npm run gen
// Sources: data/scanner-paths.txt, data/ua-suspicious.txt,
//          data/ua-verified-bots.txt, data/reserved-hosts.txt and
//          spec/decoy-catalog/catalog.yaml (DECOY-CATALOG.md v1).
// Scanner paths are kept EXACTLY as in the source file: trailing-slash
// insensitivity is applied at match time (SIGNALS §3.3), never here.

export const SCANNER_PATHS: string[] = ${JSON.stringify(scannerPaths, null, 2)};

export const UA_SUSPICIOUS: string[] = ${JSON.stringify(uaSuspicious, null, 2)};

export const UA_VERIFIED_BOTS: string[] = ${JSON.stringify(uaVerifiedBots, null, 2)};

// Reserved hostnames/networks all decoy content must stay within (I14).
// Carried so the worker snapshot matches the Go core's data exactly; the
// pollution/lint suite consumes it.
export const RESERVED_HOSTS: string[] = ${JSON.stringify(reservedHosts, null, 2)};

// Protected routes (I4): canon policy from spec/golden-vectors/vectors.json
// (policy.protected_routes). Hardcoded so the worker stays in lockstep with
// the vectors the conformance gate replays.
export const PROTECTED_ROUTES: string[] = ${JSON.stringify(["/wp-login.php", "/wp-admin/", "/checkout", "/cart", "/api/"], null, 2)};

export interface CatalogHoneytoken {
  id: string;
  format: string;
}

export interface CatalogEntry {
  id: string;
  persona: string;
  path: string;
  status: number;
  contentType: string;
  sizeCapBytes: number;
  body: string;
  leads: string[];
  honeytokens: CatalogHoneytoken[];
}

export interface CatalogPersona {
  id: string;
  story: string;
  headers: string[];
}

export interface Catalog {
  entries: CatalogEntry[];
  personas: CatalogPersona[];
}

export const CATALOG: Catalog = ${JSON.stringify(catalog, null, 2)};
`;

const outFile = here("src/generated/data.ts");
mkdirSync(new URL(".", outFile), { recursive: true });
writeFileSync(outFile, out);
console.log(`generated src/generated/data.ts: ${entries.length} catalog entries, ${personas.length} personas, ${scannerPaths.length} scanner paths`);
