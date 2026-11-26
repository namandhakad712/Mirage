// Decoy rendering — the TypeScript mirror of the Go internal/decoy renderer.
//
// Everything here is deterministic per session (DECOY-CATALOG §4): the same
// session key always renders byte-identical decoys, so an attacker who
// re-fetches a trap never sees it flicker. Bodies are inert — no scripts, no
// redirects, no third-party links (I8, I14) — and every response carries the
// noindex header set exactly once (I12). The v1 catalog bodies contain no
// timestamp placeholders, so renderDecoy takes no ts argument.

import { sha256Bytes } from "./sha256";
import { mintHoneytoken } from "./engine";
import type { CatalogEntry, CatalogPersona } from "./generated/data";

export interface RenderedDecoy {
  readonly body: string;
  readonly status: number;
  /** Complete header set: persona headers, Content-Type, then the noindex set. */
  readonly headers: [string, string][];
}

const NOINDEX_HEADER: [string, string] = ["X-Robots-Tag", "noindex, nofollow, noarchive"];
const TRUNCATION_SUFFIX = "\n[truncated]";
const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const UPPER_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
// {{SEED:N_HEX}}, {{SEED:N_B64}}, {{SEED:N_UPPER}}, {{TOKEN:id}}.
const PLACEHOLDER_RE = /\{\{(SEED:\d+_(?:HEX|B64|UPPER)|TOKEN:[^{}]+)\}\}/g;
const SEED_SPEC_RE = /^(\d+)_(HEX|B64|UPPER)$/;
// Sanity bound: a placeholder asking for more than this is a catalog bug.
const MAX_SEED_CHARS = 4096;

/**
 * Deterministic digest stream (DECOY-CATALOG §4): byte blocks
 * b_i = sha256(material + ":" + i), concatenated until `count` bytes are
 * available. Material is sessionKey + ":" + entryId + ":" + placeholder id,
 * so every placeholder shape draws an independent stream.
 */
function digestStreamBytes(material: string, count: number): Uint8Array {
  const out = new Uint8Array(count);
  let filled = 0;
  for (let i = 0; filled < count; i++) {
    const block = sha256Bytes(`${material}:${i}`);
    const take = Math.min(block.length, count - filled);
    out.set(block.subarray(0, take), filled);
    filled += take;
  }
  return out;
}

function charsFromBytes(bytes: Uint8Array, alphabet: string, count: number): string {
  let s = "";
  for (let i = 0; i < count; i++) {
    s += alphabet.charAt((bytes[i] ?? 0) % alphabet.length);
  }
  return s;
}

function seedValue(sessionKey: string, entryId: string, spec: string): string {
  const match = SEED_SPEC_RE.exec(spec);
  if (match === null) throw new Error(`unknown SEED placeholder spec: ${spec}`);
  const count = Number(match[1]);
  if (count <= 0 || count > MAX_SEED_CHARS) throw new Error(`SEED placeholder out of range: ${spec}`);
  const mode = match[2];
  const material = `${sessionKey}:${entryId}:${spec}`;
  if (mode === "HEX") {
    // One byte yields two hex chars.
    const bytes = digestStreamBytes(material, Math.ceil(count / 2));
    let s = "";
    for (let i = 0; i < bytes.length && s.length < count; i++) {
      const b = bytes[i] ?? 0;
      s += b.toString(16).padStart(2, "0");
    }
    return s.slice(0, count);
  }
  const bytes = digestStreamBytes(material, count);
  return charsFromBytes(bytes, mode === "B64" ? BASE64_ALPHABET : UPPER_ALPHABET, count);
}

/** Resolve every {{SEED:…}} / {{TOKEN:…}} placeholder in a template body. */
function applyPlaceholders(body: string, entryId: string, sessionKey: string): string {
  return body.replace(PLACEHOLDER_RE, (_match: string, spec: string): string => {
    if (spec.startsWith("SEED:")) return seedValue(sessionKey, entryId, spec.slice("SEED:".length));
    // {{TOKEN:id}} — the exact string the engine registers on serving, so
    // SIG-104 detection matches what the attacker read in the body.
    return mintHoneytoken(sessionKey, entryId, spec.slice("TOKEN:".length));
  });
}

/**
 * Enforce the per-entry size cap (I12 bounded footprint): truncate at a safe
 * UTF-8 boundary and append the truncation marker, keeping the FINAL body
 * (marker included) within `capBytes`.
 */
function capBody(body: string, capBytes: number): string {
  const bytes = new TextEncoder().encode(body);
  if (bytes.byteLength <= capBytes) return body;
  let cut = Math.max(0, capBytes - TRUNCATION_SUFFIX.length);
  // Back off while the first excluded byte is a UTF-8 continuation byte
  // (0b10xxxxxx): cutting there would split a multi-byte character.
  while (cut > 0 && (bytes[cut]! & 0xc0) === 0x80) cut--;
  return new TextDecoder().decode(bytes.subarray(0, cut)) + TRUNCATION_SUFFIX;
}

/** Render a decoy entry for one attacker session. Pure: no network, no clock (I3, I2). */
export function renderDecoy(entry: CatalogEntry, persona: CatalogPersona, sessionKey: string): RenderedDecoy {
  const body = capBody(applyPlaceholders(entry.body, entry.id, sessionKey), entry.sizeCapBytes);

  const headers: Array<[string, string]> = [];
  for (const raw of persona.headers) {
    const idx = raw.indexOf(":");
    if (idx <= 0) throw new Error(`persona "${persona.id}": malformed header "${raw}"`);
    const name = raw.slice(0, idx).trim();
    // The noindex set is appended exactly once below; a persona header with
    // the same name would duplicate it (I12 requires exactly one).
    if (name.toLowerCase() === "x-robots-tag") continue;
    headers.push([name, raw.slice(idx + 1).trim()]);
  }
  headers.push(["Content-Type", entry.contentType]);
  headers.push([NOINDEX_HEADER[0], NOINDEX_HEADER[1]]);
  return { body, status: entry.status, headers };
}
