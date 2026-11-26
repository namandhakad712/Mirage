// Decoy rendering — the TypeScript mirror of the Go internal/decoy renderer.
//
// Everything here is deterministic per session (DECOY-CATALOG §4): the same
// session key always renders byte-identical decoys, so an attacker who
// re-fetches a trap never sees it flicker. Bodies are inert — no scripts, no
// redirects, no third-party links (I8, I14) — and every response carries the
// noindex header set exactly once (I12). The v1 catalog bodies contain no
// timestamp placeholders, so renderDecoy takes no ts argument.

import { sha256Bytes, sha256Hex } from "./sha256";
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
// Must match the Go renderer's 36-char alphabet exactly (render parity is
// pinned by spec/golden-vectors/renders.json).
const UPPER_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
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

/** Standard base64 of raw bytes, unpadded — byte-identical to Go's
 * base64.StdEncoding.EncodeToString(... ) with padding stripped. */
function b64EncodeUnpadded(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    s += BASE64_ALPHABET.charAt(b0 >> 2);
    s += BASE64_ALPHABET.charAt(((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4));
    if (b1 === undefined) return s;
    s += BASE64_ALPHABET.charAt(((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6));
    if (b2 === undefined) return s;
    s += BASE64_ALPHABET.charAt(b2 & 0x3f);
  }
  return s;
}

/**
 * One {{SEED:spec}} value. Material is
 * `${sessionKey}:${entryId}:seed:${spec}:${k}` where k is the k-th
 * occurrence of THIS spec in the body — the cross-engine canon (see
 * DECOY-CATALOG.md section 4 and spec/golden-vectors/renders.json).
 *   HEX(N)   first N hex chars of sha256(material)
 *   B64(N)   unpadded standard base64 of the first 3N/4 digest-stream
 *            bytes (N must be a multiple of 4)
 *   UPPER(N) first N digest-stream bytes folded mod 36 over A-Z0-9
 */
function seedValue(sessionKey: string, entryId: string, spec: string, k: number): string {
  const match = SEED_SPEC_RE.exec(spec);
  if (match === null) throw new Error(`unknown SEED placeholder spec: ${spec}`);
  const count = Number(match[1]);
  if (count <= 0 || count > MAX_SEED_CHARS) throw new Error(`SEED placeholder out of range: ${spec}`);
  const mode = match[2];
  const material = `${sessionKey}:${entryId}:seed:${spec}:${k}`;
  if (mode === "HEX") {
    if (count > 64) throw new Error(`SEED placeholder out of range: ${spec}`);
    return sha256Hex(material).slice(0, count);
  }
  if (mode === "B64") {
    if (count % 4 !== 0) throw new Error(`SEED B64 length must be a multiple of 4: ${spec}`);
    return b64EncodeUnpadded(digestStreamBytes(material, (count / 4) * 3));
  }
  return charsFromBytes(digestStreamBytes(material, count), UPPER_ALPHABET, count);
}

/** Resolve every {{SEED:…}} / {{TOKEN:…}} placeholder in a template body. */
function applyPlaceholders(body: string, entryId: string, sessionKey: string): string {
  const seen = new Map<string, number>();
  return body.replace(PLACEHOLDER_RE, (_match: string, spec: string): string => {
    if (spec.startsWith("SEED:")) {
      const inner = spec.slice("SEED:".length);
      const k = seen.get(inner) ?? 0;
      seen.set(inner, k + 1);
      return seedValue(sessionKey, entryId, inner, k);
    }
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
