// Known-answer tests for the synchronous SHA-256 (FIPS 180-4). Reference
// digests were produced with Python's hashlib; the 203.0.113.7 and
// 198.51.100.5 values are the repo anchors from spec/SIGNALS.md §2 and
// spec/golden-vectors/HAND-COMPUTED.md (v20).
import { describe, expect, it } from "vitest";
import { sha256Hex } from "../src/sha256";

describe("sha256Hex known-answer tests", () => {
  it("hashes the FIPS alphabet message", () => {
    expect(sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("hashes the empty string", () => {
    expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("hashes the classic quick-brown-fox message", () => {
    expect(sha256Hex("The quick brown fox jumps over the lazy dog")).toBe(
      "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
    );
  });

  it("produces the session-key anchor for 203.0.113.7 (W1 / v02)", () => {
    const digest = sha256Hex("203.0.113.7");
    expect(digest.slice(0, 32)).toBe("fec52565aa0cf18f57d7cf5b3ac72850");
    expect(digest).toBe("fec52565aa0cf18f57d7cf5b3ac728503b8992d2d6f7d46da1d1201090902b02");
  });

  it("produces the session-key anchor for 198.51.100.5 (v20)", () => {
    const digest = sha256Hex("198.51.100.5");
    expect(digest.slice(0, 32)).toBe("8959edf6884f2c2e223a9319e83a6982");
    expect(digest).toBe("8959edf6884f2c2e223a9319e83a69820ff7a9c39ecd7ebe6413e5297d4347dd");
  });

  it("handles multi-block inputs (1000 chars)", () => {
    expect(sha256Hex("a".repeat(1000))).toBe("41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3");
  });

  it("hashes the UTF-8 encoding, not the UTF-16 code units", () => {
    expect(sha256Hex("héllo wörld — ünïcode ✓")).toBe("10f09f0e73dc248ba19f87f4fd749ebe966a307fd1be045f837b6b1c9c7bf993");
  });
});
