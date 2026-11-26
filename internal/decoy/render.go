package decoy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// noindexHeader is appended to every decoy response (I12: no pollution of
// the public web) regardless of what the persona lists, so no crawler ever
// indexes a decoy.
const noindexHeader = "X-Robots-Tag: noindex, nofollow, noarchive"

// truncationMarker terminates bodies cut at their size cap. It is visible
// on purpose: a cleanly marked cut looks like a truncated log, an
// invisible mid-rune cut would look like corruption.
const truncationMarker = "\n[truncated]"

// upperAlphabet is the character set of {{SEED:N_UPPER}}: uppercase alnum,
// the shape of AWS-style key material (see token-formats.md, aws_accesskey).
const upperAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// placeholderRe matches any {{...}} template placeholder. Only SEED and
// TOKEN are defined (DECOY-CATALOG.md section 4); any other occurrence
// fails the render — and therefore validation — instead of leaking
// template syntax to an attacker.
var placeholderRe = regexp.MustCompile(`\{\{([^{}]*)\}\}`)

// Rendered is a complete decoy response, ready for the serving layer to
// write to the wire.
type Rendered struct {
	Status      int
	ContentType string
	Headers     []string
	Body        []byte
	DecoyID     string
}

// Render renders entry for the given session key. The output is a pure
// function of (catalog, entry, sessionKey): no clock, no randomness
// (DECOY-CATALOG.md section 4), so the same session always receives
// byte-identical bodies and any session can be reproduced later for
// evidence (I10). The only error is a malformed placeholder, which
// validation catches before the catalog is ever served.
func (c *Catalog) Render(entry Entry, sessionKey string) (Rendered, error) {
	body, err := renderBody(entry, sessionKey)
	if err != nil {
		return Rendered{}, err
	}

	headers := make([]string, 0, 3)
	if c != nil {
		if p, ok := c.personaByID(entry.Persona); ok {
			headers = append(headers, p.Headers...)
		}
	}
	// I12: always carry the noindex set. If the persona already declares
	// an X-Robots-Tag of its own we do not duplicate it (the v1 personas
	// never do); the header is then the catalog author's responsibility.
	if !hasRobotsTag(headers) {
		headers = append(headers, noindexHeader)
	}

	return Rendered{
		Status:      entry.Status,
		ContentType: entry.ContentType,
		Headers:     headers,
		Body:        capBody([]byte(body), entry.SizeCapBytes),
		DecoyID:     entry.ID,
	}, nil
}

// renderBody resolves every placeholder in entry.Body:
//
//   - {{SEED:spec}} — session-seeded material. The material string is
//     sessionKey:entryId:seed:spec:k where k is the k-th occurrence of THAT
//     spec string in the body (0-based), so two identical SEED placeholders
//     in one body never render the same value while the derivation stays
//     identical across the Go and TypeScript implementations (the
//     cross-engine formula is pinned by spec/golden-vectors/renders.json).
//   - {{TOKEN:id}} — a honeytoken; the same id always mints the same value
//     so DATABASE_URL and DB_PASSWORD agree within a body.
func renderBody(entry Entry, sessionKey string) (string, error) {
	counts := map[string]int{}
	var firstErr error
	out := placeholderRe.ReplaceAllStringFunc(entry.Body, func(m string) string {
		inner := strings.TrimSuffix(strings.TrimPrefix(m, "{{"), "}}")
		kind, arg, _ := strings.Cut(inner, ":")
		switch kind {
		case "SEED":
			k := counts[arg]
			counts[arg]++
			material := sessionKey + ":" + entry.ID + ":seed:" + arg + ":" + strconv.Itoa(k)
			s, err := renderSeed(material, arg)
			if err != nil && firstErr == nil {
				firstErr = fmt.Errorf("entry %q: %v", entry.ID, err)
			}
			return s
		case "TOKEN":
			return MintToken(sessionKey, entry.ID, arg)
		default:
			if firstErr == nil {
				firstErr = fmt.Errorf("entry %q: unknown placeholder %q (expected SEED or TOKEN)", entry.ID, m)
			}
			return m
		}
	})
	if firstErr != nil {
		return "", firstErr
	}
	return out, nil
}

// renderSeed renders one {{SEED:spec}} placeholder from material (the
// session-scoped seed string). Specs:
//
//	N_HEX    the first N hex chars of sha256(material) — one digest is a
//	         full 64 hex chars, so N is capped at 64
//	N_B64    N unpadded standard-base64 chars taken from the digest stream;
//	         44_B64 encodes 33 raw bytes (the APP_KEY shape)
//	N_UPPER  N chars of [A-Z0-9] folded out of the digest stream
//
// The digest stream is b_i = sha256(material + ":" + i) for i = 0, 1, …,
// concatenated and sliced to need — the hash-chain from
// DECOY-CATALOG.md section 4. Everything is deterministic, so a session
// replay reproduces the exact bytes.
func renderSeed(material, spec string) (string, error) {
	nStr, kind, ok := strings.Cut(spec, "_")
	if !ok {
		return "", fmt.Errorf("bad SEED spec %q: want N_HEX, N_B64 or N_UPPER", spec)
	}
	n, err := strconv.Atoi(nStr)
	if err != nil || n <= 0 {
		return "", fmt.Errorf("bad SEED spec %q: N must be a positive integer", spec)
	}
	switch kind {
	case "HEX":
		if n > 2*sha256.Size {
			return "", fmt.Errorf("bad SEED spec %q: one digest yields at most %d hex chars", spec, 2*sha256.Size)
		}
		sum := sha256.Sum256([]byte(material))
		return hex.EncodeToString(sum[:])[:n], nil
	case "B64":
		if n%4 != 0 {
			return "", fmt.Errorf("bad SEED spec %q: N must be a multiple of 4 for unpadded base64", spec)
		}
		// n/4*3 raw bytes encode to exactly n chars with no '=' padding.
		return base64.StdEncoding.EncodeToString(seedStream(material, n/4*3)), nil
	case "UPPER":
		raw := seedStream(material, n)
		var b strings.Builder
		b.Grow(n)
		for _, x := range raw {
			// Modulo folding of the stream bytes; uniform enough for
			// decoy filler and fully deterministic.
			b.WriteByte(upperAlphabet[int(x)%len(upperAlphabet)])
		}
		return b.String(), nil
	default:
		return "", fmt.Errorf("bad SEED spec %q: unknown kind %q", spec, kind)
	}
}

// seedStream yields n deterministic bytes from material: block i is
// sha256(material + ":" + i), blocks are concatenated and sliced.
func seedStream(material string, n int) []byte {
	blocks := (n + sha256.Size - 1) / sha256.Size
	out := make([]byte, 0, blocks*sha256.Size)
	for i := 0; i < blocks; i++ {
		sum := sha256.Sum256([]byte(material + ":" + strconv.Itoa(i)))
		out = append(out, sum[:]...)
	}
	return out[:n]
}

// MintToken mints the honeytoken for (sessionKey, entryID, tokenID):
//
//	"mrg_live_" + hex(sha256(sessionKey + ":" + entryID + ":" + tokenID))[:24]
//
// The formula is canon (data/token-formats.md, token_alnum_24) and the
// detect engine mints it identically to recognise a leaked honeytoken
// (SIG-104): changing it invalidates every outstanding token. The mrg_
// namespace is issued by no real provider (I14).
func MintToken(sessionKey, entryID, tokenID string) string {
	sum := sha256.Sum256([]byte(sessionKey + ":" + entryID + ":" + tokenID))
	return "mrg_live_" + hex.EncodeToString(sum[:])[:24]
}

// capBody enforces the entry's size cap (I12: bounded footprint). A decoy
// must always render — I1's spirit — so an oversized body is truncated at
// a UTF-8 rune boundary and marked, never rejected and never cut mid-rune.
// The cut leaves room for the marker so the FINAL body stays within the
// cap, byte-for-byte like the TypeScript worker's renderer; a cap smaller
// than the marker (impossible via Load, which enforces 64..65536) keeps
// the marker visible rather than emitting an empty body. Caps of zero or
// less disable truncation; they cannot make a body vanish.
func capBody(body []byte, capBytes int) []byte {
	if capBytes <= 0 || len(body) <= capBytes {
		return body
	}
	cut := capBytes - len(truncationMarker)
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(body[cut]) {
		cut-- // back up to the start of the rune straddling the cut
	}
	out := make([]byte, 0, cut+len(truncationMarker))
	out = append(out, body[:cut]...)
	out = append(out, truncationMarker...)
	return out
}

// hasRobotsTag reports whether any header line already sets X-Robots-Tag,
// so Render never duplicates it (DECOY-CATALOG.md section 3 rule 4).
func hasRobotsTag(headers []string) bool {
	for _, h := range headers {
		name, _, _ := strings.Cut(h, ":")
		if strings.EqualFold(strings.TrimSpace(name), "X-Robots-Tag") {
			return true
		}
	}
	return false
}
