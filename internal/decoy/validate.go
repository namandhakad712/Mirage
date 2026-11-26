package decoy

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// SampleSessionKey is the fixed session key Validate renders with. It is a
// constant — never a clock or random value — so validation is reproducible,
// and no live session (a 32-hex-char key) can collide with it.
const SampleSessionKey = "mirage-catalog-validation-sample"

// defaultProtectedLeads is the canon protected-route list (I4,
// spec/SIGNALS.md section 2 — the same list internal/config ships):
// /wp-login.php, /wp-admin/, /checkout, /cart, /api/. It constrains LEADS
// only: a lead is a path the decoy itself advertises, so following it must
// never land the attacker on, or impersonate, a real login, checkout or
// API route. Entry PATHS are checked against the live site's real routes
// at install time by `mirage init` instead (DECOY-CATALOG.md section 3
// rule 1) — which is why /api/docs may be a lure path while nothing under
// /api/ may be a lead. Entries ending in "/" are prefixes.
var defaultProtectedLeads = []string{"/wp-login.php", "/wp-admin/", "/checkout", "/cart", "/api/"}

// inertPatterns are the executable/active-content markers a decoy body
// must never contain (I8: decoys are inert — nothing that acts on the
// visitor's machine, no redirects). Matching is case-insensitive. The list
// is the canon set from the spec; placeholder substitution cannot
// introduce any of them because the seed alphabets (hex, base64, A-Z0-9)
// contain no "<", "(" or ":".
var inertPatterns = []string{
	"<script",
	"javascript:",
	"onerror=",
	"onload=",
	"<iframe",
	"onclick=",
	"document.cookie",
	"eval(",
	"window.location",
	`http-equiv="refresh"`,
	"location.href",
}

// prosePhrases are the I13 markers of article-style content. The
// heuristics are deliberately narrow — an H1 line plus three press-style
// phrases — so config-file decoys (which legitimately contain "#" comment
// lines in other formats, version numbers and error text) never trip them.
var prosePhrases = []string{"according to", "press release", "breaking news"}

var (
	// urlRe matches a URL with any scheme: https://host/path,
	// postgres://user:pw@db.test:5432/db, webpack:///src/x.js. The spec's
	// canonical form is https?://[A-Za-z0-9.:-]+; the scheme is
	// generalised because decoy bodies carry non-HTTP URLs too
	// (DATABASE_URL), while still requiring a scheme so ordinary "//" in
	// prose or paths is never mistaken for a URL. The character class is
	// the RFC 3986 authority set, so userinfo and ports stay inside the
	// match and hostFromURL can strip them.
	urlRe = regexp.MustCompile("[a-zA-Z][a-zA-Z0-9+.-]*://[A-Za-z0-9._~%!$&'()*+,;=:@-]*")

	// ipv4Re matches dotted-quad literals. Only octets 0-255 are treated
	// as addresses: "999.1.1.1" is a version-ish string, not an IP.
	ipv4Re = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

	// cardSpacedRe matches the grouped card form "4111 1111 1111 1111".
	cardSpacedRe = regexp.MustCompile(`\b[0-9]{4} [0-9]{4} [0-9]{4} [0-9]{4}\b`)

	// hexRunRe matches maximal runs of hex characters. A run of exactly
	// 16 characters that are all digits is card-shaped; runs that also
	// contain a-f (hashes, hex tokens) or are longer/shorter are not.
	hexRunRe = regexp.MustCompile(`[0-9a-fA-F]+`)

	// tokenRefRe extracts {{TOKEN:id}} references from a template body.
	tokenRefRe = regexp.MustCompile(`\{\{TOKEN:([^{}]*)\}\}`)

	// realProviderRes are credential shapes issued by real providers. A
	// minted honeytoken must fail ALL of them (I14): a decoy credential
	// that could plausibly validate against a real service could harm a
	// third party. Minted values always start with "mrg_live_", so these
	// are a defence in depth for future formats.
	realProviderRes = []*regexp.Regexp{
		regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`),                  // real AWS access key id
		regexp.MustCompile(`^sk_live_[0-9a-zA-Z]{20,}$`),          // real Stripe secret key
		regexp.MustCompile(`^ghp_[0-9A-Za-z]{36}$`),               // real GitHub PAT
		regexp.MustCompile(`BEGIN (PRIVATE KEY|RSA PRIVATE KEY)`), // PEM key material
	}
)

// Validate runs the catalog safety rules (DECOY-CATALOG.md section 3;
// invariants I8, I12, I13, I14) and returns every violation found, each
// naming the offending entry. A nil return means the catalog is safe to
// serve. It re-checks rules Load enforces (lead shape, honeytoken formats)
// because callers may pass hand-built catalogs that never went through
// Load — the pollution suite relies on that.
func Validate(c *Catalog, r Reserved) error {
	var errs []error

	// Full path set first: lead collisions can reference any entry.
	entryPaths := make(map[string]string, len(c.Entries))
	for _, e := range c.Entries {
		if owner, dup := entryPaths[e.Path]; dup {
			errs = append(errs, fmt.Errorf("entry %q: duplicate path %q (also entry %q)", e.ID, e.Path, owner))
			continue
		}
		entryPaths[e.Path] = e.ID
	}
	for _, e := range c.Entries {
		errs = append(errs, validateEntry(c, e, r, entryPaths)...)
	}
	return errors.Join(errs...)
}

// validateEntry returns all safety violations of one entry.
func validateEntry(c *Catalog, e Entry, r Reserved, entryPaths map[string]string) []error {
	var errs []error
	fail := func(msg string) {
		errs = append(errs, fmt.Errorf("entry %q: %s", e.ID, msg))
	}

	// f. Leads: shape, reserved namespaces, protected routes, collisions.
	for _, lead := range e.Leads {
		if !strings.HasPrefix(lead, "/") {
			fail(fmt.Sprintf("lead %q is not an absolute path", lead))
			continue
		}
		if strings.HasPrefix(lead, wellKnownPrefix) {
			fail(fmt.Sprintf("lead %q claims the reserved namespace %s (I4)", lead, wellKnownPrefix))
		}
		if owner, clash := entryPaths[lead]; clash {
			fail(fmt.Sprintf("lead %q collides with the path of entry %q", lead, owner))
		}
		if protectedLead(lead) {
			fail(fmt.Sprintf("lead %q is a protected-style path (I4: logins, checkout and API routes are never decoyed)", lead))
		}
	}

	// a. I8: inert bodies. Scanned on the template because that is what
	// the catalog author wrote; seeds cannot synthesise these markers.
	lowerBody := strings.ToLower(e.Body)
	for _, pat := range inertPatterns {
		if strings.Contains(lowerBody, pat) {
			fail(fmt.Sprintf("body contains %q: decoys are inert, nothing executable and no redirects (I8)", pat))
		}
	}

	// c. I13: no prose/article decoys. An H1 must start at column 0
	// (leading-space "# " is a comment in many config languages); the
	// phrase list is deliberately narrow, see prosePhrases.
	for i, line := range strings.Split(e.Body, "\n") {
		if strings.HasPrefix(line, "# ") {
			fail(fmt.Sprintf("body line %d starts a markdown H1: decoys are technical artifacts, never articles (I13)", i+1))
			break // one report per body is enough to fix the template
		}
	}
	for _, phrase := range prosePhrases {
		if strings.Contains(lowerBody, phrase) {
			fail(fmt.Sprintf("body contains prose marker %q: no article-style content in decoys (I13)", phrase))
		}
	}

	// e. No real personal data: card-like numbers. Scanned on the
	// template: rendered seeds (base64 blobs) could legitimately contain
	// 16-digit runs, but template digits are exactly what the author put
	// there. A 16-digit run inside a longer hex run is a hash, not a card.
	for _, m := range cardSpacedRe.FindAllString(e.Body, -1) {
		fail(fmt.Sprintf("body contains a card-like number %q: no real personal data (I8/I14)", m))
	}
	for _, run := range hexRunRe.FindAllString(e.Body, -1) {
		if len(run) == 16 && allDigits(run) {
			fail(fmt.Sprintf("body contains a 16-digit card-like number %q: no real personal data (I8/I14)", run))
		}
	}

	// d. Honeytokens: declared ids, known formats, inert minted shapes.
	declared := make(map[string]bool, len(e.Honeytokens))
	for _, h := range e.Honeytokens {
		if h.ID == "" {
			fail("honeytoken with empty id")
			continue
		}
		if declared[h.ID] {
			fail(fmt.Sprintf("honeytoken %q declared twice", h.ID))
		}
		declared[h.ID] = true
		if !knownHoneytokenFormats[h.Format] {
			fail(fmt.Sprintf("honeytoken %q has unknown format %q", h.ID, h.Format))
		}
		minted := MintToken(SampleSessionKey, e.ID, h.ID)
		if shape := realProviderShape(minted); shape != "" {
			fail(fmt.Sprintf("honeytoken %q would mint %q, matching real-provider shape %s (I14)", h.ID, minted, shape))
		}
	}
	for _, ref := range tokenRefs(e.Body) {
		if !declared[ref] {
			fail(fmt.Sprintf("body references honeytoken %q that the entry does not declare", ref))
		}
	}

	// b. I14 plus renderability: render a sample session and scan the
	// bytes that would actually be served. Placeholders can sit inside
	// URLs (postgres://deploy:{{TOKEN:…}}@db.test), so the URL scan must
	// run on rendered output, not on the raw template.
	rendered, err := c.renderSample(e)
	if err != nil {
		fail(fmt.Sprintf("sample render failed: %v", err))
		return errs
	}
	if strings.Contains(string(rendered), "{{") {
		fail(`body leaves unresolved placeholder syntax "{{" after rendering`)
	}
	for _, v := range scanThirdParty(string(rendered), r) {
		fail(fmt.Sprintf("%s (I14)", v))
	}
	return errs
}

// renderSample renders entry with the fixed SampleSessionKey, producing
// exactly the bytes a session with that key would be served (persona
// headers included when the catalog declares the persona). Hand-built
// catalogs without personas still render — a missing persona merely drops
// the persona headers, and the body scan does not depend on them.
func (c *Catalog) renderSample(e Entry) ([]byte, error) {
	rd, err := c.Render(e, SampleSessionKey)
	if err != nil {
		return nil, err
	}
	return rd.Body, nil
}

// scanThirdParty scans rendered decoy bytes for third-party references
// (I14): every URL host must be a reserved name or a reserved-range IP,
// every bare IPv4 literal must sit in a reserved network, and mailto:
// links are banned outright (no outbound links at all).
func scanThirdParty(body string, r Reserved) []string {
	var violations []string
	for _, m := range urlRe.FindAllString(body, -1) {
		host := hostFromURL(m)
		if host == "" {
			continue // scheme-only URL (webpack:///src/app.js) names nobody
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			if !r.IsReservedIP(ip) {
				violations = append(violations, fmt.Sprintf("URL %q points at non-reserved IP %s", m, host))
			}
			continue
		}
		if !r.IsReservedHost(host) {
			violations = append(violations, fmt.Sprintf("URL %q names non-reserved host %q", m, host))
		}
	}
	for _, m := range ipv4Re.FindAllString(body, -1) {
		ip, err := netip.ParseAddr(m)
		if err != nil {
			continue // an octet above 255: a version string, not an address
		}
		if !r.IsReservedIP(ip) {
			violations = append(violations, fmt.Sprintf("IPv4 literal %s is outside the reserved documentation ranges", m))
		}
	}
	if strings.Contains(strings.ToLower(body), "mailto:") {
		violations = append(violations, "body contains a mailto: link (no outbound links)")
	}
	return violations
}

// hostFromURL extracts the host of a token matched by urlRe: everything
// after "://", minus userinfo (after the last "@") and port (at the first
// ":" of what remains). Empty when the URL has no authority.
func hostFromURL(token string) string {
	i := strings.Index(token, "://")
	if i < 0 {
		return ""
	}
	rest := token[i+3:]
	if j := strings.LastIndex(rest, "@"); j >= 0 {
		rest = rest[j+1:]
	}
	if j := strings.Index(rest, ":"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// tokenRefs returns the {{TOKEN:id}} ids referenced by body, in order,
// deduplicated.
func tokenRefs(body string) []string {
	var refs []string
	seen := make(map[string]bool)
	for _, m := range tokenRefRe.FindAllStringSubmatch(body, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			refs = append(refs, m[1])
		}
	}
	return refs
}

// realProviderShape returns the real-provider pattern the value matches,
// or "" when it matches none (which is what every minted honeytoken must
// do, I14).
func realProviderShape(v string) string {
	for _, re := range realProviderRes {
		if re.MatchString(v) {
			return re.String()
		}
	}
	return ""
}

// protectedLead reports whether lead is on the default protected list
// (I4). Entries ending in "/" are prefixes ("/api/", "/wp-admin/"); the
// rest are exact matches.
func protectedLead(lead string) bool {
	for _, p := range defaultProtectedLeads {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(lead, p) {
				return true
			}
		} else if lead == p {
			return true
		}
	}
	return false
}

// allDigits reports whether s consists only of ASCII digits.
func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
