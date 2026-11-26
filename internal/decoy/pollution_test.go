// Pollution suite (spec/DECOY-CATALOG.md section 6) for the decoy data
// layer. These tests run against the REAL catalog and the REAL
// reserved-hosts file — fixtures here would prove nothing about what
// actually ships — and pin the safety invariants a decoy change can break:
// I8 (inert bodies), I12 (noindex header set, bounded footprint),
// I13 (no prose decoys) and I14 (reserved namespaces only, honeytokens
// that match no real provider).
package decoy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/mirage-shield/mirage/internal/model"
)

// Paths are relative to internal/decoy/: the shipped catalog and data.
const (
	realCatalogPath  = "../../spec/decoy-catalog/catalog.yaml"
	realReservedPath = "../../data/reserved-hosts.txt"
)

// sessionKeys are three session keys derived exactly the way the engine
// derives them (internal/model.SessionKey over reserved documentation
// IPs), so the suite exercises realistic 32-hex-char key material.
var sessionKeys = []string{
	model.SessionKey("192.0.2.10"),
	model.SessionKey("198.51.100.20"),
	model.SessionKey("203.0.113.30"),
}

func loadReal(t *testing.T) (*Catalog, Reserved) {
	t.Helper()
	c, err := Load(realCatalogPath)
	if err != nil {
		t.Fatalf("load shipped catalog: %v", err)
	}
	r, err := LoadReserved(realReservedPath)
	if err != nil {
		t.Fatalf("load shipped reserved hosts: %v", err)
	}
	return c, r
}

// badCatalog builds an otherwise-clean one-entry catalog whose entry
// carries the violation under test. The entry id is chosen by the caller
// so assertions can require it in the error text.
func badCatalog(id, body string, mutate func(*Entry)) *Catalog {
	e := Entry{
		ID:           id,
		Persona:      "test-persona",
		Path:         "/lure.txt",
		Status:       200,
		ContentType:  "text/plain",
		SizeCapBytes: 2048,
		Body:         body,
	}
	if mutate != nil {
		mutate(&e)
	}
	return &Catalog{
		CatalogVersion: "1",
		Personas: []Persona{{
			ID:      "test-persona",
			Story:   "test persona",
			Headers: []string{"X-Powered-By: Test"},
		}},
		Entries: []Entry{e},
	}
}

func assertViolation(t *testing.T, c *Catalog, r Reserved, wants ...string) {
	t.Helper()
	err := Validate(c, r)
	if err == nil {
		t.Fatalf("expected a violation (containing %v), got none", wants)
	}
	for _, w := range wants {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("violation missing %q; got: %v", w, err)
		}
	}
}

func assertClean(t *testing.T, c *Catalog, r Reserved) {
	t.Helper()
	if err := Validate(c, r); err != nil {
		t.Fatalf("catalog must validate clean, got: %v", err)
	}
}

// --- Shipped catalog -------------------------------------------------------

// The canon catalog must pass every safety rule as shipped; if it does
// not, the bug is in this package, not in the catalog.
func TestShippedCatalogValidates(t *testing.T) {
	c, r := loadReal(t)
	assertClean(t, c, r)
}

func TestShippedCatalogShape(t *testing.T) {
	c, _ := loadReal(t)
	if len(c.Personas) != 3 {
		t.Errorf("personas = %d, want 3 (v1 canon)", len(c.Personas))
	}
	if len(c.Entries) != 6 {
		t.Errorf("entries = %d, want 6 (v1 canon)", len(c.Entries))
	}
	e, ok := c.ByPath("/api/docs")
	if !ok || e.ID != "api-docs-dev" {
		t.Errorf("ByPath(/api/docs) = %q, %v; want api-docs-dev, true", e.ID, ok)
	}
	if _, ok := c.ByPath("/not-a-decoy"); ok {
		t.Error("ByPath must miss unknown paths")
	}
	leads := c.AllLeads()
	if len(leads) == 0 || len(slices.Compact(slices.Clone(leads))) != len(leads) {
		// AllLeads is documented to deduplicate; the v1 catalog has no
		// duplicate leads, so the result must be unique.
		t.Errorf("AllLeads = %v, want non-empty and deduplicated", leads)
	}
	if !slices.Contains(leads, "/v1/admin/tokens") {
		t.Errorf("AllLeads missing /v1/admin/tokens: %v", leads)
	}
	if got := c.Leads(e); len(got) != len(e.Leads) {
		t.Errorf("Leads(api-docs-dev) = %v, want %v", got, e.Leads)
	}
}

// --- Rendering: I12 headers, determinism, size caps ------------------------

// Every decoy response carries the full noindex header set exactly once
// (I12), plus its persona's headers, for every entry and session.
func TestNoindexHeaderOnEveryResponse(t *testing.T) {
	c, _ := loadReal(t)
	for _, e := range c.Entries {
		p, ok := c.personaByID(e.Persona)
		if !ok {
			t.Fatalf("entry %s: persona %s missing from catalog", e.ID, e.Persona)
		}
		for _, key := range sessionKeys {
			rd, err := c.Render(e, key)
			if err != nil {
				t.Fatalf("render %s: %v", e.ID, err)
			}
			if rd.Status != e.Status || rd.ContentType != e.ContentType || rd.DecoyID != e.ID {
				t.Errorf("entry %s: rendered status/content-type/id = %d/%s/%s", e.ID, rd.Status, rd.ContentType, rd.DecoyID)
			}
			robots := 0
			for _, h := range rd.Headers {
				name, _, _ := strings.Cut(h, ":")
				if strings.EqualFold(strings.TrimSpace(name), "X-Robots-Tag") {
					robots++
					if h != noindexHeader {
						t.Errorf("entry %s: X-Robots-Tag value %q, want the full I12 set", e.ID, h)
					}
				}
			}
			if robots != 1 {
				t.Errorf("entry %s: X-Robots-Tag appears %d times, want exactly 1 (I12)", e.ID, robots)
			}
			for _, ph := range p.Headers {
				if !slices.Contains(rd.Headers, ph) {
					t.Errorf("entry %s: persona header %q missing from render", e.ID, ph)
				}
			}
		}
	}
}

// The same session key must render byte-identical decoys every time —
// an attacker re-fetching a trap must never see it flicker.
func TestRenderIsDeterministic(t *testing.T) {
	c, _ := loadReal(t)
	for _, e := range c.Entries {
		a, err := c.Render(e, sessionKeys[0])
		if err != nil {
			t.Fatalf("render %s: %v", e.ID, err)
		}
		b, err := c.Render(e, sessionKeys[0])
		if err != nil {
			t.Fatalf("render %s: %v", e.ID, err)
		}
		if string(a.Body) != string(b.Body) || a.Status != b.Status ||
			a.ContentType != b.ContentType || a.DecoyID != b.DecoyID ||
			!slices.Equal(a.Headers, b.Headers) {
			t.Errorf("entry %s: same session key rendered two different responses", e.ID)
		}
	}
}

// Different sessions must get different seeded material — otherwise one
// leaked seed would de-anonymise every session. Entries without
// placeholders are static by design and must render identically.
func TestRenderVariesBySession(t *testing.T) {
	c, _ := loadReal(t)
	for _, e := range c.Entries {
		bodies := make([]string, len(sessionKeys))
		for i, key := range sessionKeys {
			rd, err := c.Render(e, key)
			if err != nil {
				t.Fatalf("render %s: %v", e.ID, err)
			}
			bodies[i] = string(rd.Body)
		}
		dynamic := strings.Contains(e.Body, "{{")
		for i := 0; i < len(bodies); i++ {
			for j := i + 1; j < len(bodies); j++ {
				switch {
				case dynamic && bodies[i] == bodies[j]:
					t.Errorf("entry %s: sessions %d and %d rendered identical bodies", e.ID, i, j)
				case !dynamic && bodies[i] != bodies[j]:
					t.Errorf("entry %s: static body rendered differently for sessions %d and %d", e.ID, i, j)
				}
			}
		}
	}
}

// Rendered bodies must respect the entry's size cap (I12 bounded
// footprint), at most the cap plus one truncation marker.
func TestRenderHonoursSizeCap(t *testing.T) {
	c, _ := loadReal(t)
	slack := len("[truncated]") + 1
	for _, e := range c.Entries {
		for _, key := range sessionKeys {
			rd, err := c.Render(e, key)
			if err != nil {
				t.Fatalf("render %s: %v", e.ID, err)
			}
			if max := e.SizeCapBytes + slack; len(rd.Body) > max {
				t.Errorf("entry %s: rendered body %d bytes exceeds cap %d + marker", e.ID, len(rd.Body), e.SizeCapBytes)
			}
		}
	}
}

// Re-run the I14 scan on RENDERED output: placeholders resolve into URLs
// (the DATABASE_URL token), so the scan must see served bytes, and those
// bytes may only name reserved hosts and reserved addresses.
func TestRenderedOutputStaysInReservedNamespaces(t *testing.T) {
	c, r := loadReal(t)
	for _, e := range c.Entries {
		for _, key := range sessionKeys {
			rd, err := c.Render(e, key)
			if err != nil {
				t.Fatalf("render %s: %v", e.ID, err)
			}
			if v := scanThirdParty(string(rd.Body), r); len(v) > 0 {
				t.Errorf("entry %s session %s: third-party references in rendered body: %v", e.ID, key, v)
			}
			if strings.Contains(string(rd.Body), "{{") {
				t.Errorf("entry %s session %s: unresolved placeholder syntax in rendered body", e.ID, key)
			}
		}
	}
}

// --- Honeytokens (I14) ------------------------------------------------------

// Every minted honeytoken must fail every real-provider credential shape:
// a decoy credential that could validate against a real service could
// harm a third party.
func TestMintedTokensMatchNoRealProvider(t *testing.T) {
	c, _ := loadReal(t)
	for _, e := range c.Entries {
		for _, h := range e.Honeytokens {
			for _, key := range sessionKeys {
				tok := MintToken(key, e.ID, h.ID)
				if !strings.HasPrefix(tok, "mrg_live_") || len(tok) != len("mrg_live_")+24 {
					t.Errorf("entry %s: token %q is not token_alnum_24 shaped", e.ID, tok)
				}
				if shape := realProviderShape(tok); shape != "" {
					t.Errorf("entry %s token %s: minted %q matches real-provider shape %s (I14)", e.ID, h.ID, tok, shape)
				}
			}
		}
	}
}

// The mint formula is pinned cross-engine: the worker's test and golden
// vector v05 mint this exact value for the session of 203.0.113.10 and
// later replay it as a Bearer credential.
func TestHoneytokenGoldenAnchor(t *testing.T) {
	key := model.SessionKey("203.0.113.10")
	got := MintToken(key, "env-file-staging", "db_password")
	if want := "mrg_live_63e36e2d68663c27f6841a68"; got != want {
		t.Fatalf("MintToken(203.0.113.10 session) = %q, want the v05 golden %q", got, want)
	}
}

// The same token id used twice in one body must mint the same string:
// DATABASE_URL and DB_PASSWORD have to agree or the decoy contradicts
// itself.
func TestTokenIsConsistentInsideABody(t *testing.T) {
	c, _ := loadReal(t)
	e, ok := c.ByPath("/.env")
	if !ok {
		t.Fatal("shipped catalog missing /.env entry")
	}
	rd, err := c.Render(e, sessionKeys[0])
	if err != nil {
		t.Fatalf("render /.env: %v", err)
	}
	want := MintToken(sessionKeys[0], e.ID, "db_password")
	body := string(rd.Body)
	if n := strings.Count(body, want); n != 2 {
		t.Errorf("db_password should appear twice (DATABASE_URL and DB_PASSWORD), found %d", n)
	}
	if !strings.Contains(body, "postgres://deploy:"+want+"@db.test:5432/staging") {
		t.Errorf("DATABASE_URL does not embed the minted token:\n%s", body)
	}
}

// --- Negative validation: each violation is caught and names the entry -----

func TestValidateRejectsExecutableContent(t *testing.T) {
	_, r := loadReal(t)
	for _, body := range []string{
		"ok <script src=\"/x\"></script>\n",
		"<iframe src=\"https://example.com/f\"></iframe>\n",
		"<a href=\"javascript:alert(1)\">x</a>\n",
		"<img src=x onerror=alert(1)>\n",
		"<body onload=init()>\n",
		"<meta http-equiv=\"refresh\" content=\"0;url=https://example.com/\">\n",
	} {
		assertViolation(t, badCatalog("bad-inert", body, nil), r, "bad-inert")
	}
}

func TestValidateRejectsNonReservedURLs(t *testing.T) {
	_, r := loadReal(t)
	for _, tc := range []struct{ body, want string }{
		// example.org itself is reserved, but a lookalike real domain is
		// not — the negative case must use a genuinely non-reserved host.
		{"docs: https://real-attacker-site.com/setup\n", "real-attacker-site.com"},
		{"db: postgres://u:pw@db.production.example.io:5432/main\n", "example.io"},
		{"cdn: http://8.8.8.8/jquery.js\n", "8.8.8.8"},
		{"contact: mailto:admin@example.net\n", "mailto"},
	} {
		assertViolation(t, badCatalog("bad-url", tc.body, nil), r, "bad-url", tc.want)
	}
	// Controls: exactly the URL shapes the shipped catalog uses — a
	// subdomain of a reserved name, a .test host, a reserved-range IP.
	assertClean(t, badCatalog("good-url",
		"APP_URL=https://staging.example.com\n"+
			"REMOTE=https://git.test/app.git\n"+
			"DB=postgres://deploy:x@db.test:5432/staging\n"+
			"CDN=http://192.0.2.7/assets/\n", nil), r)
}

func TestValidateRejectsProseDecoys(t *testing.T) {
	_, r := loadReal(t)
	for _, body := range []string{
		"# Internal announcement\nWe are moving offices.\n",
		"## not an H1, but: According to sources, revenue doubled.\n",
		"Quoted from a press release yesterday.\n",
		"Breaking news: the staging deploy failed.\n",
	} {
		assertViolation(t, badCatalog("bad-prose", body, nil), r, "bad-prose")
	}
}

func TestValidateRejectsCardNumbers(t *testing.T) {
	_, r := loadReal(t)
	for _, body := range []string{
		"donor=4111111111111111\n",
		"card: 4111 1111 1111 1111\n",
	} {
		assertViolation(t, badCatalog("bad-card", body, nil), r, "bad-card")
	}
	// Controls: hashes, 20-digit serials and short numbers are not cards.
	assertClean(t, badCatalog("good-cards",
		"hash=abcdef0123456789abcdef01\nserial=12345678901234567890\nport=5432\n", nil), r)
}

func TestValidateRejectsUnknownTokenReference(t *testing.T) {
	_, r := loadReal(t)
	c := badCatalog("bad-token", "KEY={{TOKEN:ghost}}\n", func(e *Entry) {
		e.Honeytokens = []Honeytoken{{ID: "db_password", Format: "token_alnum_24"}}
	})
	assertViolation(t, c, r, "bad-token", "ghost")
}

func TestValidateRejectsUnsafeLeads(t *testing.T) {
	_, r := loadReal(t)
	for _, tc := range []struct {
		name  string
		leads []string
		want  string
	}{
		{"lead collides with own path", []string{"/lure.txt"}, "collides"},
		{"lead is relative", []string{"storage/logs"}, "absolute"},
		{"lead claims well-known", []string{"/.well-known/acme-challenge"}, "well-known"},
		{"lead is wp-login", []string{"/wp-login.php"}, "protected"},
		{"lead is wp-admin prefix", []string{"/wp-admin/plugins.php"}, "protected"},
		{"lead is checkout", []string{"/checkout"}, "protected"},
		{"lead is cart", []string{"/cart"}, "protected"},
		{"lead is under /api/", []string{"/api/v1/tokens"}, "protected"},
	} {
		c := badCatalog("bad-lead", "x\n", func(e *Entry) { e.Leads = tc.leads })
		assertViolation(t, c, r, "bad-lead")
		if err := Validate(c, r); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want violation containing %q, got: %v", tc.name, tc.want, err)
		}
	}
	// A lead may also collide with ANOTHER entry's path; the error must
	// still name the entry whose lead is wrong.
	two := badCatalog("bad-lead", "x\n", func(e *Entry) { e.Leads = []string{"/other"} })
	two.Entries = append(two.Entries, Entry{
		ID: "other-entry", Persona: "test-persona", Path: "/other", Status: 200,
		ContentType: "text/plain", SizeCapBytes: 512, Body: "y\n",
	})
	assertViolation(t, two, r, "bad-lead", "other-entry")
}

// --- Reserved namespaces (I14) ----------------------------------------------

// The reserved-host rules in one table, including the cases the task
// calls out: staging.example.com (the catalog's APP_URL) is reserved as a
// subdomain of example.com; foo.test.evil.com is NOT reserved even though
// it contains a .test label mid-name.
func TestReservedHostMatching(t *testing.T) {
	_, r := loadReal(t)
	for _, tc := range []struct {
		host string
		want bool
		note string
	}{
		{"example.com", true, "exact reserved name"},
		{"EXAMPLE.com", true, "exact match is case-insensitive"},
		{"example.net", true, ""},
		{"example.org", true, ""},
		{"example.com:443", true, "port is stripped"},
		{"db.test:5432", true, "port is stripped on suffixes too"},
		{"staging.example.com", true, "subdomain of a reserved name (catalog APP_URL)"},
		{"sub.EXAMPLE.COM", true, "subdomain match is case-insensitive"},
		{"evil.example.org", true, "still inside the reserved example.org domain"},
		{"foo.test", true, "wildcard .test suffix"},
		{"db.test", true, ""},
		{"db.legacy.test", true, "multi-label .test host"},
		{"deep.a.invalid", true, "wildcard .invalid suffix"},
		{"host.example", true, "wildcard .example suffix"},
		{"foo.test.evil.com", false, "reserved label mid-name is not a reservation"},
		{"attacker.test.evil.com", false, ""},
		{"real-attacker-site.com", false, ""},
		{"notexample.com", false, "suffix needs the separating dot"},
		{"test", false, "bare label, not under .test"},
		{"", false, ""},
	} {
		if got := r.IsReservedHost(tc.host); got != tc.want {
			t.Errorf("IsReservedHost(%q) = %v, want %v (%s)", tc.host, got, tc.want, tc.note)
		}
	}
}

func TestReservedIPMatching(t *testing.T) {
	_, r := loadReal(t)
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"192.0.2.1", true},
		{"192.0.2.254", true},
		{"198.51.100.7", true},
		{"203.0.113.200", true},
		{"192.0.3.1", false}, // TEST-NET-1 is /24, not /16
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"127.0.0.1", false}, // loopback is never-scored config, not reserved
	} {
		addr, err := netip.ParseAddr(tc.ip)
		if err != nil {
			t.Fatalf("parse %s: %v", tc.ip, err)
		}
		if got := r.IsReservedIP(addr); got != tc.want {
			t.Errorf("IsReservedIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// --- Loading ---------------------------------------------------------------

// Strict decoding: an unknown YAML field is a boot-time error, not a
// silently ignored key.
func TestLoadStrictDecoding(t *testing.T) {
	const doc = `catalog_version: "1"
personas: []
entries:
  - id: e1
    persona: p
    path: /a
    status: 200
    content_type: text/plain
    size_cap_bytes: 512
    body: hello
    surprise: true
`
	path := filepath.Join(t.TempDir(), "catalog.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "surprise") {
		t.Fatalf("strict decoding must reject unknown fields, got: %v", err)
	}
}

// The structural rules Load enforces, exercised as hand-built catalogs.
func TestLoadStructuralValidation(t *testing.T) {
	base := func() *Catalog {
		return &Catalog{
			CatalogVersion: "1",
			Personas:       []Persona{{ID: "p", Headers: []string{"X-Test: 1"}}},
			Entries: []Entry{{
				ID: "e1", Persona: "p", Path: "/a", Status: 200,
				ContentType: "text/plain", SizeCapBytes: 512, Body: "x",
				Leads: []string{"/lead"},
			}},
		}
	}
	cases := []struct {
		name   string
		mutate func(*Catalog)
		want   string
	}{
		{"duplicate entry id", func(c *Catalog) { c.Entries = append(c.Entries, c.Entries[0]) }, "duplicate entry id"},
		{"duplicate path", func(c *Catalog) {
			e := c.Entries[0]
			e.ID = "e2"
			c.Entries = append(c.Entries, e)
		}, "already used"},
		{"unknown persona", func(c *Catalog) { c.Entries[0].Persona = "ghost" }, "unknown persona"},
		{"status too low", func(c *Catalog) { c.Entries[0].Status = 199 }, "status 199"},
		{"status too high", func(c *Catalog) { c.Entries[0].Status = 600 }, "status 600"},
		{"size cap too small", func(c *Catalog) { c.Entries[0].SizeCapBytes = 63 }, "size_cap_bytes 63"},
		{"size cap too big", func(c *Catalog) { c.Entries[0].SizeCapBytes = 65537 }, "size_cap_bytes 65537"},
		{"relative path", func(c *Catalog) { c.Entries[0].Path = "env" }, `must start with`},
		{"query string in path", func(c *Catalog) { c.Entries[0].Path = "/env?debug=1" }, "query string"},
		{"empty content type", func(c *Catalog) { c.Entries[0].ContentType = "" }, "content_type"},
		{"relative lead", func(c *Catalog) { c.Entries[0].Leads = []string{"logs"} }, "absolute"},
		{"well-known lead", func(c *Catalog) { c.Entries[0].Leads = []string{"/.well-known/x"} }, "well-known"},
		{"lead collides with path", func(c *Catalog) { c.Entries[0].Leads = []string{"/a"} }, "collides"},
		{"unknown honeytoken format", func(c *Catalog) {
			c.Entries[0].Honeytokens = []Honeytoken{{ID: "t", Format: "real_aws_key"}}
		}, "unknown format"},
		{"missing version", func(c *Catalog) { c.CatalogVersion = "" }, "catalog_version"},
		{"malformed persona header", func(c *Catalog) {
			c.Personas[0].Headers = []string{"NoColonHere"}
		}, "not a"},
	}
	for _, tc := range cases {
		c := base()
		tc.mutate(c)
		err := validateStructure(c)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error containing %q, got: %v", tc.name, tc.want, err)
		}
	}
	if err := validateStructure(base()); err != nil {
		t.Errorf("clean catalog must pass structural checks, got: %v", err)
	}
}

// --- Truncation and seed shapes ---------------------------------------------

// A decoy must always render (I1 spirit): an oversized body truncates at
// a rune boundary with a visible marker instead of erroring, and the
// final body stays within the cap like the worker's renderer.
func TestOversizedBodyTruncatesNeverErrors(t *testing.T) {
	c := &Catalog{CatalogVersion: "1"}

	// Odd cap over multi-byte runes: the naive cut would split a rune.
	e := Entry{
		ID: "trunc-utf8", Persona: "p", Path: "/trunc", Status: 200,
		ContentType: "text/plain", SizeCapBytes: 61, Body: strings.Repeat("é", 100), // 200 bytes
	}
	rd, err := c.Render(e, "session")
	if err != nil {
		t.Fatalf("render must never fail on size: %v", err)
	}
	if !utf8.Valid(rd.Body) {
		t.Error("truncation split a multi-byte rune")
	}
	if !strings.HasSuffix(string(rd.Body), truncationMarker) {
		t.Errorf("truncated body must end with %q, got %q", truncationMarker, rd.Body)
	}
	if len(rd.Body) > e.SizeCapBytes {
		t.Errorf("truncated body %d bytes exceeds cap %d", len(rd.Body), e.SizeCapBytes)
	}
	// 61 - 12 marker = 49 bytes budget; "é" is 2 bytes, so 24 whole runes.
	if want := strings.Repeat("é", 24) + truncationMarker; string(rd.Body) != want {
		t.Errorf("truncated body = %q, want %q", rd.Body, want)
	}

	// A body under the cap passes through untouched.
	small := Entry{
		ID: "short", Persona: "p", Path: "/short", Status: 200,
		ContentType: "text/plain", SizeCapBytes: 512, Body: "short body\n",
	}
	rd, err = c.Render(small, "session")
	if err != nil {
		t.Fatal(err)
	}
	if string(rd.Body) != "short body\n" {
		t.Errorf("body under the cap must be untouched, got %q", rd.Body)
	}
}

// Seed specs render exactly the shapes the catalog relies on, from the
// digest formulas in DECOY-CATALOG.md section 4.
func TestSeedSpecsRenderAsSpecified(t *testing.T) {
	material := "key:entry:seed:0"

	hex16, err := renderSeed(material, "16_HEX")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(material))
	if want := hex.EncodeToString(sum[:])[:16]; hex16 != want {
		t.Errorf("16_HEX = %q, want first 16 hex of sha256(material) %q", hex16, want)
	}

	b64, err := renderSeed(material, "44_B64")
	if err != nil {
		t.Fatal(err)
	}
	if len(b64) != 44 || strings.Contains(b64, "=") {
		t.Errorf("44_B64 = %q, want 44 unpadded base64 chars", b64)
	}
	if raw, err := base64.StdEncoding.DecodeString(b64); err != nil || len(raw) != 33 {
		t.Errorf("44_B64 must decode to 33 raw bytes, got %d bytes, err %v", len(raw), err)
	}

	up, err := renderSeed(material, "13_UPPER")
	if err != nil {
		t.Fatal(err)
	}
	if len(up) != 13 {
		t.Errorf("13_UPPER length = %d, want 13", len(up))
	}
	for _, c := range up {
		if !strings.ContainsRune(upperAlphabet, c) {
			t.Errorf("13_UPPER char %q outside [A-Z0-9]", c)
		}
	}

	// Distinct seed materials never collide.
	a, _ := renderSeed("m:0", "8_HEX")
	b, _ := renderSeed("m:1", "8_HEX")
	if a == b {
		t.Error("different seed materials rendered the same value")
	}

	// Malformed specs are rejected — they are catalog bugs, caught by
	// Validate's sample render, never silently served.
	for _, spec := range []string{"x_HEX", "0_HEX", "65_HEX", "6_B64", "nounderscore", "16_LOWER", "44_b64"} {
		if _, err := renderSeed(material, spec); err == nil {
			t.Errorf("SEED spec %q must be rejected", spec)
		}
	}
}

// Two SEED placeholders in one body render different values: the
// occurrence index disambiguates them (DECOY-CATALOG.md section 4).
func TestMultipleSeedsInOneBodyDiffer(t *testing.T) {
	c := &Catalog{CatalogVersion: "1"}
	e := Entry{
		ID: "seeds", Persona: "p", Path: "/seeds", Status: 200,
		ContentType: "text/plain", SizeCapBytes: 512,
		Body: "A={{SEED:8_HEX}}\nB={{SEED:8_HEX}}\n",
	}
	rd, err := c.Render(e, "session")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(rd.Body)), "\n")
	if len(lines) != 2 {
		t.Fatalf("rendered body = %q, want two lines", rd.Body)
	}
	if lines[0] == lines[1] || !strings.HasPrefix(lines[0], "A=") || !strings.HasPrefix(lines[1], "B=") {
		t.Errorf("seed occurrences must differ: %q vs %q", lines[0], lines[1])
	}
}
