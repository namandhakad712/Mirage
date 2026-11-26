package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/mirage-shield/mirage/internal/model"
)

// Unit tests beyond the golden vectors: window semantics, session store
// bounds, concurrency, expiry, normalization edge cases and the gating
// canon decisions. All client IPs are RFC 5737 documentation addresses.

const t0 = int64(1_780_000_000_000)

const (
	browserUA  = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
	sqlmapUA   = "sqlmap/1.8.2#stable (http://sqlmap.org)"
	curlUA     = "curl/8.5.0"
	googlebot  = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	macBrowser = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
)

// testProtectedRoutes is the canon list (config default, vectors policy).
var testProtectedRoutes = []string{"/wp-login.php", "/wp-admin/", "/checkout", "/cart", "/api/"}

func loadTestRules(t *testing.T) Rules {
	t.Helper()
	r, err := LoadRules(
		repoPath(t, "data"),
		repoPath(t, "spec", "decoy-catalog", "catalog.yaml"),
		testProtectedRoutes,
	)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return r
}

// mreq builds a GET request with the common fields.
func mreq(ip, path string, ts int64, ua string, headers int, cookie bool) model.Request {
	return model.Request{
		Method:      "GET",
		Path:        path,
		ClientIP:    ip,
		UserAgent:   ua,
		HeaderCount: headers,
		HasCookie:   cookie,
		TsMs:        ts,
	}
}

// assertDecision checks the four core fields plus a label for the failure.
func assertDecision(t *testing.T, label string, got model.Decision, wantSignals []string, wantVerdict string, wantScore int, wantReason string) {
	t.Helper()
	var diffs []string
	if !equalStrings(wantSignals, got.Signals) {
		diffs = append(diffs, fmt.Sprintf("signals: want %v, got %v", wantSignals, got.Signals))
	}
	if got.Verdict != wantVerdict {
		diffs = append(diffs, fmt.Sprintf("verdict: want %s, got %s", wantVerdict, got.Verdict))
	}
	if got.Score != wantScore {
		diffs = append(diffs, fmt.Sprintf("score: want %d, got %d", wantScore, got.Score))
	}
	if got.ReasonCode != wantReason {
		diffs = append(diffs, fmt.Sprintf("reason_code: want %s, got %s", wantReason, got.ReasonCode))
	}
	if len(diffs) > 0 {
		t.Errorf("%s:\n  %s", label, strings.Join(diffs, "\n  "))
	}
}

// wantTokenFor recomputes the honeytoken formula independently of the
// engine, the way tools/gen_vectors.py does: "mrg_live_" + first 24 hex
// chars of sha256(sessionKey + ":" + entryID + ":" + tokenID).
func wantTokenFor(ip, entryID, tokenID string) string {
	sum := sha256.Sum256([]byte(model.SessionKey(ip) + ":" + entryID + ":" + tokenID))
	return "mrg_live_" + hex.EncodeToString(sum[:])[:24]
}

func TestDefaultPolicyMatchesSpec(t *testing.T) {
	want := Policy{
		SessionTTLms:        1_800_000,
		UAWindowMs:          300_000,
		EnumWindowMs:        60_000,
		EnumThreshold:       8,
		UARotationThreshold: 4,
		BanTTLms:            1_800_000,
		TagScore:            15,
		TagCumBefore:        25,
		DecoyRouteScore:     25,
		ThrottleScore:       40,
		BanScore:            60,
	}
	if got := DefaultPolicy(); got != want {
		t.Errorf("DefaultPolicy drifted: got %+v, want %+v", got, want)
	}
}

func TestNormalizePath(t *testing.T) {
	cases := []struct {
		raw        string
		wantPath   string
		wantEscape bool
	}{
		{"/", "/", false},
		{"/?q=1", "/", false},
		{"/about?x=1&y=2", "/about", false},
		{"/.env", "/.env", false}, // ".env" is a segment, not "."
		{"/shop/../wp-config.php.bak?debug=1", "/wp-config.php.bak", false}, // v15 req1
		{"/../../.env", "/.env", true},                                      // v15 req2: clamped at root
		{"/a/../../..", "/", true},                                          // v15 req3
		{"/..", "/", true},                                                  // leading ".."
		{"/a/./b", "/a/b", false},                                           // "." dropped
		{"/a/./b/", "/a/b", false},                                          // trailing slash dropped
		{"//a/./b", "/a/b", false},                                          // double slash collapsed
		{"/a/b/..", "/a", false},                                            // trailing ".." pops
		{"/.", "/", false},                                                  // bare "." is not an escape
		{"about", "/about", false},                                          // degenerate input, graceful
		{"", "/", false},                                                    // degenerate input, graceful
	}
	for _, c := range cases {
		gotPath, gotEscape := normalizePath(c.raw)
		if gotPath != c.wantPath || gotEscape != c.wantEscape {
			t.Errorf("normalizePath(%q) = (%q, %v), want (%q, %v)", c.raw, gotPath, gotEscape, c.wantPath, c.wantEscape)
		}
	}
}

func TestScannerTrailingSlashMatchesBothDirections(t *testing.T) {
	rules := loadTestRules(t)
	cases := []struct {
		path string
		want bool
	}{
		{"/phpmyadmin-old", true},  // list entry has the trailing slash (SIGNALS 3.3, v18)
		{"/phpmyadmin-old/", true}, // request carries the trailing slash
		{"/backup.tar.gz", true},   // entry has none...
		{"/backup.tar.gz/", true},  // ...but the request may add one
		{"/pma-old", true},         // entry "/pma-old/"
		{"/.env", true},
		{"/.env/", true},
		{"/phpmyadmin-oldx", false}, // no prefix semantics
		{"/phpmyadmin-old/sub", false},
		{"/", false},
		{"/about", false},
	}
	for _, c := range cases {
		if got := rules.isScanner(c.path); got != c.want {
			t.Errorf("isScanner(%q) = %v, want %v", c.path, got, c.want)
		}
	}

	// Decide-level: the slashless request against the slashed list entry.
	eng := New(rules)
	got := eng.Decide(mreq("203.0.113.120", "/pma-old", t0, browserUA, 8, false), false)
	assertDecision(t, "slashless request vs slashed entry", got, []string{"scanner_path"}, model.VerdictTag, 25, "SIG-101")
}

func TestProtectedRouteSemantics(t *testing.T) {
	rules := loadTestRules(t)
	cases := []struct {
		path string
		want bool
	}{
		{"/wp-login.php", true},
		{"/wp-login.php/extra", false}, // non-slash entries match exactly (config.IsProtected semantics)
		{"/wp-admin/", true},
		{"/wp-admin/setup.php", true}, // slash entries are prefixes
		{"/checkout", true},
		{"/checkout/", false},
		{"/cart", true},
		{"/api/", true},
		{"/api/v1/auth", true},
		{"/apiary", false}, // prefix must respect the segment boundary
		{"/about", false},
	}
	for _, c := range cases {
		if got := rules.isProtected(c.path); got != c.want {
			t.Errorf("isProtected(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestHoneytokenMintExactAndSubstringMatch(t *testing.T) {
	rules := loadTestRules(t)
	eng := New(rules)
	ip := "203.0.113.99"
	token := wantTokenFor(ip, "env-file-staging", "db_password")

	// Serve the env decoy: mints the db_password honeytoken for this session.
	d1 := eng.Decide(mreq(ip, "/.env", t0, browserUA, 8, false), false)
	assertDecision(t, "serve env decoy", d1, []string{"scanner_path"}, model.VerdictDecoyRoute, 25, "SIG-101")
	if d1.DecoyID != "env-file-staging" {
		t.Errorf("decoy_id = %q, want env-file-staging", d1.DecoyID)
	}

	// Exact token as a bearer credential on a protected route: the ban
	// survives the protected-route cap (SIGNALS section 5, W4).
	authed := mreq(ip, "/api/v1/auth", t0+1000, browserUA, 8, false)
	authed.Method = "POST"
	authed.AuthHint = "Bearer " + token
	d2 := eng.Decide(authed, false)
	assertDecision(t, "exact honeytoken use", d2, []string{"honeytoken_use"}, model.VerdictBan, 75, "SIG-104")
	if d2.BanTTLms == nil || *d2.BanTTLms != 1_800_000 {
		t.Errorf("ban_ttl_ms = %v, want 1800000", d2.BanTTLms)
	}

	// The same token embedded in a larger credential blob (substring match).
	embedded := mreq(ip, "/about", t0+2000, browserUA, 9, true)
	embedded.AuthHint = "postgres://deploy:" + token + "@db.test:5432/staging"
	d3 := eng.Decide(embedded, false)
	assertDecision(t, "substring honeytoken use", d3, []string{"honeytoken_use"}, model.VerdictBan, 125, "SIG-104")

	// A well-formed but never-minted token must not match; the dirty session
	// still tags via history (SIGNALS section 5.1).
	foreign := mreq(ip, "/about", t0+3000, browserUA, 9, true)
	foreign.AuthHint = "mrg_live_000000000000000000000000"
	d4 := eng.Decide(foreign, false)
	assertDecision(t, "foreign token", d4, nil, model.VerdictTag, 125, model.FailOpenReason)
}

func TestNoCookieSuppressedBySuspiciousUA(t *testing.T) {
	// Canon decision 2: no_cookie_persistence gates on signals 1-7, so a
	// firing ua_suspicious suppresses it even in an otherwise-clean session.
	eng := New(loadTestRules(t))
	ip := "203.0.113.101"
	for i := 0; i < 4; i++ {
		got := eng.Decide(mreq(ip, "/products", t0+int64(i)*1000, browserUA, 8, false), false)
		assertDecision(t, fmt.Sprintf("clean request %d", i+1), got, nil, model.VerdictObserve, 0, model.FailOpenReason)
	}
	got := eng.Decide(mreq(ip, "/products", t0+4000, sqlmapUA, 8, false), false)
	assertDecision(t, "5th request with tool UA", got, []string{"ua_suspicious"}, model.VerdictTag, 15, "SIG-106")
}

func TestDecoyServedOnlyOnDecoyRoute(t *testing.T) {
	rules := loadTestRules(t)

	// Throttled decoy hit: 45 >= 40 -> throttle, so no leads are registered
	// and the follow-up lead request scores nothing (canon decision 6).
	engThrottled := New(rules)
	ipA := "203.0.113.102"
	d1 := engThrottled.Decide(mreq(ipA, "/admin/login", t0, sqlmapUA, 4, false), false)
	assertDecision(t, "throttled decoy hit", d1, []string{"decoy_hit", "ua_suspicious"}, model.VerdictThrottle, 45, "SIG-102")
	if d1.DecoyID != "" {
		t.Errorf("throttle served a decoy: decoy_id = %q, want empty", d1.DecoyID)
	}
	d2 := engThrottled.Decide(mreq(ipA, "/admin/login/verify", t0+1000, browserUA, 9, true), false)
	assertDecision(t, "lead after throttled hit (must NOT follow)", d2, nil, model.VerdictTag, 45, model.FailOpenReason)

	// Decoy route verdict: leads registered, follow-up bans.
	engServed := New(rules)
	ipB := "203.0.113.103"
	d3 := engServed.Decide(mreq(ipB, "/admin/login", t0, browserUA, 8, false), false)
	assertDecision(t, "served decoy hit", d3, []string{"decoy_hit"}, model.VerdictDecoyRoute, 30, "SIG-102")
	if d3.DecoyID != "admin-panel-legacy" {
		t.Errorf("decoy_id = %q, want admin-panel-legacy", d3.DecoyID)
	}
	d4 := engServed.Decide(mreq(ipB, "/admin/login/verify", t0+1000, browserUA, 9, true), false)
	assertDecision(t, "lead after served decoy", d4, []string{"decoy_lead_follow"}, model.VerdictBan, 70, "SIG-103")
	if d4.BanTTLms == nil {
		t.Error("decoy_lead_follow ban has no TTL")
	}
}

func TestSessionExpiryBoundaryAndReset(t *testing.T) {
	rules := loadTestRules(t)
	eng := New(rules)
	ip := "203.0.113.104"
	token := wantTokenFor(ip, "env-file-staging", "db_password")

	d1 := eng.Decide(mreq(ip, "/.env", t0, browserUA, 8, false), false)
	assertDecision(t, "arm the session", d1, []string{"scanner_path"}, model.VerdictDecoyRoute, 25, "SIG-101")

	// A gap of exactly the TTL is NOT an expiry (strictly greater is).
	d2 := eng.Decide(mreq(ip, "/about", t0+1_800_000, browserUA, 9, true), false)
	assertDecision(t, "gap == TTL keeps state", d2, nil, model.VerdictTag, 25, model.FailOpenReason)

	// 31 minutes later: the epoch resets first, cumulative back to 0.
	d3 := eng.Decide(mreq(ip, "/about", t0+3_660_000, browserUA, 9, true), false)
	assertDecision(t, "gap > TTL resets", d3, nil, model.VerdictObserve, 0, model.FailOpenReason)

	// The reset wiped the minted honeytoken: reuse must not fire.
	authed := mreq(ip, "/about", t0+3_660_001, browserUA, 9, true)
	authed.AuthHint = "Bearer " + token
	d4 := eng.Decide(authed, false)
	assertDecision(t, "token wiped by reset", d4, nil, model.VerdictObserve, 0, model.FailOpenReason)

	// The reset also wiped registered leads.
	d5 := eng.Decide(mreq(ip, "/storage/logs/laravel-staging.log", t0+3_660_002, browserUA, 9, true), false)
	assertDecision(t, "leads wiped by reset", d5, nil, model.VerdictObserve, 0, model.FailOpenReason)
}

func TestUARotationWindowSlides(t *testing.T) {
	eng := New(loadTestRules(t))
	ip := "203.0.113.105"

	// Three distinct UAs, all inside the 300 s window.
	for i, ua := range []string{"UA-A/1.0", "UA-B/1.0", "UA-C/1.0"} {
		got := eng.Decide(mreq(ip, "/products", t0+int64(i)*1000, ua, 9, true), false)
		assertDecision(t, fmt.Sprintf("rotating request %d", i+1), got, nil, model.VerdictObserve, 0, model.FailOpenReason)
	}

	// Exactly 300 s after UA-A: the boundary is inclusive (ts-t <= window),
	// so A,B,C,D are 4 distinct UAs and scanner_path ungates the rotation.
	d4 := eng.Decide(mreq(ip, "/.env", t0+300_000, "UA-D/1.0", 8, false), false)
	assertDecision(t, "rotation at the inclusive boundary", d4,
		[]string{"scanner_path", "ua_rotation"}, model.VerdictThrottle, 45, "SIG-101")

	// 301 s after UA-D: every earlier UA has slid out of the window, so the
	// same scanner request no longer fires ua_rotation.
	d5 := eng.Decide(mreq(ip, "/.env", t0+601_000, "UA-E/1.0", 8, false), false)
	assertDecision(t, "rotation window slid", d5, []string{"scanner_path"}, model.VerdictDecoyRoute, 70, "SIG-101")
}

func TestSessionEvictionAtCap(t *testing.T) {
	eng := NewWithCap(loadTestRules(t), 2)
	ipA, ipB, ipC := "203.0.113.106", "203.0.113.107", "203.0.113.108"

	d := eng.Decide(mreq(ipA, "/.env", t0, browserUA, 8, false), false)
	assertDecision(t, "session A", d, []string{"scanner_path"}, model.VerdictDecoyRoute, 25, "SIG-101")
	d = eng.Decide(mreq(ipB, "/.env", t0+1000, browserUA, 8, false), false)
	assertDecision(t, "session B", d, []string{"scanner_path"}, model.VerdictDecoyRoute, 25, "SIG-101")
	if got := eng.Len(); got != 2 {
		t.Fatalf("Len() = %d after two sessions, want 2", got)
	}

	// The third session pushes past the cap: the most idle (A, oldest
	// lastSeen) is evicted — the bounded session memory of design section 6.
	d = eng.Decide(mreq(ipC, "/.env", t0+2000, browserUA, 8, false), false)
	assertDecision(t, "session C", d, []string{"scanner_path"}, model.VerdictDecoyRoute, 25, "SIG-101")
	if got := eng.Len(); got != 2 {
		t.Fatalf("Len() = %d after eviction, want 2", got)
	}

	// B survived: its history still tags a clean request.
	d = eng.Decide(mreq(ipB, "/about", t0+3000, browserUA, 9, true), false)
	assertDecision(t, "session B survived eviction", d, nil, model.VerdictTag, 25, model.FailOpenReason)

	// A was evicted: its state is gone and the same request starts fresh.
	d = eng.Decide(mreq(ipA, "/about", t0+4000, browserUA, 9, true), false)
	assertDecision(t, "session A evicted", d, nil, model.VerdictObserve, 0, model.FailOpenReason)
	if got := eng.Len(); got != 2 {
		t.Errorf("Len() = %d at the end, want 2", got)
	}
}

func TestConcurrentDecide(t *testing.T) {
	// Run under -race: 16 goroutines, each driving its own session through
	// the decoy pipeline. Per-session decisions must stay deterministic
	// regardless of interleaving.
	eng := New(loadTestRules(t))
	const goroutines = 16

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ip := fmt.Sprintf("192.0.2.%d", 10+g)

			d1 := eng.Decide(mreq(ip, "/.env", t0, browserUA, 8, false), false)
			if d1.Verdict != model.VerdictDecoyRoute || d1.DecoyID != "env-file-staging" {
				t.Errorf("goroutine %d: request 1 = %s/%q, want decoy_route/env-file-staging", g, d1.Verdict, d1.DecoyID)
			}
			d2 := eng.Decide(mreq(ip, "/storage/logs/laravel-staging.log", t0+1000, browserUA, 8, false), false)
			if d2.Verdict != model.VerdictBan || !equalStrings([]string{"decoy_lead_follow"}, d2.Signals) {
				t.Errorf("goroutine %d: request 2 = %s/%v, want ban/[decoy_lead_follow]", g, d2.Verdict, d2.Signals)
			}
			d3 := eng.Decide(mreq(ip, "/about", t0+2000, browserUA, 9, true), false)
			if d3.Verdict != model.VerdictTag || d3.Score != 65 {
				t.Errorf("goroutine %d: request 3 = %s/%d, want tag/65", g, d3.Verdict, d3.Score)
			}
		}(g)
	}
	wg.Wait()

	if got := eng.Len(); got != goroutines {
		t.Errorf("Len() = %d after %d concurrent sessions, want %d", got, goroutines, goroutines)
	}
}

func TestNeverScoredRecordsNoState(t *testing.T) {
	eng := New(loadTestRules(t))
	ip := "203.0.113.109"

	// Verified-bot hint (case-insensitive) and the allowlist flag both
	// observe without creating a session (SIGNALS section 2, I12).
	d := eng.Decide(mreq(ip, "/.env", t0, googlebot, 8, false), false)
	assertDecision(t, "googlebot", d, nil, model.VerdictObserve, 0, model.FailOpenReason)
	d = eng.Decide(mreq(ip, "/.env", t0+1000, strings.ToUpper(googlebot), 8, false), false)
	assertDecision(t, "GOOGLEBOT uppercase", d, nil, model.VerdictObserve, 0, model.FailOpenReason)
	d = eng.Decide(mreq(ip, "/.env", t0+2000, browserUA, 8, false), true)
	assertDecision(t, "allowlisted", d, nil, model.VerdictObserve, 0, model.FailOpenReason)
	if got := eng.Len(); got != 0 {
		t.Fatalf("Len() = %d after never-scored requests, want 0", got)
	}
	if d.SessionKey != model.SessionKey(ip) {
		t.Errorf("never-scored session_key = %q, want %q", d.SessionKey, model.SessionKey(ip))
	}

	// The never-scored requests must not have inflated the request count:
	// the 4th real request stays below the no-cookie threshold of 5 (canon
	// decision 5), and the 5th fires it.
	for i := 0; i < 4; i++ {
		got := eng.Decide(mreq(ip, "/products", t0+3000+int64(i)*1000, browserUA, 8, false), false)
		assertDecision(t, fmt.Sprintf("real request %d", i+1), got, nil, model.VerdictObserve, 0, model.FailOpenReason)
	}
	if got := eng.Len(); got != 1 {
		t.Errorf("Len() = %d after one scored session, want 1", got)
	}
	got := eng.Decide(mreq(ip, "/products", t0+7000, browserUA, 8, false), false)
	assertDecision(t, "5th real request fires no_cookie_persistence", got,
		[]string{"no_cookie_persistence"}, model.VerdictTag, 15, "SIG-108")
}

func TestDotSegmentsThroughDecide(t *testing.T) {
	eng := New(loadTestRules(t))
	ip := "203.0.113.110"

	// Double slashes collapse before matching.
	d1 := eng.Decide(mreq(ip, "//.env", t0, browserUA, 8, false), false)
	assertDecision(t, "double slash", d1, []string{"scanner_path"}, model.VerdictDecoyRoute, 25, "SIG-101")

	// Leading ".." clamps at the root and is itself a dot_escape.
	d2 := eng.Decide(mreq(ip, "/../.env", t0+1000, browserUA, 8, false), false)
	assertDecision(t, "dot escape", d2, []string{"scanner_path"}, model.VerdictDecoyRoute, 50, "SIG-101")

	// "." segments drop out; the resolved path is a clean unknown.
	d3 := eng.Decide(mreq(ip, "/a/./b", t0+2000, browserUA, 9, true), false)
	assertDecision(t, "dot segment", d3, nil, model.VerdictTag, 50, model.FailOpenReason) // tag via history only
}

func TestLoadRulesErrorsNameTheFile(t *testing.T) {
	rules := loadTestRules(t) // also proves the real data loads

	if len(rules.DecoyPaths) != 6 {
		t.Errorf("catalog loaded %d decoy entries, want 6", len(rules.DecoyPaths))
	}
	if !rules.AllLeads["/storage/logs/laravel-staging.log"] || !rules.AllLeads["/admin/login/verify"] {
		t.Error("AllLeads is missing catalog leads (canon decision 4)")
	}

	if _, err := LoadRules("/nonexistent-mirage-dir", repoPath(t, "spec", "decoy-catalog", "catalog.yaml"), testProtectedRoutes); err == nil {
		t.Error("missing data dir: want error, got nil")
	} else if !strings.Contains(err.Error(), "scanner-paths.txt") {
		t.Errorf("error does not name the broken file: %v", err)
	}
	if _, err := LoadRules(repoPath(t, "data"), "/nonexistent-mirage-catalog.yaml", testProtectedRoutes); err == nil {
		t.Error("missing catalog: want error, got nil")
	} else if !strings.Contains(err.Error(), "/nonexistent-mirage-catalog.yaml") {
		t.Errorf("error does not name the broken file: %v", err)
	}
}
