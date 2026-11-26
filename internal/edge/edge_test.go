package edge

// The edge adapter suite. Every test composes a REAL service behind the
// middleware — the same wiring internal/service's own tests use (loaded
// data files, canon catalog, memory store, bounded queue, generous
// gatekeeper budgets, deterministic clocks) — so assertions measure the
// adapter, never a stub of the decision path. Requests are driven two
// ways, each pinning a different property:
//
//   - direct handler invocation with a crafted RemoteAddr: deterministic
//     client identity, no sockets — used wherever the scoring input, not
//     the wire, is the subject;
//   - a real httptest.Server with 127.0.0.1 trusted as the proxy (the
//     nginx topology, docs/deploy/nginx.md) and the scoring client named
//     in X-Forwarded-For — used wherever the WIRE is the subject (header
//     hygiene, concurrency), because Date and Content-Length exist only
//     on the wire.
//
// Client IPs stay inside the reserved documentation ranges (I14):
// 203.0.113.0/24 for scored clients, 198.51.100.0/24 for never-scored,
// 10.0.0.0/8 for the fake trusted proxy, loopback for the real server.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirage-shield/mirage/internal/config"
	"github.com/mirage-shield/mirage/internal/decoy"
	"github.com/mirage-shield/mirage/internal/detect"
	"github.com/mirage-shield/mirage/internal/enforce"
	"github.com/mirage-shield/mirage/internal/events"
	"github.com/mirage-shield/mirage/internal/model"
	"github.com/mirage-shield/mirage/internal/service"
	"github.com/mirage-shield/mirage/internal/store"
)

// Shared constants for the suite: the frozen decision time (deadline
// arithmetic always sees zero elapsed, so nothing here is wall-clock
// flaky), an ordinary browser signature, and the tooling UA the curl
// gating rule (SIGNALS section 6.1) keys on.
const (
	testToken = "edge-test-dashboard-token-0123456789abcdef"
	frozenMs  = int64(1_789_000_000_000)
	browserUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
	curlUA    = "curl/8.5.0"
)

// canonProtectedRoutes is the canon protected-route list (spec/SIGNALS.md
// section 2, I4) — the same list config.Default ships.
var canonProtectedRoutes = []string{"/wp-login.php", "/wp-admin/", "/checkout", "/cart", "/api/"}

func frozenClock() int64 { return frozenMs }

// repoPath resolves a path relative to the repository root from this test
// file's compile-time location, so the suite works no matter the working
// directory go test was launched from (the same approach as the service
// and detect suites).
func repoPath(t *testing.T, elems ...string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("edge: cannot locate test source file")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(append([]string{root}, elems...)...)
}

// loadTestRules loads the repo's data files and canon catalog once for the
// whole suite; the engine reads only in-memory state afterwards.
var testRulesOnce sync.Once

var (
	testRules    detect.Rules
	testCatalog  *decoy.Catalog
	testRulesErr error
)

func loadTestRules(t *testing.T) (detect.Rules, *decoy.Catalog) {
	t.Helper()
	testRulesOnce.Do(func() {
		testRules, testRulesErr = detect.LoadRules(
			repoPath(t, "data"),
			repoPath(t, "spec", "decoy-catalog", "catalog.yaml"),
			canonProtectedRoutes,
		)
		if testRulesErr != nil {
			return
		}
		testCatalog, testRulesErr = decoy.Load(repoPath(t, "spec", "decoy-catalog", "catalog.yaml"))
	})
	if testRulesErr != nil {
		t.Fatalf("load rules: %v", testRulesErr)
	}
	return testRules, testCatalog
}

// testConfig builds a validated config for the given mode; mutators run
// before Validate so a test can flip wiring the way a site file would.
func testConfig(t *testing.T, mode string, mutators ...func(*config.Config)) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Mode = mode
	cfg.DashboardToken = testToken
	cfg.ProtectedRoutes = canonProtectedRoutes
	for _, m := range mutators {
		m(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	return cfg
}

// harness is one fully wired edge over a real service, with the queue the
// decision events land in — tests read it back to assert what the decision
// path actually recorded (I10) without reaching into the middleware.
type harness struct {
	cfg  *config.Config
	svc  *service.Service
	edge *Edge
	q    *events.Queue
}

// newHarness wires the service in the requested mode with a deterministic
// (frozen) clock and generous gatekeeper budgets, then the edge on top —
// the mode's own defaults (protect enables enforcement) run before the
// caller's mutators, which may override them.
func newHarness(t *testing.T, mode string, svcOpts service.Options, mutators ...func(*config.Config)) *harness {
	t.Helper()
	rules, cat := loadTestRules(t)
	defaults := func(c *config.Config) {
		if mode == config.ModeProtect {
			c.Enforcement.Enabled = true
		}
	}
	cfg := testConfig(t, mode, append([]func(*config.Config){defaults}, mutators...)...)
	eng := detect.New(rules)
	st := store.NewMemoryStore()
	q := events.NewQueue(events.DefaultQueueCapacity)
	var gk *enforce.Gatekeeper
	if mode == config.ModeProtect {
		gk = enforce.NewGatekeeper(enforce.Budgets{MaxBansPerMinute: 100, MaxConcurrentBans: 100}, nil)
	}
	if svcOpts.Clock == nil {
		svcOpts.Clock = frozenClock
	}
	svc, err := service.New(cfg, eng, cat, st, q, gk, nil, svcOpts)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	e, err := New(cfg, svc, Options{Clock: frozenClock})
	if err != nil {
		t.Fatalf("new edge: %v", err)
	}
	return &harness{cfg: cfg, svc: svc, edge: e, q: q}
}

// upstreamStub is the origin behind the middleware: it records every call
// (path and the exact *http.Request it received) and answers a fixed
// marker, so "reached the origin" and "reached it unmodified" are both
// assertable.
type upstreamStub struct {
	mu     sync.Mutex
	reqs   []*http.Request
	status int
	body   string
}

func newUpstream() *upstreamStub {
	return &upstreamStub{status: http.StatusOK, body: "origin-ok"}
}

func (u *upstreamStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.reqs = append(u.reqs, r)
		u.mu.Unlock()
		w.Header().Set("X-Origin", "yes")
		w.WriteHeader(u.status)
		_, _ = io.WriteString(w, u.body)
	})
}

func (u *upstreamStub) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.reqs)
}

func (u *upstreamStub) last() *http.Request {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.reqs) == 0 {
		return nil
	}
	return u.reqs[len(u.reqs)-1]
}

// newEdgeRequest builds a request as if it arrived on the wire with ip as
// the direct peer, carrying the baseline headers a real client sends. The
// Accept pair keeps the header count at or above the sparse threshold and
// the caller sets (or deliberately omits) the User-Agent, so each test's
// score contains exactly the signals it means to fire.
func newEdgeRequest(method, target, ip string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = ip + ":54321"
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	return r
}

// lastDecision drains the harness queue and returns the newest decision,
// preserving FIFO order for tests that drive sequences.
func lastDecisions(t *testing.T, h *harness) []model.Decision {
	t.Helper()
	evs := h.q.Drain(1000)
	out := make([]model.Decision, 0, len(evs))
	for _, ev := range evs {
		if ev.Decision == nil {
			t.Fatal("edge: queued event carries no decision")
		}
		out = append(out, *ev.Decision)
	}
	return out
}

// serveBehindProxy starts the wrapped middleware on a real loopback
// listener with 127.0.0.1 trusted as the only proxy — the nginx topology
// (docs/deploy/nginx.md). The test client plays the proxy and names the
// scoring client in X-Forwarded-For, so the edge resolves identity through
// the same walk production traffic takes (I6).
func serveBehindProxy(t *testing.T, h *harness, up http.Handler) *httptest.Server {
	t.Helper()
	if !slices.Contains(h.cfg.TrustedProxyCIDRs, "127.0.0.1/32") {
		t.Fatal("edge: serveBehindProxy requires the harness to trust 127.0.0.1/32")
	}
	srv := httptest.NewServer(h.edge.Wrap(up))
	t.Cleanup(srv.Close)
	return srv
}

// proxyGet builds a request through the fake proxy for clientIP.
func proxyRequest(t *testing.T, srv *httptest.Server, method, path, clientIP string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-For", clientIP)
	return req
}

// ---------------------------------------------------------------------------
// Construction and wiring
// ---------------------------------------------------------------------------

func TestNewRejectsNilArguments(t *testing.T) {
	// Boot fails closed on wiring errors (the twin of request-time I1):
	// a nil config or service is rejected at New, never at the first
	// request.
	rules, _ := loadTestRules(t)
	cfg := testConfig(t, config.ModeLook)
	svc, err := service.New(cfg, detect.New(rules), nil, store.NewMemoryStore(), nil, nil, nil, service.Options{})
	if err != nil {
		t.Fatalf("new look service: %v", err)
	}
	if _, err := New(nil, svc, Options{}); err == nil || !strings.Contains(err.Error(), "config") {
		t.Fatalf("New(nil config) = %v, want an error naming the config", err)
	}
	if _, err := New(cfg, nil, Options{}); err == nil || !strings.Contains(err.Error(), "service") {
		t.Fatalf("New(nil service) = %v, want an error naming the service", err)
	}
	if _, err := New(cfg, svc, Options{}); err != nil {
		t.Fatalf("New with valid arguments: %v", err)
	}
}

func TestWrapNilUpstreamAnswersNotFound(t *testing.T) {
	// A nil upstream is a wiring bug the middleware cannot fail open past
	// (there is no origin to pass TO): it must answer 404, never panic.
	h := newHarness(t, config.ModeLook, service.Options{})
	hh := h.edge.Wrap(nil)
	r := newEdgeRequest("GET", "/about", "203.0.113.29")
	r.Header.Set("User-Agent", browserUA)
	r.Header.Set("Cookie", "sid=abc")
	rec := httptest.NewRecorder()
	hh.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (nil upstream must not panic)", rec.Code)
	}
}

func TestDashboardIsTheTokenGuardedServiceHandler(t *testing.T) {
	// Dashboard() hands out the service's own handler: the tokenless
	// healthz probe answers, every API route demands the token even on
	// loopback, and the token unlocks it. Deep dashboard behavior is the
	// service suite's subject; this pins the wiring.
	h := newHarness(t, config.ModeLook, service.Options{})
	dh := h.edge.Dashboard()

	rec := httptest.NewRecorder()
	dh.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("healthz = %d %q, want 200 with the fixed ok body", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	dh.ServeHTTP(rec, httptest.NewRequest("GET", "/api/status", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tokenless /api/status = %d, want 403 (token required even on loopback)", rec.Code)
	}

	r := httptest.NewRequest("GET", "/api/status", nil)
	r.Header.Set("X-Mirage-Dashboard-Token", testToken)
	rec = httptest.NewRecorder()
	dh.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"look"`) {
		t.Fatalf("authorized /api/status = %d %q, want 200 reporting look mode", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Request extraction — worker parity, field by field
// ---------------------------------------------------------------------------

func TestBuildRequestMirrorsWorkerExtraction(t *testing.T) {
	rules, _ := loadTestRules(t)

	// newEdgeWith builds an edge over a throwaway look-mode service with
	// the given trusted-proxy config; buildRequest never consults the
	// service, but New's contract requires one.
	newEdgeWith := func(t *testing.T, clock func() int64, trusted ...string) *Edge {
		t.Helper()
		cfg := testConfig(t, config.ModeLook, func(c *config.Config) { c.TrustedProxyCIDRs = trusted })
		svc, err := service.New(cfg, detect.New(rules), nil, store.NewMemoryStore(), nil, nil, nil, service.Options{})
		if err != nil {
			t.Fatalf("new service: %v", err)
		}
		e, err := New(cfg, svc, Options{Clock: clock})
		if err != nil {
			t.Fatalf("new edge: %v", err)
		}
		return e
	}

	t.Run("raw path keeps dot segments and query", func(t *testing.T) {
		// The worker's rawPathFromUrl exists so WHATWG normalization cannot
		// erase dot segments (SIGNALS section 3.2); the Go twin must keep
		// r.RequestURI's raw bytes for the same reason.
		e := newEdgeWith(t, frozenClock)
		for _, target := range []string{
			"/a/../../..?x=1",
			"/shop/../wp-config.php.bak?debug=1",
			"/about?keep=1",
			"/",
		} {
			r := httptest.NewRequest("GET", target, nil)
			r.RemoteAddr = "203.0.113.70:1111"
			if got := e.buildRequest(r).Path; got != target {
				t.Errorf("path for %q = %q, want the raw target", target, got)
			}
		}
	})

	t.Run("percent-escapes are not decoded", func(t *testing.T) {
		// r.URL.Path holds the decoded form ("/../. env" would lose the
		// double-encoding evidence); the adapter must send the wire bytes.
		e := newEdgeWith(t, frozenClock)
		r := httptest.NewRequest("GET", "/%2e%2e/.env?x=1", nil)
		r.RemoteAddr = "203.0.113.70:1112"
		if got := e.buildRequest(r).Path; got != "/%2e%2e/.env?x=1" {
			t.Fatalf("path = %q, want the undecoded %q", got, "/%2e%2e/.env?x=1")
		}
	})

	t.Run("absolute-form target reduces to its raw path", func(t *testing.T) {
		// Proxy-style absolute targets are not origin-form; the fallback
		// yields the same slice the worker's rawPathFromUrl produces.
		e := newEdgeWith(t, frozenClock)
		r := httptest.NewRequest("GET", "https://x.test/shop/../wp-config.php.bak?debug=1", nil)
		r.RemoteAddr = "203.0.113.70:1113"
		if got := e.buildRequest(r).Path; got != "/shop/../wp-config.php.bak?debug=1" {
			t.Fatalf("path = %q, want the URL's raw path+query", got)
		}
	})

	t.Run("header count includes Host and nothing twice", func(t *testing.T) {
		// SIGNALS section 1 counts ALL request headers including Host;
		// net/http promotes Host out of r.Header, so it is counted back in.
		e := newEdgeWith(t, frozenClock)
		r := httptest.NewRequest("GET", "/about", nil) // Host: example.com
		for _, h := range []string{"User-Agent", "Accept", "X-One", "X-Two"} {
			r.Header.Set(h, "v")
		}
		if got := e.buildRequest(r).HeaderCount; got != 5 {
			t.Fatalf("header count = %d, want 5 (four fields plus the promoted Host)", got)
		}
		r.Host = "" // an HTTP/1.0 request without a Host sent none
		if got := e.buildRequest(r).HeaderCount; got != 4 {
			t.Fatalf("header count without Host = %d, want 4", got)
		}
	})

	t.Run("cookie presence matches the worker's non-empty test", func(t *testing.T) {
		e := newEdgeWith(t, frozenClock)
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "203.0.113.70:1114"
		if e.buildRequest(r).HasCookie {
			t.Fatal("no Cookie header, want HasCookie false")
		}
		r.Header.Set("Cookie", "sid=abc")
		if !e.buildRequest(r).HasCookie {
			t.Fatal("Cookie: sid=abc, want HasCookie true")
		}
		r.Header.Set("Cookie", "")
		if e.buildRequest(r).HasCookie {
			t.Fatal("empty Cookie header, want HasCookie false (worker: cookie !== \"\")")
		}
	})

	t.Run("auth hint joins Authorization and the raw query", func(t *testing.T) {
		// The worker's composition: [Authorization, query] with empties
		// dropped, joined by one space; entirely absent when both are.
		e := newEdgeWith(t, frozenClock)
		r := httptest.NewRequest("GET", "/login?debug=1&token=abc", nil)
		r.RemoteAddr = "203.0.113.70:1115"
		r.Header.Set("Authorization", "Bearer xyz")
		if got := e.buildRequest(r).AuthHint; got != "Bearer xyz debug=1&token=abc" {
			t.Fatalf("auth hint = %q, want both parts joined", got)
		}
		r2 := httptest.NewRequest("GET", "/login", nil)
		r2.RemoteAddr = "203.0.113.70:1116"
		r2.Header.Set("Authorization", "Bearer xyz")
		if got := e.buildRequest(r2).AuthHint; got != "Bearer xyz" {
			t.Fatalf("auth hint = %q, want the authorization alone", got)
		}
		r3 := httptest.NewRequest("GET", "/login?debug=1", nil)
		r3.RemoteAddr = "203.0.113.70:1117"
		if got := e.buildRequest(r3).AuthHint; got != "debug=1" {
			t.Fatalf("auth hint = %q, want the query alone", got)
		}
		r4 := httptest.NewRequest("GET", "/login", nil)
		r4.RemoteAddr = "203.0.113.70:1118"
		if got := e.buildRequest(r4).AuthHint; got != "" {
			t.Fatalf("auth hint = %q, want empty (worker omits it)", got)
		}
	})

	t.Run("method, user agent and clock timestamp", func(t *testing.T) {
		e := newEdgeWith(t, func() int64 { return 42 }) // TsMs comes from the edge clock
		r := httptest.NewRequest("POST", "/api/v1/auth", nil)
		r.RemoteAddr = "203.0.113.70:1119"
		req := e.buildRequest(r)
		if req.Method != "POST" {
			t.Fatalf("method = %q, want POST", req.Method)
		}
		if req.UserAgent != "" {
			t.Fatalf("user agent = %q, want the neutral empty string", req.UserAgent)
		}
		if req.TsMs != 42 {
			t.Fatalf("ts = %d, want the injected clock's 42", req.TsMs)
		}
		r.Header.Set("User-Agent", browserUA)
		if got := e.buildRequest(r).UserAgent; got != browserUA {
			t.Fatalf("user agent = %q, want %q", got, browserUA)
		}
	})

	t.Run("client identity walks the trusted-proxy chain (I6)", func(t *testing.T) {
		cases := []struct {
			name        string
			trusted     []string
			remoteAddr  string
			xff         string
			wantIP      string
			wantTrusted bool
		}{
			// An untrusted peer's forwarding header is ignored entirely: an
			// attacker must not be able to frame an innocent address.
			{"untrusted peer ignores XFF", nil, "198.51.100.9:777", "203.0.113.7", "198.51.100.9", false},
			// The walk goes right-to-left past trusted proxies to the first
			// non-trusted hop (SIGNALS section 2).
			{"trusted peer walks to rightmost untrusted hop", []string{"10.0.0.0/8"}, "10.9.8.7:1234", "203.0.113.7, 10.0.0.2", "203.0.113.7", true},
			{"single untrusted hop", []string{"10.0.0.0/8"}, "10.9.8.7:1234", "203.0.113.7", "203.0.113.7", true},
			{"all hops trusted falls back to the peer", []string{"10.0.0.0/8"}, "10.9.8.7:1234", "10.0.0.2, 10.0.0.3", "10.9.8.7", true},
			{"no XFF from a trusted peer", []string{"10.0.0.0/8"}, "10.9.8.7:1234", "", "10.9.8.7", true},
			{"ipv6 peer", nil, "[2001:db8::1]:443", "", "2001:db8::1", false},
			// An unparseable peer stays an opaque identity — never trusted,
			// never forwarded evidence.
			{"unparseable peer is opaque", nil, "garbage", "203.0.113.7", "garbage", false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				e := newEdgeWith(t, frozenClock, tc.trusted...)
				r := httptest.NewRequest("GET", "/about", nil)
				r.RemoteAddr = tc.remoteAddr
				if tc.xff != "" {
					r.Header.Set("X-Forwarded-For", tc.xff)
				}
				req := e.buildRequest(r)
				if req.ClientIP != tc.wantIP {
					t.Errorf("client ip = %q, want %q", req.ClientIP, tc.wantIP)
				}
				if req.TrustedPeer != tc.wantTrusted {
					t.Errorf("trusted peer = %v, want %v", req.TrustedPeer, tc.wantTrusted)
				}
				if req.ForwardedFor != tc.xff {
					t.Errorf("forwarded-for = %q, want the raw header %q (informational only)", req.ForwardedFor, tc.xff)
				}
			})
		}
	})
}

// ---------------------------------------------------------------------------
// Actions through a real decision path
// ---------------------------------------------------------------------------

func TestBenignRequestPassesThroughUnmodified(t *testing.T) {
	// Protect mode with enforcement armed, and the request still passes:
	// a clean session sees nothing but the origin (I9's default posture is
	// invisible to legitimate traffic).
	h := newHarness(t, config.ModeProtect, service.Options{})
	up := newUpstream()
	hh := h.edge.Wrap(up.handler())

	r := newEdgeRequest("GET", "/about?utm=1", "203.0.113.20")
	r.Header.Set("User-Agent", browserUA)
	r.Header.Set("Cookie", "sid=abc")
	rec := httptest.NewRecorder()
	hh.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want the upstream's 200", rec.Code)
	}
	if rec.Body.String() != "origin-ok" {
		t.Fatalf("body = %q, want the upstream's body intact", rec.Body.String())
	}
	if got := rec.Header().Get("X-Origin"); got != "yes" {
		t.Fatalf("upstream header lost: X-Origin = %q", got)
	}
	if n := len(rec.Header()); n != 1 {
		t.Fatalf("response carries %d header fields, want only the upstream's own (edge added nothing)", n)
	}
	if up.count() != 1 {
		t.Fatalf("upstream called %d times, want 1", up.count())
	}
	// Unmodified means the very same *http.Request object: the edge passes
	// it through, it never clones or rewrites (the worker asserts the same
	// identity for its origin fetch).
	if got := up.last(); got != r {
		t.Fatal("upstream saw a different *http.Request: pass-through must hand over the original")
	}
}

func TestScannerPathServesDecoyFromCatalog(t *testing.T) {
	// The mission's reference decoy flow: scanner_path on a decoyable path
	// in a mode that serves decoys renders the catalog entry verbatim —
	// status, persona headers, noindex set, session-keyed body — and the
	// origin is never consulted (I3, I12; ADAPTER-PROTOCOL section 3).
	h := newHarness(t, config.ModeTripwires, service.Options{})
	up := newUpstream()
	hh := h.edge.Wrap(up.handler())

	ip := "203.0.113.21"
	r := newEdgeRequest("GET", "/.env", ip)
	r.Header.Set("User-Agent", browserUA)
	r.Header.Set("Cookie", "sid=abc")
	rec := httptest.NewRecorder()
	hh.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want the catalog entry's 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "APP_NAME=staging") {
		t.Fatalf("body does not carry the env-file-staging content: %q", body)
	}
	// The body is rendered for THIS session: the honeytoken is minted from
	// the session key, so the same client always sees the same credential
	// (DECOY-CATALOG section 4) and the follow-up ban test can replay it.
	token := decoy.MintToken(model.SessionKey(ip), "env-file-staging", "db_password")
	if !strings.Contains(body, token) {
		t.Fatalf("body does not carry the session's honeytoken %q", token)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain" {
		t.Fatalf("content type = %q, want the entry's text/plain", got)
	}
	if got := rec.Header().Get("Server"); got != "nginx/1.24.0" {
		t.Fatalf("Server = %q, want the laravel-staging persona's header", got)
	}
	if got := rec.Header().Get("X-Powered-By"); got != "PHP/8.2.12" {
		t.Fatalf("X-Powered-By = %q, want the persona's header", got)
	}
	if got := rec.Header().Get("X-Robots-Tag"); got != "noindex, nofollow, noarchive" {
		t.Fatalf("X-Robots-Tag = %q, want the noindex set (I12)", got)
	}
	if up.count() != 0 {
		t.Fatalf("upstream called %d times, want 0 (the decoy IS the answer)", up.count())
	}
	ds := lastDecisions(t, h)
	if len(ds) != 1 || ds[0].Action != model.ActionServeDecoy || ds[0].DecoyID != "env-file-staging" {
		t.Fatalf("decisions = %+v, want one serve_decoy naming env-file-staging", ds)
	}
}

func TestThrottleAnswers429WithSpecRetryAfter(t *testing.T) {
	// The exact spec threshold (SIGNALS section 5.3): scanner_path 25 plus
	// the ungated tooling_curl 15 makes 40 — and section 6.1's ungating is
	// the reason curl counts here: scanner_path fired earlier in evaluation
	// order. The answer is 429 + Retry-After 30 (the reference adapter's
	// value) and a static body.
	h := newHarness(t, config.ModeProtect, service.Options{})
	up := newUpstream()
	hh := h.edge.Wrap(up.handler())

	r := newEdgeRequest("GET", "/.env", "203.0.113.22")
	r.Header.Set("User-Agent", curlUA)
	rec := httptest.NewRecorder()
	hh.ServeHTTP(rec, r)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "30" {
		t.Fatalf("Retry-After = %q, want 30", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/plain; charset=utf-8", got)
	}
	if got := len(rec.Header()); got != 2 {
		t.Fatalf("response carries %d header fields, want exactly Content-Type and Retry-After", got)
	}
	if rec.Body.String() != "Too many requests. Please retry later." {
		t.Fatalf("body = %q, want the fixed throttle body", rec.Body.String())
	}
	if up.count() != 0 {
		t.Fatalf("upstream called %d times, want 0 (throttled here, not forwarded)", up.count())
	}

	// The decision the edge acted on, read back from the evidence trail
	// (I10): exactly the two ungated signals, 40, throttle, SIG-101.
	ds := lastDecisions(t, h)
	if len(ds) != 1 {
		t.Fatalf("decisions = %d, want 1", len(ds))
	}
	d := ds[0]
	if want := []string{"scanner_path", "tooling_curl"}; !slices.Equal(d.Signals, want) {
		t.Fatalf("signals = %v, want %v (section 6.1: scanner_path ungates tooling_curl)", d.Signals, want)
	}
	if d.RequestScore != 40 || d.Score != 40 {
		t.Fatalf("scores = request %d, cumulative %d, want 40/40 (section 5.3 threshold)", d.RequestScore, d.Score)
	}
	if d.Verdict != model.VerdictThrottle || d.Action != model.ActionThrottle {
		t.Fatalf("verdict/action = %s/%s, want throttle/throttle", d.Verdict, d.Action)
	}
	if d.ReasonCode != "SIG-101" {
		t.Fatalf("reason = %q, want SIG-101 (highest-weight signal)", d.ReasonCode)
	}

	// The negative control for the ungating rule: curl on an ordinary path
	// fires NOTHING (headers_sparse would not ungate it either — a fresh
	// session has no signal from the 1-5 set), so the request passes.
	r2 := newEdgeRequest("GET", "/about", "203.0.113.23")
	r2.Header.Set("User-Agent", curlUA)
	rec2 := httptest.NewRecorder()
	hh.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusOK || rec2.Body.String() != "origin-ok" {
		t.Fatalf("curl on an ordinary path = %d %q, want the origin's answer", rec2.Code, rec2.Body.String())
	}
	ds = lastDecisions(t, h)
	if len(ds) != 1 || len(ds[0].Signals) != 0 {
		t.Fatalf("signals = %v, want none (curl alone never throttles, section 6.1)", ds)
	}
}

func TestHoneytokenBanAnswersPlain403(t *testing.T) {
	// The golden ban flow (W4, the worker's end-to-end test): the decoy is
	// served, its honeytoken replayed as a credential, and the answer is a
	// plain generic 403 that names nothing (ADR-0001).
	h := newHarness(t, config.ModeProtect, service.Options{})
	up := newUpstream()
	hh := h.edge.Wrap(up.handler())

	ip := "203.0.113.24"

	// Request 1 arms the trip: the decoy mints this session's token.
	r1 := newEdgeRequest("GET", "/.env", ip)
	r1.Header.Set("User-Agent", browserUA)
	r1.Header.Set("Cookie", "sid=abc")
	rec1 := httptest.NewRecorder()
	hh.ServeHTTP(rec1, r1)
	if rec1.Code != http.StatusOK || !strings.Contains(rec1.Body.String(), "APP_NAME=staging") {
		t.Fatalf("decoy leg = %d, want the served env-file-staging", rec1.Code)
	}

	// Request 2 replays the leaked credential on a PROTECTED route — the
	// one verdict that survives the protected-route cap (section 5, R3).
	token := decoy.MintToken(model.SessionKey(ip), "env-file-staging", "db_password")
	r2 := newEdgeRequest("POST", "/api/v1/auth", ip)
	r2.Header.Set("User-Agent", browserUA)
	r2.Header.Set("Authorization", "Bearer "+token)
	rec2 := httptest.NewRecorder()
	hh.ServeHTTP(rec2, r2)

	if rec2.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec2.Code)
	}
	if rec2.Body.String() != "Request blocked." {
		t.Fatalf("body = %q, want the plain generic denial body", rec2.Body.String())
	}
	// Exactly one header field on the recorder: Content-Type. Content-Length
	// and Date belong to the wire (asserted in the hygiene test); anything
	// else — an X-Mirage-Ban-Ttl, a cache directive — would be a marker.
	if got := len(rec2.Header()); got != 1 {
		t.Fatalf("response carries %d header fields (%v), want only Content-Type", got, rec2.Header())
	}
	if got := rec2.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/plain; charset=utf-8", got)
	}
	if up.count() != 0 {
		t.Fatalf("upstream called %d times, want 0 across the whole flow", up.count())
	}

	// The recorded evidence: honeytoken_use, ban, SIG-104, the fixed TTL.
	ds := lastDecisions(t, h)
	if len(ds) != 2 {
		t.Fatalf("decisions = %d, want 2 (decoy then ban)", len(ds))
	}
	d := ds[1]
	if d.Verdict != model.VerdictBan || d.Action != model.ActionBan || d.ReasonCode != "SIG-104" {
		t.Fatalf("decision = %s/%s reason %s, want ban/ban SIG-104", d.Verdict, d.Action, d.ReasonCode)
	}
	if !slices.Contains(d.Signals, "honeytoken_use") {
		t.Fatalf("signals = %v, want honeytoken_use among them", d.Signals)
	}
	if d.BanTTLms == nil || *d.BanTTLms != 1_800_000 {
		t.Fatalf("ban ttl = %v, want the fixed 1800000 (section 5)", d.BanTTLms)
	}
}

// ---------------------------------------------------------------------------
// Fail-open (I1): both layers, exercised separately
// ---------------------------------------------------------------------------

// scriptClock returns scripted values in order, repeating the last one, so
// the service's deadline arithmetic can jump past the budget at an exact
// point of Decide without any real waiting (the same tool the service
// suite uses).
type scriptClock struct {
	mu   sync.Mutex
	vals []int64
	idx  int
}

func (c *scriptClock) now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.vals[len(c.vals)-1]
	if c.idx < len(c.vals) {
		v = c.vals[c.idx]
	}
	c.idx++
	return v
}

func TestServiceFailOpenFlowsThroughAsPass(t *testing.T) {
	// Layer one: the Service itself fails open on its own clock — the edge
	// must simply forward that as a pass, with no event emitted (SIG-000
	// is reserved and never recorded, ADAPTER-PROTOCOL section 3).
	rules, cat := loadTestRules(t)
	cfg := testConfig(t, config.ModeTripwires)
	q := events.NewQueue(events.DefaultQueueCapacity)
	clock := &scriptClock{vals: []int64{frozenMs, frozenMs + service.DefaultDecideBudgetMs + 1}}
	svc, err := service.New(cfg, detect.New(rules), cat, store.NewMemoryStore(), q, nil, nil,
		service.Options{Clock: clock.now})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	e, err := New(cfg, svc, Options{Clock: frozenClock})
	if err != nil {
		t.Fatalf("new edge: %v", err)
	}
	up := newUpstream()
	hh := e.Wrap(up.handler())

	// A request whose decision would serve the decoy: the overrun
	// discards it and the origin answers instead.
	r := newEdgeRequest("GET", "/.env", "203.0.113.40")
	r.Header.Set("User-Agent", browserUA)
	r.Header.Set("Cookie", "sid=abc")
	rec := httptest.NewRecorder()
	hh.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK || rec.Body.String() != "origin-ok" {
		t.Fatalf("answer = %d %q, want the origin's (decision discarded on overrun)", rec.Code, rec.Body.String())
	}
	if up.count() != 1 {
		t.Fatalf("upstream called %d times, want 1", up.count())
	}
	if got := up.last().URL.Path; got != "/.env" {
		t.Fatalf("origin saw path %q, want the original /.env", got)
	}
	if got := q.Len(); got != 0 {
		t.Fatalf("queue holds %d events after a fail-open decision, want 0", got)
	}
}

// slowStore wraps a memory store whose UpsertBanRecord — the one
// synchronous store write on the decision path — sleeps past the edge's
// wall-clock budget, while the service's frozen clock reports zero
// elapsed. This is exactly the case the edge's defensive deadline exists
// for: the service's own check cannot see the stall.
type slowStore struct {
	store.Store
	delay time.Duration
}

func (s *slowStore) UpsertBanRecord(ctx context.Context, b store.BanRecord) error {
	time.Sleep(s.delay)
	return s.Store.UpsertBanRecord(ctx, b)
}

func TestEdgeWallClockOverrunFailsOpenDespiteFrozenServiceClock(t *testing.T) {
	// Layer two: the edge's own wall-time guard. The service decides "ban"
	// with a frozen clock (its checks see zero elapsed) but takes 50 ms of
	// real time on the ban's store write; the edge measures the wall, logs
	// one line, and passes the request to the origin (I1). The ban
	// bookkeeping still persisted — the decision was discarded, not the
	// ban — so the next request from the address renews and is answered.
	rules, cat := loadTestRules(t)
	cfg := testConfig(t, config.ModeProtect, func(c *config.Config) { c.Enforcement.Enabled = true })
	q := events.NewQueue(events.DefaultQueueCapacity)
	gk := enforce.NewGatekeeper(enforce.Budgets{MaxBansPerMinute: 100, MaxConcurrentBans: 100}, nil)
	svc, err := service.New(cfg, detect.New(rules), cat, &slowStore{Store: store.NewMemoryStore(), delay: 50 * time.Millisecond},
		q, gk, nil, service.Options{Clock: frozenClock})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	e, err := New(cfg, svc, Options{Clock: frozenClock})
	if err != nil {
		t.Fatalf("new edge: %v", err)
	}
	up := newUpstream()
	hh := e.Wrap(up.handler())

	ip := "203.0.113.41"

	// Leg 1 — the decoy: no store write on this path, well inside the
	// budget, the decoy serves normally.
	r1 := newEdgeRequest("GET", "/.env", ip)
	r1.Header.Set("User-Agent", browserUA)
	r1.Header.Set("Cookie", "sid=abc")
	rec1 := httptest.NewRecorder()
	hh.ServeHTTP(rec1, r1)
	if rec1.Code != http.StatusOK || !strings.Contains(rec1.Body.String(), "APP_NAME=staging") {
		t.Fatalf("decoy leg = %d %q, want the served decoy inside the budget", rec1.Code, rec1.Body.String())
	}

	// Leg 2 — the honeytoken ban: Decide returns "ban" 50 ms late in wall
	// time. The edge discards it and the origin answers.
	token := decoy.MintToken(model.SessionKey(ip), "env-file-staging", "db_password")
	r2 := newEdgeRequest("POST", "/api/v1/auth", ip)
	r2.Header.Set("User-Agent", browserUA)
	r2.Header.Set("Authorization", "Bearer "+token)
	rec2 := httptest.NewRecorder()
	hh.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusOK || rec2.Body.String() != "origin-ok" {
		t.Fatalf("answer = %d %q, want the origin's (edge failed the late decision open)", rec2.Code, rec2.Body.String())
	}
	if up.count() != 1 {
		t.Fatalf("upstream called %d times, want 1 (the throttled ban reached the origin)", up.count())
	}

	// Sanity: the budget does not false-positive — an ordinary request
	// through the same edge still decides fast and passes.
	r3 := newEdgeRequest("GET", "/about", "203.0.113.42")
	r3.Header.Set("User-Agent", browserUA)
	r3.Header.Set("Cookie", "sid=abc")
	rec3 := httptest.NewRecorder()
	hh.ServeHTTP(rec3, r3)
	if rec3.Code != http.StatusOK || rec3.Body.String() != "origin-ok" {
		t.Fatalf("clean request = %d %q, want the origin's", rec3.Code, rec3.Body.String())
	}

	// The discarded decision's ban bookkeeping persisted at the
	// gatekeeper: renewal answers the next request with the ban action —
	// and that path writes no store row, so it fits the budget and is
	// applied as the plain 403.
	r4 := newEdgeRequest("GET", "/about", ip)
	r4.Header.Set("User-Agent", browserUA)
	r4.Header.Set("Cookie", "sid=abc")
	rec4 := httptest.NewRecorder()
	hh.ServeHTTP(rec4, r4)
	if rec4.Code != http.StatusForbidden || rec4.Body.String() != "Request blocked." {
		t.Fatalf("renewal = %d %q, want the plain 403 (the ban outlived the discarded decision)", rec4.Code, rec4.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Never-scored addresses (I6, I15)
// ---------------------------------------------------------------------------

func TestNeverScoredIPPassesRegardlessOfPath(t *testing.T) {
	// Owner ranges are never scored: even the throttle-grade probe from
	// inside one passes untouched, in protect mode with enforcement armed.
	// The control case proves the pass comes from the never-scored rule,
	// not from a broken throttle path.
	h := newHarness(t, config.ModeProtect, service.Options{}, func(c *config.Config) {
		c.OwnerIPCIDRs = []string{"198.51.100.0/24"}
	})
	up := newUpstream()
	hh := h.edge.Wrap(up.handler())

	for _, tc := range []struct{ name, remoteAddr string }{
		{"owner range", "198.51.100.5:4444"},
		{"loopback", "127.0.0.1:5555"},
	} {
		r := httptest.NewRequest("GET", "/.env", nil)
		r.RemoteAddr = tc.remoteAddr
		r.Header.Set("Accept", "text/html")
		r.Header.Set("Accept-Language", "en")
		r.Header.Set("User-Agent", curlUA)
		rec := httptest.NewRecorder()
		hh.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK || rec.Body.String() != "origin-ok" {
			t.Errorf("%s: status = %d %q, want the origin's (never scored, SIGNALS section 2)", tc.name, rec.Code, rec.Body.String())
		}
	}
	if up.count() != 2 {
		t.Fatalf("upstream called %d times, want 2", up.count())
	}

	// Control: the same request shape from a scored address throttles.
	r := newEdgeRequest("GET", "/.env", "203.0.113.50")
	r.Header.Set("User-Agent", curlUA)
	rec := httptest.NewRecorder()
	hh.ServeHTTP(rec, r)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("control status = %d, want 429 (the pass above is the never-scored rule at work)", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// The wire: header hygiene (ADR-0001) and concurrency
// ---------------------------------------------------------------------------

// assertNoMirageMarker checks both marker surfaces ADR-0001 forbids: no
// response header key names Mirage, and no body bytes do.
func assertNoMirageMarker(t *testing.T, resp *http.Response, body string) {
	t.Helper()
	for key := range resp.Header {
		if strings.HasPrefix(key, "X-Mirage") {
			t.Errorf("response header %q identifies Mirage (ADR-0001)", key)
		}
	}
	if strings.Contains(strings.ToLower(body), "mirage") {
		t.Errorf("response body carries a Mirage marker: %q", body)
	}
}

func TestResponseHeaderHygienePerAction(t *testing.T) {
	// On the wire (a real server, so Date and Content-Length exist), every
	// action's response carries only what its contract requires: the pass
	// and decoy answers keep their own headers, throttle adds exactly
	// Retry-After, ban adds nothing at all.
	h := newHarness(t, config.ModeProtect, service.Options{}, func(c *config.Config) {
		c.TrustedProxyCIDRs = []string{"127.0.0.1/32"}
	})
	up := newUpstream()
	srv := serveBehindProxy(t, h, up.handler())
	client := srv.Client()

	// assertExactHeaders fails on any key outside want.
	assertExactHeaders := func(t *testing.T, resp *http.Response, want ...string) {
		t.Helper()
		allowed := map[string]bool{
			"Content-Type":   true,
			"Content-Length": true,
			"Date":           true,
		}
		for _, k := range want {
			allowed[k] = true
		}
		for key := range resp.Header {
			if !allowed[key] {
				t.Errorf("unexpected header %q (allowed: %v)", key, want)
			}
		}
	}

	do := func(method, path, ip, ua string, hdrs map[string]string) (*http.Response, string) {
		t.Helper()
		req := proxyRequest(t, srv, method, path, ip)
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %s %s: %v", method, path, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		return resp, string(body)
	}

	t.Run("pass keeps the origin's answer", func(t *testing.T) {
		resp, body := do("GET", "/about", "203.0.113.90", browserUA, map[string]string{"Cookie": "sid=1"})
		if resp.StatusCode != http.StatusOK || body != "origin-ok" {
			t.Fatalf("answer = %d %q, want the origin's", resp.StatusCode, body)
		}
		assertExactHeaders(t, resp, "X-Origin")
		assertNoMirageMarker(t, resp, body)
	})

	t.Run("decoy serves the catalog's headers verbatim", func(t *testing.T) {
		resp, body := do("GET", "/.env", "203.0.113.91", browserUA, nil)
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, "APP_NAME=staging") {
			t.Fatalf("answer = %d, want the served decoy", resp.StatusCode)
		}
		// The persona headers and the noindex set are the entry's own; the
		// renderer guarantees X-Robots-Tag (I12).
		assertExactHeaders(t, resp, "Server", "X-Powered-By", "X-Robots-Tag")
		if got := resp.Header.Get("X-Robots-Tag"); got != "noindex, nofollow, noarchive" {
			t.Fatalf("X-Robots-Tag = %q, want the noindex set", got)
		}
		assertNoMirageMarker(t, resp, body)
	})

	t.Run("throttle adds exactly Retry-After", func(t *testing.T) {
		resp, body := do("GET", "/.env", "203.0.113.92", curlUA, nil)
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429", resp.StatusCode)
		}
		if got := resp.Header.Get("Retry-After"); got != "30" {
			t.Fatalf("Retry-After = %q, want 30", got)
		}
		if body != "Too many requests. Please retry later." {
			t.Fatalf("body = %q, want the fixed throttle body", body)
		}
		assertExactHeaders(t, resp, "Retry-After")
		assertNoMirageMarker(t, resp, body)
	})

	t.Run("ban adds nothing beyond the body's type", func(t *testing.T) {
		ip := "203.0.113.93"
		resp, body := do("GET", "/.env", ip, browserUA, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("decoy leg = %d, want 200", resp.StatusCode)
		}
		token := decoy.MintToken(model.SessionKey(ip), "env-file-staging", "db_password")
		resp, body = do("POST", "/api/v1/auth", ip, browserUA, map[string]string{"Authorization": "Bearer " + token})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		if body != "Request blocked." {
			t.Fatalf("body = %q, want the plain generic denial", body)
		}
		assertExactHeaders(t, resp)
		assertNoMirageMarker(t, resp, body)
	})
}

func TestConcurrentRequestsThroughOneEdge(t *testing.T) {
	// One Edge, many handler goroutines, one shared origin: the adapter is
	// stateless by design (I3 — every lock belongs to the Service), so the
	// race detector must find nothing. Half the requests are decoy routes
	// (served from the catalog, never forwarded), half ordinary pages.
	h := newHarness(t, config.ModeProtect, service.Options{}, func(c *config.Config) {
		c.TrustedProxyCIDRs = []string{"127.0.0.1/32"}
	})
	up := newUpstream()
	srv := serveBehindProxy(t, h, up.handler())
	client := srv.Client()

	const workers = 8
	const perWorker = 24 // even: half ordinary pages, half decoy routes
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		ip := fmt.Sprintf("203.0.113.%d", 100+w)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				path := "/about"
				if i%2 == 1 {
					path = "/.env"
				}
				req := proxyRequest(t, srv, "GET", path, ip)
				req.Header.Set("User-Agent", browserUA)
				resp, err := client.Do(req)
				if err != nil {
					t.Errorf("request %s: %v", path, err)
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("%s answered %d, want 200 (decoy or origin, never an error)", path, resp.StatusCode)
				}
			}
		}()
	}
	wg.Wait()

	// Half the requests were decoy routes served by Mirage; the origin saw
	// only the ordinary pages.
	if want := workers * perWorker / 2; up.count() != want {
		t.Fatalf("origin saw %d requests, want %d (decoy routes never reach it)", up.count(), want)
	}
}

// ---------------------------------------------------------------------------
// Modes (I9)
// ---------------------------------------------------------------------------

func TestEdgeServesEveryMode(t *testing.T) {
	// Look: no decoys are served and nothing is enforced — a request that
	// would throttle passes, and the recorded verdict is capped at tag
	// with its evidence intact.
	hLook := newHarness(t, config.ModeLook, service.Options{})
	up := newUpstream()
	hh := hLook.edge.Wrap(up.handler())

	r := newEdgeRequest("GET", "/.env", "203.0.113.80")
	r.Header.Set("User-Agent", curlUA)
	rec := httptest.NewRecorder()
	hh.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || rec.Body.String() != "origin-ok" {
		t.Fatalf("look mode answer = %d %q, want the origin's (observe only)", rec.Code, rec.Body.String())
	}
	if up.count() != 1 {
		t.Fatalf("origin saw %d requests in look mode, want 1", up.count())
	}
	ds := lastDecisions(t, hLook)
	if len(ds) != 1 || ds[0].Verdict != model.VerdictTag || ds[0].Action != model.ActionPass || ds[0].Score != 40 {
		t.Fatalf("look mode decision = %+v, want tag/pass with the 40 recorded", ds)
	}

	// Tripwires: decoys serve (they ARE the tripwires) while enforcement
	// verdicts pass.
	hTrip := newHarness(t, config.ModeTripwires, service.Options{})
	upTrip := newUpstream()
	hhTrip := hTrip.edge.Wrap(upTrip.handler())

	r2 := newEdgeRequest("GET", "/.env", "203.0.113.81")
	r2.Header.Set("User-Agent", browserUA)
	r2.Header.Set("Cookie", "sid=abc")
	rec2 := httptest.NewRecorder()
	hhTrip.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusOK || !strings.Contains(rec2.Body.String(), "APP_NAME=staging") {
		t.Fatalf("tripwires decoy = %d, want the served decoy", rec2.Code)
	}
	r3 := newEdgeRequest("GET", "/.env", "203.0.113.82")
	r3.Header.Set("User-Agent", curlUA)
	rec3 := httptest.NewRecorder()
	hhTrip.ServeHTTP(rec3, r3)
	if rec3.Code != http.StatusOK || rec3.Body.String() != "origin-ok" {
		t.Fatalf("tripwires throttle-grade request = %d %q, want the origin's (recorded, not enforced)", rec3.Code, rec3.Body.String())
	}

	// Protect with the opt-in: the same request answers 429.
	hProt := newHarness(t, config.ModeProtect, service.Options{})
	upProt := newUpstream()
	hhProt := hProt.edge.Wrap(upProt.handler())
	r4 := newEdgeRequest("GET", "/.env", "203.0.113.83")
	r4.Header.Set("User-Agent", curlUA)
	rec4 := httptest.NewRecorder()
	hhProt.ServeHTTP(rec4, r4)
	if rec4.Code != http.StatusTooManyRequests {
		t.Fatalf("protect answer = %d, want 429 (enforcement armed)", rec4.Code)
	}
}

// ---------------------------------------------------------------------------
// Unit edges of the response writers
// ---------------------------------------------------------------------------

func TestWriteDecoySkipsMalformedHeaderLine(t *testing.T) {
	// Catalog Load guarantees "Name: value" shape; a hand-built catalog
	// that violates it must cost the one header line, never the response
	// (I1's spirit: a decoy must always serve).
	rec := httptest.NewRecorder()
	writeDecoy(rec, decoy.Rendered{
		Status:      200,
		ContentType: "text/plain",
		Headers:     []string{"Server: nginx/1.24.0", "badline-without-a-colon", "X-Robots-Tag: noindex"},
		Body:        []byte("hi"),
	})
	if rec.Code != 200 || rec.Body.String() != "hi" {
		t.Fatalf("answer = %d %q, want the rendered decoy despite the bad line", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Server"); got != "nginx/1.24.0" {
		t.Fatalf("Server = %q, want the well-formed headers kept", got)
	}
	if got := rec.Header().Get("X-Robots-Tag"); got != "noindex" {
		t.Fatalf("X-Robots-Tag = %q, want the noindex header kept", got)
	}
}
