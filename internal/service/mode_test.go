package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mirage-shield/mirage/internal/config"
	"github.com/mirage-shield/mirage/internal/connectors"
	"github.com/mirage-shield/mirage/internal/decoy"
	"github.com/mirage-shield/mirage/internal/detect"
	"github.com/mirage-shield/mirage/internal/enforce"
	"github.com/mirage-shield/mirage/internal/events"
	"github.com/mirage-shield/mirage/internal/model"
	"github.com/mirage-shield/mirage/internal/store"
)

// Shared test plumbing for the service suite.

// testToken is the dashboard token every test config carries. The
// dashboard tests assert it never appears in any response body.
const testToken = "test-dashboard-token-0123456789abcdef"

// frozenMs is the frozen decision time of every clock in the suite that
// does not need to move: deadline arithmetic always sees zero elapsed.
const frozenMs = int64(1_789_000_000_000)

// browserUA is an ordinary browser signature: full headers, no signals.
const browserUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

// canonProtectedRoutes is the canon protected-route list (spec/SIGNALS.md
// section 2, I4) — the same list config.Default ships.
var canonProtectedRoutes = []string{"/wp-login.php", "/wp-admin/", "/checkout", "/cart", "/api/"}

// testConfig builds a validated config for the given mode. mutators run
// before Validate, so a test can flip enforcement blocks the way a site
// file would.
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

// testRulesOnce loads the repo's data files and canon catalog once for the
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

// testHarness is one fully wired service in the requested mode, with the
// pieces the assertions need to reach.
type testHarness struct {
	svc *Service
	st  *store.MemoryStore
	q   *events.Queue
	gk  *enforce.Gatekeeper
	eng *detect.Engine
}

// newHarness builds a service in the given mode with a deterministic
// (frozen) clock, fresh engine session state and generous gatekeeper
// budgets, so assertions measure the mode wiring, not the budgets. The
// caller's mutators run AFTER the mode's own defaults (protect enables
// enforcement), so a test can override them.
func newHarness(t *testing.T, mode string, cs []connectors.Connector, mutators ...func(*config.Config)) *testHarness {
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
	gk := enforce.NewGatekeeper(enforce.Budgets{MaxBansPerMinute: 100, MaxConcurrentBans: 100}, nil)
	svc, err := New(cfg, eng, cat, st, q, gk, cs, Options{Clock: func() int64 { return frozenMs }})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return &testHarness{svc: svc, st: st, q: q, gk: gk, eng: eng}
}

// banGradeSequence returns the three-request attack ladder and the minted
// honeytoken its first decision arms:
//
//	req1 GET  /.env          browser UA   -> scanner_path 25  -> decoy_route
//	req2 GET  /.env          sqlmap UA    -> 25 + 15 = 40    -> throttle
//	req3 POST /api/v1/auth   bearer token -> honeytoken 50   -> ban (I4 cap survives, R3)
func banGradeSequence(ip string, ts int64) []model.Request {
	token := decoy.MintToken(model.SessionKey(ip), "env-file-staging", "db_password")
	return []model.Request{
		{Method: "GET", Path: "/.env", ClientIP: ip, UserAgent: browserUA, HeaderCount: 8, TsMs: ts},
		{Method: "GET", Path: "/.env", ClientIP: ip, UserAgent: "sqlmap/1.8", HeaderCount: 8, TsMs: ts + 1000},
		{Method: "POST", Path: "/api/v1/auth", ClientIP: ip, UserAgent: browserUA, HeaderCount: 8, AuthHint: "Bearer " + token, TsMs: ts + 2000},
	}
}

// cleanRequest is an ordinary browsing request the engine scores as
// observe on a fresh session (cumulative history alone may tag it).
func cleanRequest(ip string, ts int64) model.Request {
	return model.Request{Method: "GET", Path: "/about", ClientIP: ip, UserAgent: browserUA, HeaderCount: 9, HasCookie: true, TsMs: ts}
}

// fakeConnector records every enforcement call. err, when non-nil, is the
// fixed error Apply returns — set before the service is built, never
// mutated afterwards, so the fan-out goroutine races nothing. appliedC
// signals each Apply without blocking the fan-out goroutine; tests wait
// on it (never on a sleep) to synchronize with the asynchronous call.
type fakeConnector struct {
	err       error
	appliedC  chan struct{}
	mu        sync.Mutex
	applied   []connectors.Ban
	revoked   []connectors.Ban
	reconcile []connectors.Ban
	health    int
}

func newFakeConnector(err error) *fakeConnector {
	return &fakeConnector{err: err, appliedC: make(chan struct{}, 64)}
}

func (f *fakeConnector) Name() string { return "fake" }

func (f *fakeConnector) Apply(_ context.Context, b connectors.Ban) error {
	f.mu.Lock()
	f.applied = append(f.applied, b)
	f.mu.Unlock()
	select {
	case f.appliedC <- struct{}{}:
	default:
	}
	return f.err
}

func (f *fakeConnector) Revoke(_ context.Context, b connectors.Ban) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, b)
	return nil
}

func (f *fakeConnector) Reconcile(_ context.Context, active []connectors.Ban, _ int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reconcile = append([]connectors.Ban(nil), active...)
	return 0, nil
}

func (f *fakeConnector) HealthCheck(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.health++
	return nil
}

func (f *fakeConnector) appliedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applied)
}

func (f *fakeConnector) appliedAt(i int) connectors.Ban {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied[i]
}

// waitApplied blocks until Apply has been called n times, or fails the
// test: synchronization is the channel, never a sleep.
func (f *fakeConnector) waitApplied(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-f.appliedC:
		case <-time.After(5 * time.Second):
			t.Fatalf("connector Apply called %d times, want at least %d", f.appliedCount(), n)
		}
	}
}

// adjustableClock is a frozen clock the test can move between decisions
// (never mid-decision): a renewal's remaining TTL becomes observable
// without any real-time waiting.
type adjustableClock struct {
	mu  sync.Mutex
	now int64
}

func (c *adjustableClock) get() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *adjustableClock) set(v int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = v
}

// runSequence decides every request in order and returns the decisions.
func runSequence(t *testing.T, svc *Service, reqs []model.Request) []model.Decision {
	t.Helper()
	out := make([]model.Decision, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, svc.Decide(r))
	}
	return out
}

// The mode gating contract (I9): one ban-grade sequence, three postures.

func TestModeLookCapsVerdictAtTagAndPasses(t *testing.T) {
	// Look mode observes only: the verdict never rises above tag, the
	// action always passes, no decoy is named and nothing is enforced.
	fc := newFakeConnector(nil)
	h := newHarness(t, config.ModeLook, []connectors.Connector{fc})
	ds := runSequence(t, h.svc, banGradeSequence("203.0.113.30", frozenMs))

	for i, want := range []struct {
		verdict string
		reason  string
		score   int
	}{
		{model.VerdictTag, "SIG-101", 25},  // decoy_route capped
		{model.VerdictTag, "SIG-101", 65},  // throttle capped
		{model.VerdictTag, "SIG-104", 115}, // ban capped
	} {
		if ds[i].Verdict != want.verdict {
			t.Errorf("request %d verdict = %q, want %q (capped)", i+1, ds[i].Verdict, want.verdict)
		}
		if ds[i].Action != model.ActionPass {
			t.Errorf("request %d action = %q, want pass in look mode", i+1, ds[i].Action)
		}
		if ds[i].ReasonCode != want.reason {
			t.Errorf("request %d reason = %q, want %q (evidence survives the cap, I10)", i+1, ds[i].ReasonCode, want.reason)
		}
		if ds[i].Score != want.score {
			t.Errorf("request %d score = %d, want %d (recorded, not acted on)", i+1, ds[i].Score, want.score)
		}
		if ds[i].DecoyID != "" {
			t.Errorf("request %d decoy id = %q, want empty (nothing will be served)", i+1, ds[i].DecoyID)
		}
		if ds[i].BanTTLms != nil {
			t.Errorf("request %d ban ttl = %d, want none (nothing will be enforced)", i+1, *ds[i].BanTTLms)
		}
	}
	if n := fc.appliedCount(); n != 0 {
		t.Fatalf("connector Apply called %d times in look mode, want 0", n)
	}
	if _, ok := h.gk.IsBanned("203.0.113.30", frozenMs); ok {
		t.Fatal("look mode recorded a gatekeeper ban, want none")
	}
}

func TestModeTripwiresServesDecoysButPassesEnforcement(t *testing.T) {
	// Tripwires mode baits and records: decoy_route still serves (the
	// decoys are the tripwires), while throttle and ban verdicts stay
	// recorded but their actions pass.
	fc := newFakeConnector(nil)
	h := newHarness(t, config.ModeTripwires, []connectors.Connector{fc})
	ds := runSequence(t, h.svc, banGradeSequence("203.0.113.31", frozenMs))

	if ds[0].Verdict != model.VerdictDecoyRoute || ds[0].Action != model.ActionServeDecoy {
		t.Fatalf("request 1 = %s/%s, want decoy_route/serve_decoy", ds[0].Verdict, ds[0].Action)
	}
	if ds[0].DecoyID != "env-file-staging" {
		t.Fatalf("request 1 decoy id = %q, want env-file-staging", ds[0].DecoyID)
	}
	if ds[1].Verdict != model.VerdictThrottle || ds[1].Action != model.ActionPass {
		t.Fatalf("request 2 = %s/%s, want throttle/pass (recorded, not enforced)", ds[1].Verdict, ds[1].Action)
	}
	if ds[2].Verdict != model.VerdictBan || ds[2].Action != model.ActionPass {
		t.Fatalf("request 3 = %s/%s, want ban/pass (recorded, not enforced)", ds[2].Verdict, ds[2].Action)
	}
	if ds[2].BanTTLms == nil || *ds[2].BanTTLms != 1_800_000 {
		t.Fatalf("request 3 ban ttl = %v, want the recorded 1800000 (verdict parameters survive)", ds[2].BanTTLms)
	}
	if n := fc.appliedCount(); n != 0 {
		t.Fatalf("connector Apply called %d times in tripwires mode, want 0", n)
	}
	if _, ok := h.gk.IsBanned("203.0.113.31", frozenMs); ok {
		t.Fatal("tripwires mode recorded a gatekeeper ban, want none")
	}
	// The decoy the decision named renders: a tripwire must be servable.
	rendered, err := h.svc.ServeDecoy(ds[0])
	if err != nil {
		t.Fatalf("serve decoy: %v", err)
	}
	if rendered.DecoyID != "env-file-staging" || rendered.Status != 200 || len(rendered.Body) == 0 {
		t.Fatalf("rendered decoy = %+v, want the env-file-staging body", rendered)
	}
}

func TestModeProtectEnforcesThroughGatekeeper(t *testing.T) {
	// Protect mode with the opt-in: actions follow the verdicts, and the
	// ban goes through the gatekeeper to the store and the connectors.
	fc := newFakeConnector(nil)
	h := newHarness(t, config.ModeProtect, []connectors.Connector{fc})
	ip := "203.0.113.32"
	ds := runSequence(t, h.svc, banGradeSequence(ip, frozenMs))

	if ds[0].Action != model.ActionServeDecoy {
		t.Fatalf("request 1 action = %q, want serve_decoy", ds[0].Action)
	}
	if ds[1].Action != model.ActionThrottle {
		t.Fatalf("request 2 action = %q, want throttle (adapter-local, no gatekeeper)", ds[1].Action)
	}
	if ds[2].Verdict != model.VerdictBan || ds[2].Action != model.ActionBan {
		t.Fatalf("request 3 = %s/%s, want ban/ban (gatekeeper allows)", ds[2].Verdict, ds[2].Action)
	}
	if ds[2].BanTTLms == nil || *ds[2].BanTTLms != 1_800_000 {
		t.Fatalf("request 3 ban ttl = %v, want 1800000", ds[2].BanTTLms)
	}

	// The gatekeeper holds the ban until its expiry.
	if exp, ok := h.gk.IsBanned(ip, frozenMs+1_799_999); !ok || exp != frozenMs+1_800_000 {
		t.Fatalf("gatekeeper ban = (%d, %v), want (%d, true)", exp, ok, frozenMs+1_800_000)
	}
	// The store holds the durable record with the bounded context note.
	records, err := h.st.BanRecords(context.Background(), frozenMs, 10)
	if err != nil {
		t.Fatalf("read ban records: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("stored %d ban records, want 1", len(records))
	}
	rec := records[0]
	wantNote := "verdict=ban score=115 session=" + model.SessionKey(ip)
	if rec.IP != ip || rec.Reason != "SIG-104" || !rec.Active ||
		rec.CreatedAtMs != frozenMs || rec.ExpiresAtMs != frozenMs+1_800_000 || rec.Note != wantNote {
		t.Fatalf("stored record = %+v, want ip=%s reason=SIG-104 active with note %q", rec, ip, wantNote)
	}
	// Exactly one asynchronous Apply per enforced ban — never for the
	// serve_decoy or throttle decisions before it (I5).
	fc.waitApplied(t, 1)
	if n := fc.appliedCount(); n != 1 {
		t.Fatalf("connector Apply called %d times, want exactly 1", n)
	}
	applied := fc.appliedAt(0)
	if applied.IP != ip || applied.Reason != "SIG-104" || applied.Note != wantNote ||
		applied.CreatedAtMs != frozenMs || applied.ExpiresAtMs != frozenMs+1_800_000 {
		t.Fatalf("connector saw %+v, want the applied SIG-104 ban for %s", applied, ip)
	}
}

func TestModeProtectRenewsActiveBanWithoutRescoring(t *testing.T) {
	// The renewal path (I5): after a protect-mode ban, the next request
	// from the address answers with the original reason and the remaining
	// TTL, without the engine rescoring it — a banned address must not
	// earn its way out with clean-looking requests.
	fc := newFakeConnector(nil)
	h := newHarness(t, config.ModeProtect, []connectors.Connector{fc})
	ip := "203.0.113.33"
	runSequence(t, h.svc, banGradeSequence(ip, frozenMs))
	fc.waitApplied(t, 1)

	d := h.svc.Decide(cleanRequest(ip, frozenMs+3000))
	if d.Verdict != model.VerdictBan || d.Action != model.ActionBan {
		t.Fatalf("renewal = %s/%s, want ban/ban", d.Verdict, d.Action)
	}
	if d.ReasonCode != "SIG-104" {
		t.Fatalf("renewal reason = %q, want the original SIG-104, not a rescore", d.ReasonCode)
	}
	if d.RequestScore != 0 || d.Score != 0 {
		t.Fatalf("renewal scores = request %d, cumulative %d, want 0/0", d.RequestScore, d.Score)
	}
	if len(d.Signals) != 0 {
		t.Fatalf("renewal signals = %v, want empty", d.Signals)
	}
	if d.BanTTLms == nil || *d.BanTTLms != 1_800_000 {
		t.Fatalf("renewal ttl = %v, want the remaining %d (the frozen clock has not moved)", d.BanTTLms, 1_800_000)
	}
	if d.SessionKey != model.SessionKey(ip) {
		t.Fatalf("renewal session key = %q, want %q", d.SessionKey, model.SessionKey(ip))
	}
	// Renewal re-emits the decision as an event, like every decision.
	if got := h.q.Len(); got != 4 {
		t.Fatalf("queue holds %d events after 3 decisions and a renewal, want 4", got)
	}
	// Renewal fans out to nothing: the ban already exists at the provider.
	if n := fc.appliedCount(); n != 1 {
		t.Fatalf("connector Apply called %d times after renewal, want still 1", n)
	}
}

func TestModeProtectRenewalTTLShrinksWithClock(t *testing.T) {
	// The remaining TTL is measured, not parroted: as the clock moves the
	// renewal answers with less time left each time.
	fc := newFakeConnector(nil)
	rules, cat := loadTestRules(t)
	cfg := testConfig(t, config.ModeProtect, func(c *config.Config) { c.Enforcement.Enabled = true })
	clock := &adjustableClock{now: frozenMs}
	svc, err := New(cfg, detect.New(rules), cat, store.NewMemoryStore(),
		events.NewQueue(events.DefaultQueueCapacity),
		enforce.NewGatekeeper(enforce.Budgets{MaxBansPerMinute: 100, MaxConcurrentBans: 100}, nil),
		[]connectors.Connector{fc}, Options{Clock: clock.get})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	ip := "203.0.113.34"
	runSequence(t, svc, banGradeSequence(ip, frozenMs))
	fc.waitApplied(t, 1)

	clock.set(frozenMs + 25_000)
	d := svc.Decide(cleanRequest(ip, frozenMs+25_000))
	if d.BanTTLms == nil || *d.BanTTLms != 1_800_000-25_000 {
		t.Fatalf("renewal ttl = %v, want remaining %d", d.BanTTLms, 1_800_000-25_000)
	}
}

func TestModeProtectWithoutEnforcementOptsOut(t *testing.T) {
	// I9's two opt-out shapes in protect mode: no opt-in block, or the
	// kill switch engaged. Both re-check every decision, so both take
	// effect immediately; both record verdicts while their actions pass,
	// and neither leaves a ban for the renewal path to answer.
	cases := []struct {
		name    string
		mutator func(*config.Config)
	}{
		{"not opted in", func(c *config.Config) { c.Enforcement.Enabled = false }},
		{"kill switch engaged", func(c *config.Config) {
			c.Enforcement.Enabled = true
			c.Enforcement.KillSwitch = true
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := newFakeConnector(nil)
			h := newHarness(t, config.ModeProtect, []connectors.Connector{fc}, tc.mutator)
			ip := "203.0.113.35"
			ds := runSequence(t, h.svc, banGradeSequence(ip, frozenMs))

			if ds[0].Action != model.ActionServeDecoy {
				t.Fatalf("request 1 action = %q, want serve_decoy (decoys are tripwires, not enforcement)", ds[0].Action)
			}
			if ds[1].Action != model.ActionPass || ds[1].Verdict != model.VerdictThrottle {
				t.Fatalf("request 2 = %s/%s, want throttle/pass", ds[1].Verdict, ds[1].Action)
			}
			if ds[2].Action != model.ActionPass || ds[2].Verdict != model.VerdictBan {
				t.Fatalf("request 3 = %s/%s, want ban/pass (recorded, disarmed)", ds[2].Verdict, ds[2].Action)
			}
			if _, ok := h.gk.IsBanned(ip, frozenMs); ok {
				t.Fatal("disarmed protect mode recorded a gatekeeper ban, want none")
			}
			if n := fc.appliedCount(); n != 0 {
				t.Fatalf("connector Apply called %d times, want 0", n)
			}
			// No renewal path either: the next request scores fresh.
			d := h.svc.Decide(cleanRequest(ip, frozenMs+3000))
			if d.Action == model.ActionBan {
				t.Fatalf("next request renewed a disarmed ban: %s/%s", d.Verdict, d.Action)
			}
			if d.Verdict != model.VerdictTag {
				t.Fatalf("next request verdict = %q, want tag via session history", d.Verdict)
			}
		})
	}
}

func TestConnectorErrorsNeverChangeDecisions(t *testing.T) {
	// A failing connector is a fail-open leg of the fan-out (I1): the
	// decision is enforced exactly as before, the error is logged, and
	// nothing about the request changes.
	fc := newFakeConnector(errors.New("provider on fire"))
	h := newHarness(t, config.ModeProtect, []connectors.Connector{fc})
	ip := "203.0.113.36"
	ds := runSequence(t, h.svc, banGradeSequence(ip, frozenMs))

	if ds[2].Verdict != model.VerdictBan || ds[2].Action != model.ActionBan {
		t.Fatalf("request 3 = %s/%s, want ban/ban despite the connector error", ds[2].Verdict, ds[2].Action)
	}
	fc.waitApplied(t, 1)
	if n := fc.appliedCount(); n != 1 {
		t.Fatalf("connector Apply called %d times, want exactly 1", n)
	}
	// The renewal path works regardless of the provider's health.
	d := h.svc.Decide(cleanRequest(ip, frozenMs+3000))
	if d.Action != model.ActionBan || d.ReasonCode != "SIG-104" {
		t.Fatalf("renewal = %s/%s reason %s, want ban/ban reason SIG-104", d.Verdict, d.Action, d.ReasonCode)
	}
}

func TestModeProtectZeroConnectorsStillEnforcesLocally(t *testing.T) {
	// Protect mode without connectors is a valid local-enforcement
	// deployment: the ban gates renewals and persists as a record; nothing
	// fans out and nothing breaks.
	h := newHarness(t, config.ModeProtect, nil)
	ip := "203.0.113.37"
	ds := runSequence(t, h.svc, banGradeSequence(ip, frozenMs))
	if ds[2].Action != model.ActionBan {
		t.Fatalf("request 3 action = %q, want ban", ds[2].Action)
	}
	if _, ok := h.gk.IsBanned(ip, frozenMs); !ok {
		t.Fatal("no gatekeeper ban without connectors, want one")
	}
	records, err := h.st.BanRecords(context.Background(), frozenMs, 10)
	if err != nil {
		t.Fatalf("read ban records: %v", err)
	}
	if len(records) != 1 || !records[0].Active {
		t.Fatalf("stored records = %+v, want one active ban", records)
	}
	d := h.svc.Decide(cleanRequest(ip, frozenMs+3000))
	if d.Action != model.ActionBan {
		t.Fatalf("renewal action = %q, want ban", d.Action)
	}
}
