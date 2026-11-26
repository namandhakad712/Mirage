// Command faultinject is Mirage's fault-injection lab (docs/invariants.md
// cites it as the test hook for I1 and friends). It builds the REAL decision
// path — real rules loaded from the repo's data files and canon decoy
// catalog, the real engine, event queue, gatekeeper and dashboard, a site
// config loaded through the real config.Load from a YAML fixture — and then
// breaks exactly one dependency per scenario, asserting the system's
// behavior (not merely "it did not crash").
//
// The scenarios speak the narrow TestingT interface so the same registry
// runs under `go test` (scenarios_test.go wraps *testing.T) and under the
// terminal runner (main.go wraps a CLI adapter); nothing in this file
// imports the testing package, so the CLI build carries no test machinery.
//
// Every scenario is self-contained: it builds its own stack, injects one
// fault family, and cleans up after itself. Synchronization inside a
// scenario is channels plus bounded waits (time.After IS the assertion —
// the bound proves a fault cannot stall the request path); sleeps as a
// coordination device are forbidden by the lab's rules.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mirage-shield/mirage/internal/config"
	"github.com/mirage-shield/mirage/internal/connectors"
	"github.com/mirage-shield/mirage/internal/decoy"
	"github.com/mirage-shield/mirage/internal/detect"
	"github.com/mirage-shield/mirage/internal/enforce"
	"github.com/mirage-shield/mirage/internal/events"
	"github.com/mirage-shield/mirage/internal/model"
	"github.com/mirage-shield/mirage/internal/service"
	"github.com/mirage-shield/mirage/internal/store"
)

// TestingT is the slice of *testing.T the scenarios need: helper marking,
// failure reporting, fatal bailout and progress logs. *testing.T satisfies
// it directly; main.go ships a CLI adapter with the same surface, so the
// registry runs unmodified in both harnesses.
type TestingT interface {
	Helper()
	Error(args ...any)
	Errorf(format string, args ...any)
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Logf(format string, args ...any)
}

// Scenario is one fault family: a name, a one-line description, the
// invariants (docs/invariants.md, I-numbered) its assertions prove, and the
// run function. A scenario must assert the system's observable behavior —
// verdicts, actions, records, bounded timings — never just survival.
type Scenario struct {
	Name       string
	Desc       string
	Invariants []string
	Run        func(t TestingT)
}

// registry is the ordered fault matrix. Order is part of the contract: the
// CLI and `go test` (TestAllScenarios) execute it top to bottom, and
// TestRegistry keeps names unique, citations well-formed and README.md's
// table mentioning every entry.
var registry = []Scenario{
	{
		Name:       "store-down",
		Desc:       "Every store method fails: Decide still answers the exact engine ladder, decoys still render, the dashboard answers a clean JSON 500, /healthz stays 200 and Stop stays bounded.",
		Invariants: []string{"I1", "I3", "I10"},
		Run:        runStoreDown,
	},
	{
		Name:       "queue-flood",
		Desc:       "Queue at minimum capacity with no drainer: overflow events are dropped and counted, Decide never blocks, and decisions stay correct while the queue drops.",
		Invariants: []string{"I3", "I10"},
		Run:        runQueueFlood,
	},
	{
		Name:       "connector-dead",
		Desc:       "Apply always fails: the ban still lands locally, Apply is attempted exactly once, and the decision path stays prompt.",
		Invariants: []string{"I1", "I5", "I10"},
		Run:        runConnectorDead,
	},
	{
		Name:       "connector-hang",
		Desc:       "Apply blocks forever: Decide returns promptly, the ban is still enforced locally, and cleanup releases the wedged goroutine.",
		Invariants: []string{"I1", "I3", "I5"},
		Run:        runConnectorHang,
	},
	{
		Name:       "budget-exhausted",
		Desc:       "MaxBansPerMinute 1 with two different attackers: the first ban lands, the second degrades to observe while its verdict is still recorded.",
		Invariants: []string{"I5", "I9", "I10"},
		Run:        runBudgetExhausted,
	},
	{
		Name:       "never-ban",
		Desc:       "A ban-grade replay from inside an owner range: never scored, never banned, no record minted.",
		Invariants: []string{"I6", "I15"},
		Run:        runNeverBan,
	},
	{
		Name:       "deadline-overrun",
		Desc:       "The decision clock jumps past the budget between the start and the deadline check: the answer is exactly the reserved fail-open decision, with no event and no ban.",
		Invariants: []string{"I1", "I3"},
		Run:        runDeadlineOverrun,
	},
	{
		Name:       "kill-switch",
		Desc:       "Kill switch engaged from the fixture: verdicts record but actions pass, and an existing ban stops renewing within one decision of the flip.",
		Invariants: []string{"I9", "I10"},
		Run:        runKillSwitch,
	},
	{
		Name:       "dashboard-storm",
		Desc:       "50 concurrent workers over a broken store: every answer is well-formed JSON, prompt and panic-free, and the dashboard token never leaks into a response body.",
		Invariants: []string{"I1", "I7", "I11"},
		Run:        runDashboardStorm,
	},
}

// Lab constants. The scenario IP 203.0.113.7 and its canon session key are
// the reserved-range pair the golden-vector suite also uses
// (sha256("203.0.113.7")[:32]), so the ladder here replays a known vector
// identity, not an arbitrary one.
const (
	// labToken is the dashboard token of the lab's site fixture. The
	// dashboard-storm scenario asserts it never appears in any response
	// body (I11).
	labToken = "lab-dashboard-token-fec52565aa0cf18f57d7cf5b3ac72850"

	// labMs is the frozen decision time of every deterministic clock: the
	// deadline arithmetic always sees zero elapsed, so verdicts are
	// measured without real-time flakiness from a loaded machine.
	labMs = int64(1_789_000_000_000)

	// canonSessionKey is sha256("203.0.113.7")[:32] (spec/SIGNALS.md
	// section 2), the session the store-down ladder replays.
	canonSessionKey = "fec52565aa0cf18f57d7cf5b3ac72850"

	// browserUA is an ordinary browser signature: full headers, no signals.
	browserUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

// Bounded-wait assertions. Each bound is the ASSERTION that a fault cannot
// stall the path under test, so each is generous against a loaded CI box
// (three or more orders of magnitude above the in-memory work involved)
// while still proving promptness. None of them is a sleep: the channel is
// the synchronization, the timeout is the failure detector.
const (
	// decideBound bounds one Decide call: its synchronous work is
	// in-memory scoring plus at most a bounded store upsert — microseconds
	// even on a slow box.
	decideBound = 5 * time.Second

	// stopBound bounds Stop: it waits only for two ticker loops to observe
	// the closed channel plus one queue flush of already-emitted events.
	stopBound = 10 * time.Second

	// fanoutBound bounds the wait for the asynchronous fan-out goroutine to
	// reach a connector: a goroutine spawn and a channel send, plus the
	// OS scheduler's worst case under load.
	fanoutBound = 5 * time.Second

	// floodBound bounds the whole 125-decision flood: each decision is
	// in-memory work, so even a hundredfold slowdown fits comfortably.
	floodBound = 10 * time.Second

	// stormBound bounds the whole 200-request dashboard storm: every
	// request is an in-memory handler call, and the broken store fails
	// fast rather than hanging.
	stormBound = 15 * time.Second
)

// Site fixtures. They are real YAML, loaded through config.Load (strict
// decode, defaults, validation — the same boot path a site runs), so the
// scenarios prove the invariants against the config shape a deployment
// would actually boot with. The canon protected-route list (I4,
// spec/SIGNALS.md section 2) is spelled out explicitly so the fixture
// cannot drift if the default ever changes.

const protectYAML = `site: https://example.test
mode: protect
dashboard_token: lab-dashboard-token-fec52565aa0cf18f57d7cf5b3ac72850
protected_routes:
  - /wp-login.php
  - /wp-admin/
  - /checkout
  - /cart
  - /api/
enforcement:
  enabled: true
`

// killSwitchYAML is the same site with the global kill switch engaged
// (I9): legal in protect mode alongside the opt-in block — the switch is
// the operator's emergency stop, not a config error.
const killSwitchYAML = `site: https://example.test
mode: protect
dashboard_token: lab-dashboard-token-fec52565aa0cf18f57d7cf5b3ac72850
protected_routes:
  - /wp-login.php
  - /wp-admin/
  - /checkout
  - /cart
  - /api/
owner_ips:
  - 10.0.0.0/8
enforcement:
  enabled: true
  kill_switch: true
`

// neverBanYAML is the same site plus an owner range (I6): addresses inside
// 10.0.0.0/8 are never scored, and the gatekeeper refuses their bans on
// top of that (I15).
const neverBanYAML = `site: https://example.test
mode: protect
dashboard_token: lab-dashboard-token-fec52565aa0cf18f57d7cf5b3ac72850
protected_routes:
  - /wp-login.php
  - /wp-admin/
  - /checkout
  - /cart
  - /api/
owner_ips:
  - 10.0.0.0/8
enforcement:
  enabled: true
`

// repoRoot resolves the repository root from this file's compile-time
// location (lab/faultinject sits two levels below it). The lab runs from a
// source checkout because it reads the repo's real data files; a binary
// copied elsewhere fails with the honest error below instead of silently
// testing nothing.
func repoRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("cannot locate the lab's source file")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	if _, err := os.Stat(filepath.Join(root, "data", "scanner-paths.txt")); err != nil {
		return "", fmt.Errorf("lab runs from a source checkout (data files not found under %s): %w", root, err)
	}
	return root, nil
}

// Fixtures shared by every scenario: the real rules (data/ plus the canon
// catalog, canon protected routes) and the real catalog. Loaded once per
// process; the engine reads only in-memory state afterwards.
var (
	fixOnce sync.Once
	fixErr  error
	fixRul  detect.Rules
	fixCat  *decoy.Catalog
)

// loadFixtures loads the repo's detection data and canon decoy catalog.
func loadFixtures(t TestingT) (detect.Rules, *decoy.Catalog) {
	t.Helper()
	fixOnce.Do(func() {
		root, err := repoRoot()
		if err != nil {
			fixErr = err
			return
		}
		fixRul, fixErr = detect.LoadRules(
			filepath.Join(root, "data"),
			filepath.Join(root, "spec", "decoy-catalog", "catalog.yaml"),
			[]string{"/wp-login.php", "/wp-admin/", "/checkout", "/cart", "/api/"},
		)
		if fixErr != nil {
			return
		}
		fixCat, fixErr = decoy.Load(filepath.Join(root, "spec", "decoy-catalog", "catalog.yaml"))
	})
	if fixErr != nil {
		t.Fatalf("load lab fixtures: %v", fixErr)
	}
	return fixRul, fixCat
}

// loadSiteConfig writes the fixture YAML to a fresh temp file and loads it
// through the real config.Load, then removes the file: the scenario boots
// through the same strict decode / default / validate path a site's boot
// uses, so a fixture typo is a scenario failure, never a silently
// half-configured service.
func loadSiteConfig(t TestingT, yaml string) *config.Config {
	t.Helper()
	dir, err := os.MkdirTemp("", "faultinject-site-*")
	if err != nil {
		t.Fatalf("create temp dir for site fixture: %v", err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "mirage.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write site fixture: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load site fixture: %v", err)
	}
	return cfg
}

// frozenClock is a decision clock frozen at labMs: the deadline arithmetic
// always sees zero elapsed, so deterministic scenarios measure behavior
// without real-time flakiness.
func frozenClock() func() int64 {
	return func() int64 { return labMs }
}

// scriptClock returns scripted values in order and repeats the last one
// afterwards, so a scenario can jump the clock past the decision budget at
// an exact point of Decide's sequence (start, post-engine deadline check,
// post-enforcement deadline check) without any real waiting.
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

// stackOptions names every wire a scenario may replace with its fault;
// everything else is the real thing.
type stackOptions struct {
	yaml       string        // site fixture; required
	clock      func() int64  // nil = frozen at labMs
	store      store.Store   // nil = a real memory store
	queue      *events.Queue // nil = default capacity
	connectors []connectors.Connector
	budgets    enforce.Budgets // zero = generous lab budgets
}

// stack is one fully wired protect-mode Mirage for a scenario run: config
// from the YAML fixture, the real rules and catalog, a fresh engine, the
// queue, the gatekeeper (built with the scenario's budgets, the way a site's
// wiring feeds config budgets in) and the service on top.
type stack struct {
	svc *service.Service
	cfg *config.Config
	q   *events.Queue
	gk  *enforce.Gatekeeper
	st  store.Store
	mem *store.MemoryStore // the honest store when no fault wrapped it
	eng *detect.Engine
}

// newStack builds a scenario's stack. The zero budgets default to generous
// caps (100 bans/minute, 100 concurrent) so scenarios that are not about
// budgets never meet them.
func newStack(t TestingT, o stackOptions) *stack {
	t.Helper()
	if o.yaml == "" {
		t.Fatalf("stack: a scenario must pick a site fixture")
	}
	rules, cat := loadFixtures(t)
	cfg := loadSiteConfig(t, o.yaml)
	eng := detect.New(rules)
	st := o.store
	var mem *store.MemoryStore
	if st == nil {
		mem = store.NewMemoryStore()
		st = mem
	}
	q := o.queue
	if q == nil {
		q = events.NewQueue(events.DefaultQueueCapacity)
	}
	b := o.budgets
	if b == (enforce.Budgets{}) {
		b = enforce.Budgets{MaxBansPerMinute: 100, MaxConcurrentBans: 100, MaxSharePct: 5}
	}
	gk := enforce.NewGatekeeper(b, nil)
	clock := o.clock
	if clock == nil {
		clock = frozenClock()
	}
	svc, err := service.New(cfg, eng, cat, st, q, gk, o.connectors, service.Options{Clock: clock})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return &stack{svc: svc, cfg: cfg, q: q, gk: gk, st: st, mem: mem, eng: eng}
}

// wantRung is one expected rung of the attack ladder: the exact verdict,
// action, reason code, per-request score and cumulative session score.
type wantRung struct {
	verdict  string
	action   string
	reason   string
	reqScore int
	score    int
}

// ladderWant is what the protect-mode service must answer for the ladder
// below on a fresh session — the same rungs internal/service's own suite
// asserts, so the lab's "decisions remain correct" assertions carry the
// same authority as the parity gate.
var ladderWant = []wantRung{
	{verdict: model.VerdictDecoyRoute, action: model.ActionServeDecoy, reason: "SIG-101", reqScore: 25, score: 25},
	{verdict: model.VerdictThrottle, action: model.ActionThrottle, reason: "SIG-101", reqScore: 40, score: 65},
	{verdict: model.VerdictBan, action: model.ActionBan, reason: "SIG-104", reqScore: 50, score: 115},
}

// banGradeSequence is the honeytoken canon attack ladder the lab replays
// (the same shape internal/service's suite uses): a scanner hit arms a
// decoy lead, a tool-UA follow escalates, and the minted honeytoken on the
// protected auth route (I4's cap does not save the attacker) earns the ban.
//
//	req1 GET  /.env        browser UA   -> scanner_path 25 -> decoy_route
//	req2 GET  /.env        sqlmap UA    -> +40            -> throttle
//	req3 POST /api/v1/auth bearer token -> honeytoken 50 -> ban
func banGradeSequence(ip string, ts int64) []model.Request {
	token := decoy.MintToken(model.SessionKey(ip), "env-file-staging", "db_password")
	return []model.Request{
		{Method: "GET", Path: "/.env", ClientIP: ip, UserAgent: browserUA, HeaderCount: 8, TsMs: ts},
		{Method: "GET", Path: "/.env", ClientIP: ip, UserAgent: "sqlmap/1.8", HeaderCount: 8, TsMs: ts + 1000},
		{Method: "POST", Path: "/api/v1/auth", ClientIP: ip, UserAgent: browserUA, HeaderCount: 8, AuthHint: "Bearer " + token, TsMs: ts + 2000},
	}
}

// cleanRequest is an ordinary browsing request: no signals on a fresh
// session, so floods of them stay observe/pass.
func cleanRequest(ip string, ts int64) model.Request {
	return model.Request{Method: "GET", Path: "/about", ClientIP: ip, UserAgent: browserUA, HeaderCount: 9, HasCookie: true, TsMs: ts}
}

// assertRung fails the scenario with a precise diff when one rung diverges.
func assertRung(t TestingT, n int, got model.Decision, want wantRung) {
	t.Helper()
	var diffs []string
	if got.Verdict != want.verdict {
		diffs = append(diffs, fmt.Sprintf("verdict:       want %s, got %s", want.verdict, got.Verdict))
	}
	if got.Action != want.action {
		diffs = append(diffs, fmt.Sprintf("action:        want %s, got %s", want.action, got.Action))
	}
	if got.ReasonCode != want.reason {
		diffs = append(diffs, fmt.Sprintf("reason_code:   want %s, got %s", want.reason, got.ReasonCode))
	}
	if got.RequestScore != want.reqScore {
		diffs = append(diffs, fmt.Sprintf("request_score: want %d, got %d", want.reqScore, got.RequestScore))
	}
	if got.Score != want.score {
		diffs = append(diffs, fmt.Sprintf("score:         want %d, got %d", want.score, got.Score))
	}
	if len(diffs) > 0 {
		t.Errorf("ladder rung %d diverges (a fault must never distort the engine's decision):\n  %s",
			n, strings.Join(diffs, "\n  "))
	}
}

// decideLadder decides the ladder in order and returns the decisions,
// asserting nothing — for postures whose ACTIONS differ from the enforced
// ladder (the budget cap, the kill switch) the scenario asserts each rung
// itself with the action it expects.
func decideLadder(t TestingT, svc *service.Service, ip string, ts int64) []model.Decision {
	t.Helper()
	seq := banGradeSequence(ip, ts)
	out := make([]model.Decision, 0, len(seq))
	for _, req := range seq {
		out = append(out, svc.Decide(req))
	}
	return out
}

// replayLadder decides the ladder in order and asserts every rung exactly
// against the enforced ladder. It returns the decisions for follow-up
// assertions (decoy rendering, session keys).
func replayLadder(t TestingT, svc *service.Service, ip string, ts int64) []model.Decision {
	t.Helper()
	ds := decideLadder(t, svc, ip, ts)
	for i, d := range ds {
		assertRung(t, i+1, d, ladderWant[i])
	}
	return ds
}

// waitDecide runs one Decide in its own goroutine and returns its decision,
// failing the scenario when the bound elapses first: the bound IS the
// assertion that the injected fault cannot stall the request path (I1, I3).
// A timed-out Decide goroutine is the failure being reported; Decide takes
// no context, so there is nothing to cancel — the run is already failing.
func waitDecide(t TestingT, bound time.Duration, what string, svc *service.Service, req model.Request) model.Decision {
	t.Helper()
	type result struct{ d model.Decision }
	c := make(chan result, 1)
	go func() { c <- result{svc.Decide(req)} }()
	select {
	case r := <-c:
		return r.d
	case <-time.After(bound):
		t.Fatalf("Decide(%s) did not return within %s: a fault must never stall the request path (I1, I3)", what, bound)
		return model.Decision{}
	}
}

// ---------------------------------------------------------------------------
// Fault actors
// ---------------------------------------------------------------------------

// errStoreDown is the fixed error every brokenStore method returns: one
// error for the whole family, so failures in the log are recognizable.
var errStoreDown = errors.New("faultinject: store down")

// brokenStore is the store-down fault: EVERY method of the Store contract
// fails, reads and writes alike — the shape of a wedged disk, a locked
// database or a full filesystem. It embeds nothing and stores nothing; the
// point is that nothing the service does with it can succeed.
type brokenStore struct{}

var _ store.Store = brokenStore{}

func (brokenStore) AppendEvent(context.Context, model.Event) error { return errStoreDown }
func (brokenStore) RecentEvents(context.Context, int) ([]model.Event, error) {
	return nil, errStoreDown
}
func (brokenStore) UpsertSessionSummary(context.Context, store.SessionSummary) error {
	return errStoreDown
}
func (brokenStore) SessionSummaries(context.Context, int) ([]store.SessionSummary, error) {
	return nil, errStoreDown
}
func (brokenStore) BanRecords(context.Context, int64, int) ([]store.BanRecord, error) {
	return nil, errStoreDown
}
func (brokenStore) UpsertBanRecord(context.Context, store.BanRecord) error {
	return errStoreDown
}
func (brokenStore) Close() error { return errStoreDown }

// deadConnector is the connector-dead fault: a provider that always fails.
// The attempt counter and the signal channel let the scenario assert the
// fan-out tried exactly once without blocking on it — the fan-out runs on
// its own goroutine precisely so a dead provider cannot touch the request.
type deadConnector struct {
	err     error
	applied chan struct{}
	count   atomic.Int64
}

func newDeadConnector(err error) *deadConnector {
	return &deadConnector{err: err, applied: make(chan struct{}, 8)}
}

func (d *deadConnector) Name() string { return "dead-provider" }

// Apply records the attempt and fails — always, and promptly.
func (d *deadConnector) Apply(_ context.Context, _ connectors.Ban) error {
	d.count.Add(1)
	select {
	case d.applied <- struct{}{}:
	default:
	}
	return d.err
}

func (d *deadConnector) Revoke(context.Context, connectors.Ban) error { return nil }

func (d *deadConnector) Reconcile(context.Context, []connectors.Ban, int64) (int, error) {
	return 0, nil
}

func (d *deadConnector) HealthCheck(context.Context) error { return d.err }

// waitApplied blocks until Apply has been attempted n times, failing the
// scenario on the bound: the channel is the synchronization, never a sleep.
func (d *deadConnector) waitApplied(t TestingT, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-d.applied:
		case <-time.After(fanoutBound):
			t.Fatalf("connector Apply attempted %d times, want at least %d within %s",
				d.count.Load(), n, fanoutBound)
		}
	}
}

// hungConnector is the connector-hang fault: a provider that never
// answers. Apply blocks until the scenario's cleanup closes release; the
// entered channel signals that the fan-out goroutine has reached Apply, so
// the scenario can prove Decide returned while the provider was still
// wedged. The WaitGroup counts entered Apply calls so cleanup can prove no
// goroutine leaked.
type hungConnector struct {
	release chan struct{}
	entered chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

func newHungConnector() *hungConnector {
	return &hungConnector{
		release: make(chan struct{}),
		entered: make(chan struct{}, 8),
	}
}

func (c *hungConnector) Name() string { return "wedged-provider" }

// Apply enters the WaitGroup BEFORE signalling, so a caller that observed
// the signal can safely Wait; it then blocks on release, ignoring the
// context exactly like a wedged provider would.
func (c *hungConnector) Apply(_ context.Context, _ connectors.Ban) error {
	c.wg.Add(1)
	defer c.wg.Done()
	select {
	case c.entered <- struct{}{}:
	default:
	}
	<-c.release
	return errors.New("faultinject: provider released after a hang")
}

func (c *hungConnector) Revoke(context.Context, connectors.Ban) error { return nil }

func (c *hungConnector) Reconcile(context.Context, []connectors.Ban, int64) (int, error) {
	return 0, nil
}

func (c *hungConnector) HealthCheck(context.Context) error { return nil }

// waitEntered blocks until the fan-out goroutine has reached Apply.
func (c *hungConnector) waitEntered(t TestingT) {
	t.Helper()
	select {
	case <-c.entered:
	case <-time.After(fanoutBound):
		t.Fatalf("the fan-out goroutine never reached the hung connector's Apply within %s", fanoutBound)
	}
}

// unblock releases the wedged Apply exactly once; safe to call from a
// deferred cleanup even if the scenario bailed out first.
func (c *hungConnector) unblock() { c.once.Do(func() { close(c.release) }) }

var (
	_ connectors.Connector = (*deadConnector)(nil)
	_ connectors.Connector = (*hungConnector)(nil)
)

// ---------------------------------------------------------------------------
// Dashboard helpers
// ---------------------------------------------------------------------------

// The dashboard auth header styles the lab exercises.
const (
	tokenHeader = "X-Mirage-Dashboard-Token"
	authHeader  = "Authorization"
)

// dashboardRequest performs one dashboard request against the handler and
// returns the status and body. It is safe for concurrent use: every call
// builds its own request and recorder.
func dashboardRequest(h http.Handler, method, target, style, token, body string) (int, string) {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rdr)
	switch style {
	case "header":
		req.Header.Set(tokenHeader, token)
	case "bearer":
		req.Header.Set(authHeader, "Bearer "+token)
	case "none":
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// doDashboard wraps dashboardRequest for single-threaded scenario use,
// failing on an unknown style so a typo cannot silently test "no token".
func doDashboard(t TestingT, h http.Handler, method, target, style, token, body string) (int, string) {
	t.Helper()
	switch style {
	case "header", "bearer", "none":
	default:
		t.Fatalf("unknown token style %q", style)
	}
	return dashboardRequest(h, method, target, style, token, body)
}

// decodeJSONObject parses a body as a flat JSON object and fails the
// scenario when it is not one — "well-formed JSON" is the assertion, the
// status code is the caller's business.
func decodeJSONObject(t TestingT, label, body string) map[string]any {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("%s body is not a JSON object (%v): %q", label, err, body)
	}
	return parsed
}

// ---------------------------------------------------------------------------
// Scenario 1: store-down
// ---------------------------------------------------------------------------

// runStoreDown proves the decision path does not need the store to be
// alive (I1): with every store method failing, Decide still answers the
// exact engine ladder for the canon 203.0.113.7 session (I3 — scoring is
// in-memory and the one deliberate store write degrades to a logged
// error), ServeDecoy still renders (the catalog is not the store), the
// dashboard answers a well-formed JSON 500 instead of a panic (I7 — no
// internal detail in the body), the tokenless /healthz probe stays 200,
// and Stop still returns promptly with nil (I1: shutdown degrades, it does
// not error).
func runStoreDown(t TestingT) {
	t.Helper()
	h := newStack(t, stackOptions{yaml: protectYAML, store: brokenStore{}})
	h.svc.Start(context.Background()) // drainer and reconciler live, draining into the broken store

	ds := replayLadder(t, h.svc, "203.0.113.7", labMs)
	if ds[0].SessionKey != canonSessionKey {
		t.Errorf("session key = %q, want the canon key %q of the replayed vector identity", ds[0].SessionKey, canonSessionKey)
	}

	// Decoys render from the catalog, not the store: a decoy_route decision
	// is still servable while the store is down (I1).
	rendered, err := h.svc.ServeDecoy(ds[0])
	if err != nil {
		t.Fatalf("ServeDecoy over a broken store: %v (I1: the caller serves the origin)", err)
	}
	if rendered.DecoyID != "env-file-staging" || rendered.Status != 200 || len(rendered.Body) == 0 {
		t.Errorf("rendered decoy = id %q status %d body %d bytes, want env-file-staging/200/non-empty", rendered.DecoyID, rendered.Status, len(rendered.Body))
	}

	handler := h.svc.Handler()

	// Stored-data endpoints degrade to a clean JSON 500 — no panic, no
	// internal detail, no store error text in the body (I7).
	code, body := doDashboard(t, handler, "GET", "/api/events", "header", labToken, "")
	if code != http.StatusInternalServerError {
		t.Errorf("/api/events over a broken store = %d, want 500", code)
	}
	if got := decodeJSONObject(t, "/api/events", body)["error"]; got != "store unavailable" {
		t.Errorf("/api/events error body = %v, want the fixed store unavailable envelope", got)
	}

	// The LB probe carries no token and no store dependency: it stays 200
	// while everything behind it is on fire (I1).
	code, body = doDashboard(t, handler, "GET", "/healthz", "none", "", "")
	if code != http.StatusOK {
		t.Errorf("/healthz over a broken store = %d, want 200", code)
	}
	if got := decodeJSONObject(t, "/healthz", body)["status"]; got != "ok" {
		t.Errorf("/healthz body = %v, want ok", got)
	}

	// Stop returns nil within the bound even though the final flush is
	// writing into a failing store: shutdown degrades, it does not hang.
	done := make(chan error, 1)
	go func() { done <- h.svc.Stop(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Stop over a broken store = %v, want nil (degrade, do not error)", err)
		}
	case <-time.After(stopBound):
		t.Fatalf("Stop did not return within %s over a broken store: shutdown must stay bounded (I1)", stopBound)
	}
}

// ---------------------------------------------------------------------------
// Scenario 2: queue-flood
// ---------------------------------------------------------------------------

// runQueueFlood proves a full queue costs events, never requests (I3):
// with the queue at the minimum legal capacity and no drainer running, a
// flood of decisions over capacity completes inside the bound, the
// overflow is counted in Dropped() (I10's honest loss accounting), and the
// decision made while the queue was already full is still exactly right.
func runQueueFlood(t TestingT) {
	t.Helper()
	const capacity = events.MinQueueCapacity // 100, the smallest legal queue
	const flood = 125                        // capacity + 25 overflow
	h := newStack(t, stackOptions{
		yaml:  protectYAML,
		queue: events.NewQueue(capacity),
	})
	// The drainer is deliberately never started: nothing rescues the queue.

	var mu sync.Mutex
	var floodErrs []string
	failed := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		floodErrs = append(floodErrs, fmt.Sprintf(format, args...))
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < flood; i++ {
			d := h.svc.Decide(cleanRequest("203.0.113.98", labMs+int64(i)))
			if d.Verdict != model.VerdictObserve || d.Action != model.ActionPass {
				failed("flood decision %d = %s/%s, want observe/pass", i+1, d.Verdict, d.Action)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(floodBound):
		t.Fatalf("the flood of %d decisions did not complete within %s: TryEmit must never block the hot path (I3)", flood, floodBound)
	}
	for _, e := range floodErrs {
		t.Errorf("%s", e)
	}

	if got := h.q.Len(); got != capacity {
		t.Errorf("queue holds %d events after the flood, want %d (at capacity)", got, capacity)
	}
	if got := h.q.Dropped(); got != flood-capacity {
		t.Errorf("queue dropped %d events, want %d (every overflow counted, I10)", got, flood-capacity)
	}

	// Decisions stay correct while the queue drops: a fresh attacker's
	// first rung answers exactly right even as its event is discarded.
	d := h.svc.Decide(model.Request{
		Method: "GET", Path: "/.env", ClientIP: "203.0.113.99",
		UserAgent: browserUA, HeaderCount: 8, TsMs: labMs,
	})
	assertRung(t, 1, d, ladderWant[0])
	if got := h.q.Dropped(); got != flood-capacity+1 {
		t.Errorf("queue dropped %d events after the post-flood decision, want %d", got, flood-capacity+1)
	}
	if got := h.q.Len(); got != capacity {
		t.Errorf("queue holds %d events after the post-flood decision, want still %d (the newest event was dropped)", got, capacity)
	}
}

// ---------------------------------------------------------------------------
// Scenario 3: connector-dead
// ---------------------------------------------------------------------------

// runConnectorDead proves a provider outage changes nothing about the
// decision (I1): Apply always failing still yields the exact ladder with
// the ban rung enforced (I5 — the gatekeeper and the store record are the
// local truth), the attempt was made exactly once, and the decision path
// returned promptly despite it.
func runConnectorDead(t TestingT) {
	t.Helper()
	dc := newDeadConnector(errors.New("faultinject: provider unreachable"))
	h := newStack(t, stackOptions{yaml: protectYAML, connectors: []connectors.Connector{dc}})
	ip := "203.0.113.7"

	seq := banGradeSequence(ip, labMs)
	assertRung(t, 1, h.svc.Decide(seq[0]), ladderWant[0])
	assertRung(t, 2, h.svc.Decide(seq[1]), ladderWant[1])
	// The ban rung must return promptly even though its provider call will
	// fail: the fan-out is asynchronous by design (I1).
	d := waitDecide(t, decideBound, "the ban rung against a dead provider", h.svc, seq[2])
	assertRung(t, 3, d, ladderWant[2])

	// The ban is real locally: gatekeeper plus durable record (I5, I10).
	if _, ok := h.gk.IsBanned(ip, labMs); !ok {
		t.Error("the gatekeeper holds no ban for the dead-provider run, want one (local enforcement)")
	}
	records, err := h.mem.BanRecords(context.Background(), labMs, 10)
	if err != nil {
		t.Fatalf("read ban records: %v", err)
	}
	if len(records) != 1 || !records[0].Active || records[0].Reason != "SIG-104" || records[0].IP != ip {
		t.Errorf("stored records = %+v, want one active SIG-104 record for %s", records, ip)
	}

	// Exactly one attempt: an error is retried by the reconcile loop in
	// real deployments, never by re-running the decision.
	dc.waitApplied(t, 1)
	if got := dc.count.Load(); got != 1 {
		t.Errorf("connector Apply attempted %d times, want exactly 1", got)
	}
}

// ---------------------------------------------------------------------------
// Scenario 4: connector-hang
// ---------------------------------------------------------------------------

// runConnectorHang proves a wedged provider cannot stall a request (I1,
// I3): Apply blocks forever, yet the ban rung returns promptly, the ban is
// still enforced locally, and the scenario's cleanup releases the wedged
// goroutine and waits for it — no leaks.
func runConnectorHang(t TestingT) {
	t.Helper()
	hc := newHungConnector()
	h := newStack(t, stackOptions{yaml: protectYAML, connectors: []connectors.Connector{hc}})
	ip := "203.0.113.7"

	// Cleanup runs even if the scenario bails out mid-run (Fatalf panics
	// through the defers): release the wedge first, then wait for the
	// fan-out goroutine to leave Apply — deferred calls run LIFO, so these
	// two defers execute in exactly that order.
	defer hc.wg.Wait()
	defer hc.unblock()

	seq := banGradeSequence(ip, labMs)
	assertRung(t, 1, h.svc.Decide(seq[0]), ladderWant[0])
	assertRung(t, 2, h.svc.Decide(seq[1]), ladderWant[1])
	d := waitDecide(t, decideBound, "the ban rung against a hung provider", h.svc, seq[2])
	assertRung(t, 3, d, ladderWant[2])

	// The ban is real while the provider is still wedged (I5).
	if _, ok := h.gk.IsBanned(ip, labMs); !ok {
		t.Error("the gatekeeper holds no ban for the hung-provider run, want one (local enforcement)")
	}
	records, err := h.mem.BanRecords(context.Background(), labMs, 10)
	if err != nil {
		t.Fatalf("read ban records: %v", err)
	}
	if len(records) != 1 || !records[0].Active {
		t.Errorf("stored records = %+v, want one active ban", records)
	}

	// Prove the provider was actually still wedged when the decision
	// returned: the fan-out goroutine is inside Apply, blocking.
	hc.waitEntered(t)
	t.Logf("Decide returned while the provider Apply was still blocked (I1, I3)")
}

// ---------------------------------------------------------------------------
// Scenario 5: budget-exhausted
// ---------------------------------------------------------------------------

// runBudgetExhausted proves the operational budgets cap enforcement
// without erasing evidence (I5, I9, I10): with one ban per minute allowed,
// the first attacker's ban lands and the second attacker's ban-grade run
// still records its verdicts, but the action degrades to pass — the
// gatekeeper's OutcomeObserve semantics surfaced through the service.
func runBudgetExhausted(t TestingT) {
	t.Helper()
	h := newStack(t, stackOptions{
		yaml:    protectYAML,
		budgets: enforce.Budgets{MaxBansPerMinute: 1, MaxConcurrentBans: 100, MaxSharePct: 5},
	})
	first, second := "203.0.113.7", "198.51.100.23"

	// The first attacker meets a fresh budget: the full enforced ladder.
	ds := decideLadder(t, h.svc, first, labMs)
	for i, d := range ds {
		assertRung(t, i+1, d, ladderWant[i])
	}
	if ds[2].Action != model.ActionBan {
		t.Fatalf("the first attacker's ban rung action = %q, want ban (the budget was fresh)", ds[2].Action)
	}

	// A second, different attacker inside the same budget window: the
	// verdicts stay exact (evidence, I10) but the cap drops the action.
	ds2 := decideLadder(t, h.svc, second, labMs+10_000)
	assertRung(t, 1, ds2[0], ladderWant[0])
	assertRung(t, 2, ds2[1], ladderWant[1])
	capped := ladderWant[2] // copy: the cap changes the action, nothing else
	capped.action = model.ActionPass
	assertRung(t, 3, ds2[2], capped)
	if ds2[0].Action != model.ActionServeDecoy || ds2[1].Action != model.ActionThrottle {
		t.Errorf("the second attacker's early rungs = %s/%s, want serve_decoy/throttle (unaffected by ban budgets)", ds2[0].Action, ds2[1].Action)
	}

	// All six decisions were recorded as events; only the first ban exists.
	if got := h.q.Len(); got != 6 {
		t.Errorf("queue holds %d events, want 6 (every verdict recorded, I10)", got)
	}
	if _, ok := h.gk.IsBanned(first, labMs+12_000); !ok {
		t.Error("the first attacker lost its gatekeeper ban, want it kept (the cap must not disarm earned bans)")
	}
	if _, ok := h.gk.IsBanned(second, labMs+12_000); ok {
		t.Error("the second attacker holds a gatekeeper ban, want none (its ban dropped to observe)")
	}
	records, err := h.mem.BanRecords(context.Background(), labMs+12_000, 10)
	if err != nil {
		t.Fatalf("read ban records: %v", err)
	}
	if len(records) != 1 || records[0].IP != first {
		t.Errorf("stored records = %+v, want exactly the first attacker's record", records)
	}
}

// ---------------------------------------------------------------------------
// Scenario 6: never-ban
// ---------------------------------------------------------------------------

// runNeverBan proves the never-ban ranges hold against a full ban-grade
// replay (I15, I6): an address inside the site's owner range is never
// scored (the service resolves owner ranges before the engine), so the
// armed honeytoken earns nothing, every action passes, and no ban record
// exists anywhere.
func runNeverBan(t TestingT) {
	t.Helper()
	h := newStack(t, stackOptions{yaml: neverBanYAML})
	ip := "10.0.0.5" // inside owner_ips 10.0.0.0/8

	for i, req := range banGradeSequence(ip, labMs) {
		d := h.svc.Decide(req)
		if d.Action != model.ActionPass {
			t.Errorf("rung %d from the owner range action = %q, want pass (never banned, I15)", i+1, d.Action)
		}
		if d.Verdict != model.VerdictObserve {
			t.Errorf("rung %d from the owner range verdict = %q, want observe (owner ranges are never scored, I6)", i+1, d.Verdict)
		}
		if d.BanTTLms != nil {
			t.Errorf("rung %d from the owner range carries a ban ttl of %d, want none", i+1, *d.BanTTLms)
		}
	}

	if _, ok := h.gk.IsBanned(ip, labMs); ok {
		t.Error("the gatekeeper holds a ban for an owner-range address, want none (I15)")
	}
	records, err := h.mem.BanRecords(context.Background(), labMs, 10)
	if err != nil {
		t.Fatalf("read ban records: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("stored ban records = %+v, want none for a never-ban address", records)
	}
}

// ---------------------------------------------------------------------------
// Scenario 7: deadline-overrun
// ---------------------------------------------------------------------------

// runDeadlineOverrun proves I1's sharpest edge: when the decision clock
// jumps past the budget between the start and the deadline check, even a
// fully armed ban-grade request answers with EXACTLY the reserved
// fail-open decision — reason SIG-000, action pass — and the fail-open
// path mints nothing: no event, no gatekeeper ban, no record (SIG-000 is
// never a ban input, ADAPTER-PROTOCOL section 3).
func runDeadlineOverrun(t TestingT) {
	t.Helper()
	// The clock reads: decision start, post-engine deadline check. The
	// second read jumps past DefaultDecideBudgetMs, so the first deadline
	// check fires before any enforcement wiring can run.
	clk := &scriptClock{vals: []int64{labMs, labMs, labMs + service.DefaultDecideBudgetMs + 1}}
	h := newStack(t, stackOptions{yaml: protectYAML, clock: clk.now})

	d := h.svc.Decide(banGradeSequence("203.0.113.7", labMs)[2])
	if !reflect.DeepEqual(d, model.FailOpen()) {
		t.Fatalf("decision on deadline overrun = %+v, want exactly the reserved fail-open decision (I1)", d)
	}
	if d.ReasonCode != model.FailOpenReason || d.Action != model.ActionPass || d.Verdict != model.VerdictObserve {
		t.Fatalf("fail-open shape = %s/%s reason %s, want observe/pass reason %s",
			d.Verdict, d.Action, d.ReasonCode, model.FailOpenReason)
	}

	if got := h.q.Len(); got != 0 {
		t.Errorf("queue holds %d events after a fail-open decision, want 0 (no event is minted)", got)
	}
	if _, ok := h.gk.IsBanned("203.0.113.7", labMs); ok {
		t.Error("the gatekeeper holds a ban minted by a fail-open decision, want none (SIG-000 is never a ban input)")
	}
	records, err := h.mem.BanRecords(context.Background(), labMs, 10)
	if err != nil {
		t.Fatalf("read ban records: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("stored ban records = %+v, want none minted by the fail-open path", records)
	}
}

// ---------------------------------------------------------------------------
// Scenario 8: kill-switch
// ---------------------------------------------------------------------------

// runKillSwitch proves the global kill switch (I9) in both directions:
// engaged from the fixture, a ban-grade run records every verdict (I10)
// while every enforcement action passes and nothing is minted; flipped
// live on an armed service, an already-banned address stops renewing
// within one decision — the per-decision EnforcementAllowed re-check is
// what disarms renewal immediately, not a TTL later.
func runKillSwitch(t TestingT) {
	t.Helper()

	// Phase 1: the switch engaged at boot, from the site fixture itself.
	// The verdicts, reasons and scores stay exact (I10); only the
	// enforcement actions pass.
	h1 := newStack(t, stackOptions{yaml: killSwitchYAML})
	ip1 := "203.0.113.7"
	ds := decideLadder(t, h1.svc, ip1, labMs)
	assertRung(t, 1, ds[0], ladderWant[0]) // decoys are tripwires, not enforcement
	disarmed := ladderWant[1]              // copy: only the action is overridden
	disarmed.action = model.ActionPass
	assertRung(t, 2, ds[1], disarmed)
	capped := ladderWant[2] // copy: only the action is overridden
	capped.action = model.ActionPass
	assertRung(t, 3, ds[2], capped)
	if ds[0].Action != model.ActionServeDecoy {
		t.Errorf("rung 1 action = %q, want serve_decoy (decoys are tripwires, not enforcement)", ds[0].Action)
	}
	if ds[2].BanTTLms == nil {
		t.Error("rung 3 carries no ban ttl, want the recorded verdict parameter to survive the disarm")
	}
	if got := h1.q.Len(); got != 3 {
		t.Errorf("queue holds %d events, want 3 (verdicts still recorded, I10)", got)
	}
	if _, ok := h1.gk.IsBanned(ip1, labMs); ok {
		t.Error("the gatekeeper holds a ban under the kill switch, want none")
	}

	// Phase 2: armed boot, a real ban, then the live flip. The flip is the
	// operation under test: the service re-checks EnforcementAllowed on
	// every decision, so flipping the field is exactly what an operator's
	// reload does — and the flipped config is re-validated to prove the
	// engaged switch remains a legal state.
	h2 := newStack(t, stackOptions{yaml: protectYAML})
	ip2 := "198.51.100.23"
	replayLadder(t, h2.svc, ip2, labMs)
	if _, ok := h2.gk.IsBanned(ip2, labMs); !ok {
		t.Fatal("phase 2 setup: the armed run left no ban to disarm")
	}
	h2.cfg.Enforcement.KillSwitch = true
	if err := h2.cfg.Validate(); err != nil {
		t.Fatalf("the flipped config is invalid: %v (kill_switch in protect mode is legal, I9)", err)
	}
	d := h2.svc.Decide(cleanRequest(ip2, labMs+3000))
	if d.Action == model.ActionBan || d.ReasonCode == "SIG-104" {
		t.Fatalf("post-flip request = %s/%s reason %s, want a fresh score (renewal must disarm within one decision)",
			d.Verdict, d.Action, d.ReasonCode)
	}
	if d.Action != model.ActionPass {
		t.Errorf("post-flip request action = %q, want pass (enforcement is off)", d.Action)
	}
	// The record survives — the switch stops answering, it does not erase
	// history — but nothing renews it.
	if _, ok := h2.gk.IsBanned(ip2, labMs+3000); !ok {
		t.Error("the flip erased the existing ban record, want it kept (the switch disarms, it does not rewrite history)")
	}
	records, err := h2.mem.BanRecords(context.Background(), labMs+3000, 10)
	if err != nil {
		t.Fatalf("read ban records: %v", err)
	}
	if len(records) != 1 || records[0].IP != ip2 {
		t.Errorf("stored records = %+v, want exactly the pre-flip ban", records)
	}
}

// ---------------------------------------------------------------------------
// Scenario 9: dashboard-storm
// ---------------------------------------------------------------------------

// stormTarget is one request shape of the storm: an endpoint, a token
// presentation style and an optional body.
type stormTarget struct {
	method, target, style, token, body string
}

// runDashboardStorm proves the dashboard survives a concurrent hammering
// while the store behind it is fully broken (I1): 50 workers mix valid and
// invalid tokens across every endpoint; every response is well-formed JSON
// with the JSON content type (I7), every handler call returns inside the
// bound, no call panics, and the dashboard token never appears in any
// response body (I11) — not in errors, not in listings.
func runDashboardStorm(t TestingT) {
	t.Helper()
	h := newStack(t, stackOptions{yaml: protectYAML, store: brokenStore{}})
	handler := h.svc.Handler()

	targets := []stormTarget{
		{"GET", "/api/status", "header", labToken, ""},
		{"GET", "/api/status", "none", "", ""},
		{"GET", "/api/events", "bearer", labToken, ""},
		{"GET", "/api/events", "header", "wrong-token", ""},
		{"GET", "/api/sessions", "none", "", ""},
		{"GET", "/api/bans", "header", labToken, ""},
		{"POST", "/api/bans/revoke", "header", labToken, `{"ip":"203.0.113.7","reason":"SIG-104"}`},
		{"POST", "/api/bans/revoke", "header", "wrong-token", `{"ip":"203.0.113.7","reason":"SIG-104"}`},
		{"GET", "/healthz", "none", "", ""},
		{"GET", "/api/no-such-path", "none", "", ""},
	}

	const workers = 50
	const rounds = 4 // 200 requests total

	var mu sync.Mutex
	bodies := make([]string, 0, workers*rounds)
	violations := make([]string, 0)
	note := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		violations = append(violations, fmt.Sprintf(format, args...))
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				tg := targets[(w+r)%len(targets)]
				func() {
					// A handler panic is a scenario failure, not a process
					// crash: recover it and record it.
					defer func() {
						if v := recover(); v != nil {
							note("panic on %s %s: %v", tg.method, tg.target, v)
						}
					}()
					req := httptest.NewRequest(tg.method, tg.target, strings.NewReader(tg.body))
					switch tg.style {
					case "header":
						req.Header.Set(tokenHeader, tg.token)
					case "bearer":
						req.Header.Set(authHeader, "Bearer "+tg.token)
					}
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					var probe any
					if err := json.Unmarshal(rec.Body.Bytes(), &probe); err != nil {
						note("%s %s returned a non-JSON body: %q", tg.method, tg.target, rec.Body.String())
					}
					if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
						note("%s %s Content-Type = %q, want application/json", tg.method, tg.target, ct)
					}
					mu.Lock()
					bodies = append(bodies, rec.Body.String())
					mu.Unlock()
				}()
			}
		}(w)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(stormBound):
		t.Fatalf("the dashboard storm did not complete within %s: the handler must answer promptly even over a broken store (I1)", stormBound)
	}

	for _, v := range violations {
		t.Errorf("%s", v)
	}
	if len(bodies) != workers*rounds {
		t.Fatalf("collected %d response bodies, want %d (every request answered)", len(bodies), workers*rounds)
	}
	for _, b := range bodies {
		if strings.Contains(b, labToken) {
			t.Errorf("the dashboard token leaked into a response body (I11): %q", b)
			break
		}
	}
}
