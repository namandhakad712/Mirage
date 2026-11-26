package service

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/mirage-shield/mirage/internal/config"
	"github.com/mirage-shield/mirage/internal/decoy"
	"github.com/mirage-shield/mirage/internal/detect"
	"github.com/mirage-shield/mirage/internal/enforce"
	"github.com/mirage-shield/mirage/internal/events"
	"github.com/mirage-shield/mirage/internal/model"
	"github.com/mirage-shield/mirage/internal/store"
)

// scriptClock returns scripted values in order and repeats the last one
// afterwards, so a test can jump the clock past the decision budget at an
// exact point of Decide's sequence (start, post-engine check,
// post-enforcement check) without any real waiting.
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

// newScriptService builds a look-mode service with the scripted clock. Look
// mode is enough: the deadline guards every mode's decision path, and a
// queue is attached so the no-event assertion can see emissions.
func newScriptService(t *testing.T, vals ...int64) (*Service, *events.Queue) {
	t.Helper()
	rules, cat := loadTestRules(t)
	cfg := testConfig(t, config.ModeLook)
	q := events.NewQueue(events.DefaultQueueCapacity)
	svc, err := New(cfg, detect.New(rules), cat, store.NewMemoryStore(), q, nil, nil,
		Options{Clock: (&scriptClock{vals: vals}).now})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, q
}

func TestDecideFailOpenOnDeadlineOverrunAfterEngine(t *testing.T) {
	// I1 + ADAPTER-PROTOCOL section 2: the clock jumps past the budget
	// right after the engine call, so the first deadline check fails and
	// the decision is the reserved fail-open decision — with NO event:
	// SIG-000 must never become ban input.
	svc, q := newScriptService(t, frozenMs, frozenMs+DefaultDecideBudgetMs+1)
	d := svc.Decide(model.Request{
		Method: "GET", Path: "/.env", ClientIP: "203.0.113.40",
		UserAgent: browserUA, HeaderCount: 8, TsMs: frozenMs,
	})
	if !reflect.DeepEqual(d, model.FailOpen()) {
		t.Fatalf("decision = %+v, want the fail-open decision", d)
	}
	if d.ReasonCode != model.FailOpenReason {
		t.Fatalf("reason = %q, want the reserved %s", d.ReasonCode, model.FailOpenReason)
	}
	if got := q.Len(); got != 0 {
		t.Fatalf("queue holds %d events after a fail-open decision, want 0", got)
	}
}

func TestDecideFailOpenOnDeadlineOverrunAfterEnforcement(t *testing.T) {
	// The second check: the engine call fits the budget, the enforcement
	// wiring runs (gatekeeper, reason memo, store record), and the clock
	// jumps only at the final check. The decision is discarded entirely —
	// fail-open answer, no event — while the ban bookkeeping it recorded
	// persists: the next request from the address renews it.
	rules, cat := loadTestRules(t)
	cfg := testConfig(t, config.ModeProtect, func(c *config.Config) {
		c.Enforcement.Enabled = true
	})
	clock := &scriptClock{vals: []int64{
		frozenMs, frozenMs, frozenMs, // req1: start, post-engine, post-wiring
		frozenMs, frozenMs, frozenMs, // req2: same
		frozenMs, frozenMs, frozenMs + DefaultDecideBudgetMs + 1, // req3: jump after enforcement
	}}
	q := events.NewQueue(events.DefaultQueueCapacity)
	gk := enforce.NewGatekeeper(enforce.Budgets{MaxBansPerMinute: 100, MaxConcurrentBans: 100}, nil)
	svc, err := New(cfg, detect.New(rules), cat, store.NewMemoryStore(), q, gk, nil,
		Options{Clock: clock.now})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	ip := "203.0.113.41"
	seq := banGradeSequence(ip, frozenMs)
	for i := 0; i < 2; i++ {
		d := svc.Decide(seq[i])
		if d.ReasonCode == model.FailOpenReason {
			t.Fatalf("request %d failed open inside the budget", i+1)
		}
	}
	d := svc.Decide(seq[2])
	if !reflect.DeepEqual(d, model.FailOpen()) {
		t.Fatalf("decision = %+v, want the fail-open decision after the enforcement overrun", d)
	}
	if got := q.Len(); got != 2 {
		t.Fatalf("queue holds %d events, want 2 (the discarded decision emits none)", got)
	}
	if _, ok := gk.IsBanned(ip, frozenMs+1); !ok {
		t.Fatal("the overrun discarded the decision's ban bookkeeping, want it persisted")
	}
}

func TestDecideQueueNilNeverBlocksOrPanics(t *testing.T) {
	// A look-mode service without a queue decides normally: no emission,
	// no blocking, no panic. Nil queues are a wiring error only in the
	// modes that must record verdicts (asserted in TestNewValidation).
	rules, cat := loadTestRules(t)
	cfg := testConfig(t, config.ModeLook)
	svc, err := New(cfg, detect.New(rules), cat, store.NewMemoryStore(), nil, nil, nil, Options{})
	if err != nil {
		t.Fatalf("new service with nil queue in look mode: %v", err)
	}
	d := svc.Decide(cleanRequest("203.0.113.42", frozenMs))
	if d.Verdict != model.VerdictObserve || d.Action != model.ActionPass {
		t.Fatalf("decision = %s/%s, want observe/pass", d.Verdict, d.Action)
	}
	// Stop with no queue and no Start is still a graceful no-op.
	if err := svc.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

func TestDecideFullQueueDropsNeverBlocks(t *testing.T) {
	// A full queue drops the newest event and counts it (I3): Decide
	// returns the engine's decision, unblocked, and the drop shows up in
	// the queue's counter — never as an error to the request.
	rules, cat := loadTestRules(t)
	cfg := testConfig(t, config.ModeLook)
	q := events.NewQueue(100) // the minimum capacity
	svc, err := New(cfg, detect.New(rules), cat, store.NewMemoryStore(), q, nil, nil, Options{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	for i := 0; i < 100; i++ {
		d := svc.Decide(cleanRequest("203.0.113.43", frozenMs+int64(i)))
		if d.Action != model.ActionPass {
			t.Fatalf("decision %d action = %q, want pass", i+1, d.Action)
		}
	}
	if got := q.Len(); got != 100 {
		t.Fatalf("queue holds %d events, want 100 (at capacity)", got)
	}
	d := svc.Decide(cleanRequest("203.0.113.43", frozenMs+100))
	if d.Verdict != model.VerdictObserve || d.Action != model.ActionPass {
		t.Fatalf("decision over a full queue = %s/%s, want observe/pass", d.Verdict, d.Action)
	}
	if got := q.Dropped(); got != 1 {
		t.Fatalf("queue dropped %d events, want 1 (counted, not returned)", got)
	}
	if got := q.Len(); got != 100 {
		t.Fatalf("queue holds %d events after the drop, want still 100", got)
	}
}

// failingStore wraps a memory store whose AppendEvent always fails: the
// drainer's error leg, exercised without a real broken disk.
type failingStore struct {
	store.Store
}

func (f *failingStore) AppendEvent(_ context.Context, _ model.Event) error {
	return errors.New("store down")
}

func TestStopDegradesWhenStoreFails(t *testing.T) {
	// Drainer failures are logged and counted, never surfaced: Stop still
	// returns nil, and the events it could not persist leave the queue
	// (a drained drop beats a blocked shutdown, I1's spirit).
	rules, cat := loadTestRules(t)
	cfg := testConfig(t, config.ModeLook)
	q := events.NewQueue(events.DefaultQueueCapacity)
	svc, err := New(cfg, detect.New(rules), cat, &failingStore{Store: store.NewMemoryStore()}, q, nil, nil, Options{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	svc.Start(context.Background())
	for i := 0; i < 3; i++ {
		svc.Decide(cleanRequest("203.0.113.44", frozenMs+int64(i)))
	}
	if err := svc.Stop(context.Background()); err != nil {
		t.Fatalf("stop with a failing store = %v, want nil (degrade, do not error)", err)
	}
	if err := svc.Stop(context.Background()); err != nil {
		t.Fatalf("second stop = %v, want nil (idempotent)", err)
	}
	if got := q.Len(); got != 0 {
		t.Fatalf("queue holds %d events after stop, want 0 (drained despite the failures)", got)
	}
}

func TestNewValidation(t *testing.T) {
	// Boot fails closed (I1's twin: wiring errors surface at New, not at
	// request time). The nil-ness rules are the mode's shape: the catalog
	// and the queue are required wherever decoys are served or verdicts
	// must be recorded; the gatekeeper is required wherever bans live.
	rules, cat := loadTestRules(t)
	eng := detect.New(rules)
	st := store.NewMemoryStore()
	q := events.NewQueue(events.DefaultQueueCapacity)
	gk := enforce.NewGatekeeper(enforce.Budgets{MaxBansPerMinute: 10, MaxConcurrentBans: 10}, nil)
	look := testConfig(t, config.ModeLook)
	trip := testConfig(t, config.ModeTripwires)
	prot := testConfig(t, config.ModeProtect, func(c *config.Config) { c.Enforcement.Enabled = true })

	cases := []struct {
		name string
		cfg  *config.Config
		eng  *detect.Engine
		cat  *decoy.Catalog
		st   store.Store
		q    *events.Queue
		gk   *enforce.Gatekeeper
		want string
	}{
		{"nil config", nil, eng, cat, st, q, gk, "config"},
		{"nil engine", look, nil, cat, st, q, gk, "engine"},
		{"nil store", look, eng, cat, nil, q, gk, "store"},
		// An unvalidated config is the only way an unknown mode reaches
		// New; testConfig would have rejected it in Validate.
		{"unknown mode", func() *config.Config {
			c := config.Default()
			c.Mode = "sideways"
			c.DashboardToken = testToken
			return c
		}(), eng, cat, st, q, gk, "mode"},
		{"empty token", func() *config.Config {
			c := testConfig(t, config.ModeLook)
			c.DashboardToken = ""
			return c
		}(), eng, cat, st, q, gk, "token"},
		{"no catalog in tripwires", trip, eng, nil, st, q, gk, "catalog"},
		{"no catalog in protect", prot, eng, nil, st, q, gk, "catalog"},
		{"no queue in tripwires", trip, eng, cat, st, nil, gk, "queue"},
		{"no queue in protect", prot, eng, cat, st, nil, gk, "queue"},
		{"no gatekeeper in protect", prot, eng, cat, st, q, nil, "gatekeeper"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg, tc.eng, tc.cat, tc.st, tc.q, tc.gk, nil, Options{})
			if err == nil {
				t.Fatal("New accepted invalid wiring, want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to name %q", err, tc.want)
			}
		})
	}

	// The legal minimal shapes: look mode may drop catalog, queue and
	// gatekeeper; tripwires and protect require their pieces.
	if _, err := New(look, eng, nil, st, nil, nil, nil, Options{}); err != nil {
		t.Fatalf("look mode without catalog/queue/gatekeeper: %v", err)
	}
	if _, err := New(trip, eng, cat, st, q, nil, nil, Options{}); err != nil {
		t.Fatalf("tripwires mode without gatekeeper: %v", err)
	}
	if _, err := New(prot, eng, cat, st, q, gk, nil, Options{}); err != nil {
		t.Fatalf("protect mode without connectors: %v", err)
	}
}

func TestServeDecoyFailsOpenToOrigin(t *testing.T) {
	// Every ServeDecoy error tells the caller to serve the origin (I1):
	// no catalog (look mode), no decoy id, no session key, an unknown id.
	rules, _ := loadTestRules(t)
	look, err := New(testConfig(t, config.ModeLook), detect.New(rules), nil,
		store.NewMemoryStore(), nil, nil, nil, Options{})
	if err != nil {
		t.Fatalf("new look service: %v", err)
	}
	if _, err := look.ServeDecoy(model.Decision{DecoyID: "env-file-staging", SessionKey: "k"}); err == nil {
		t.Fatal("serve without a catalog succeeded, want an error")
	}

	h := newHarness(t, config.ModeTripwires, nil)
	d := h.svc.Decide(model.Request{
		Method: "GET", Path: "/.env", ClientIP: "203.0.113.45",
		UserAgent: browserUA, HeaderCount: 8, TsMs: frozenMs,
	})
	if d.DecoyID == "" {
		t.Fatal("decoy_route decision carries no decoy id")
	}
	bad := []model.Decision{
		{},                         // no id at all
		{SessionKey: d.SessionKey}, // empty id
		{DecoyID: d.DecoyID},       // empty session key
		{DecoyID: "no-such-decoy", SessionKey: d.SessionKey}, // unknown id
	}
	for i, b := range bad {
		if _, err := h.svc.ServeDecoy(b); err == nil {
			t.Errorf("ServeDecoy case %d succeeded, want an error (serve the origin)", i)
		}
	}
	if _, err := h.svc.ServeDecoy(d); err != nil {
		t.Errorf("ServeDecoy on a fresh decoy_route decision: %v", err)
	}
}

func TestDecideIsConcurrencySafe(t *testing.T) {
	// The engine is internally locked and every service-owned structure
	// carries its own mutex: hammering Decide from many goroutines must be
	// race-clean and every answer well-formed (run under -race).
	h := newHarness(t, config.ModeProtect, nil)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		ip := fmt.Sprintf("203.0.113.%d", 50+w) // reserved documentation range
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				d := h.svc.Decide(model.Request{
					Method: "GET", Path: "/.env", ClientIP: ip,
					UserAgent: browserUA, HeaderCount: 8, TsMs: frozenMs + int64(i),
				})
				if d.ProtocolVersion != model.ProtocolVersion {
					t.Errorf("decision lost its protocol version: %+v", d)
				}
			}
		}()
	}
	wg.Wait()
}
