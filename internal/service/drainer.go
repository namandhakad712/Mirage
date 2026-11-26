package service

import (
	"context"
	"log"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mirage-shield/mirage/internal/connectors"
	"github.com/mirage-shield/mirage/internal/model"
	"github.com/mirage-shield/mirage/internal/store"
)

// Background loop periods and bounds. The drainer owns everything between
// the queue and the store; the reconcile loop owns the connectors' view of
// the world. Neither may block Decide, which is why both run off the hot
// path (I3) and both tolerate their own failures (I1).
const (
	// drainInterval is the drainer tick: every 250 ms the queue is drained
	// into the store, in bounded chunks, until empty.
	drainInterval = 250 * time.Millisecond

	// drainBatch bounds one Drain call: it caps the per-tick memory spike
	// and the store write burst; 512 per tick clears a sustained 2 048
	// decisions per second, far above the traffic a single Mirage Core is
	// meant to score.
	drainBatch = 512

	// reconcileInterval is the reconcile tick: every 30 s the connectors
	// see the store's active ban set, so a missed or crashed Apply heals
	// within half a minute and a revoked ban disappears from providers in
	// the same window (I5's reversibility half).
	reconcileInterval = 30 * time.Second

	// reconcileLimit bounds the active-ban read feeding reconciliation.
	// Ban budgets keep concurrent bans far below it; the bound exists so a
	// runaway ban table cannot turn one dashboard tick into a full scan.
	reconcileLimit = store.MaxLimit

	// healthTimeout bounds one connector health probe so a wedged
	// provider cannot stall the reconcile loop for the healthy ones.
	healthTimeout = 5 * time.Second

	// maxHealthErrLen caps the error text carried on /api/status (I7: even
	// operational output is length-capped when it may carry provider text).
	maxHealthErrLen = 200

	// maxRollingSessions bounds the in-memory per-session summaries at
	// 65 536. Sessions beyond the bound evict the least-recently-seen one,
	// and the dashboard's per-session counters for an evicted session
	// restart from zero when its address returns — the documented
	// approximation: the store keeps every event (I10), so the session's
	// history is never lost, only the running aggregate is folded fresh.
	maxRollingSessions = 65536
)

// summaryEntry is one rolling per-session summary plus the drain time that
// drives eviction. The drain clock — not the adapter-supplied event
// timestamp, which is attacker-adjacent and may skew (I7) — defines
// "recently seen".
type summaryEntry struct {
	sum        store.SessionSummary
	lastSeenMs int64
}

// connectorHealth is the dashboard's honest view of one connector: its
// name, whether the last health probe passed, when that was (0 = never
// probed; the reconcile loop probes every 30 s while running), and the
// bounded error text of the last failure.
type connectorHealth struct {
	Name        string `json:"name"`
	Healthy     bool   `json:"healthy"`
	CheckedAtMs int64  `json:"checked_at_ms"`
	LastError   string `json:"last_error,omitempty"`
}

// Start spawns the background loops: the drainer (queue -> store events plus
// per-session rolling summaries) and the reconciler (active bans ->
// connector Reconcile plus health probes). It is idempotent and race-safe:
// a second call while running is a no-op, and Stop cancels exactly the
// generation Start spawned. ctx bounds the loops' store and connector calls
// and, like Stop, cancels the loops; with no queue (look mode) the drainer
// is not spawned at all.
func (s *Service) Start(ctx context.Context) {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	if s.running {
		return
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.startedAtMs = s.clock()
	wg := &sync.WaitGroup{}
	s.genWg = wg
	if s.q != nil {
		wg.Add(1)
		go s.drainLoop(ctx, s.stopCh, wg)
	}
	wg.Add(1)
	go s.reconcileLoop(ctx, s.stopCh, wg)
}

// Stop stops the background loops and flushes the queue into the store one
// final time. It is idempotent and race-safe: stopping a stopped service
// only re-flushes whatever was emitted since. The flush runs AFTER the
// loops exit — a flush before the loops stop could miss events an in-flight
// drain tick was still appending. Stop never closes the store (its owner
// does) and never returns an error: a store failure during the flush is
// logged and dropped — shutdown degrades, it does not error (I1's spirit).
func (s *Service) Stop(ctx context.Context) error {
	s.lifeMu.Lock()
	var wg *sync.WaitGroup
	if s.running {
		s.running = false
		close(s.stopCh)
		wg = s.genWg
		s.genWg = nil
	}
	s.lifeMu.Unlock()
	if wg != nil {
		wg.Wait()
	}
	s.flushOnce(ctx)
	return nil
}

// drainLoop persists the queue into the store on every tick until stopped.
func (s *Service) drainLoop(ctx context.Context, stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	t := time.NewTicker(drainInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.drainOnce(ctx, stop)
	}
}

// drainOnce empties the queue in bounded chunks. The chunk loop re-checks
// stop between chunks so a large backlog delays Stop by at most one chunk;
// the final flush in Stop picks up whatever remains.
func (s *Service) drainOnce(ctx context.Context, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		batch := s.q.Drain(drainBatch)
		if len(batch) == 0 {
			return
		}
		s.persistBatch(ctx, batch)
	}
}

// flushOnce is the final drain: same chunks, no stop checks — the loops are
// already down, and the queue is bounded, so the flush terminates.
func (s *Service) flushOnce(ctx context.Context) {
	if s.q == nil {
		return
	}
	for {
		batch := s.q.Drain(drainBatch)
		if len(batch) == 0 {
			return
		}
		s.persistBatch(ctx, batch)
	}
}

// persistBatch appends the batch to the store, folds each event into the
// rolling summaries and upserts every touched session once — a rolling
// aggregate needs only its final state per batch durable. A failed append is
// logged and its summary update is skipped with it, so a summary never
// references evidence that was not recorded (I10's evidence discipline).
func (s *Service) persistBatch(ctx context.Context, batch []model.Event) {
	now := s.clock()
	touched := make(map[string]store.SessionSummary, len(batch))
	for _, ev := range batch {
		if err := s.st.AppendEvent(ctx, ev); err != nil {
			log.Printf("service: drainer: append event: %v", err)
			continue
		}
		if sum, ok := s.applyEvent(ev, now); ok {
			touched[sum.SessionKey] = sum
		}
	}
	for _, sum := range touched {
		if err := s.st.UpsertSessionSummary(ctx, sum); err != nil {
			log.Printf("service: drainer: upsert session %s: %v", sum.SessionKey, err)
		}
	}
}

// applyEvent folds one drained event into the rolling summary map and
// returns the up-to-date summary for the store upsert. nowMs is the drain
// time, which — unlike the adapter-supplied event timestamp — is monotonic
// enough to drive least-recently-seen eviction. Events whose decision is
// nil (never produced by this Service; tolerated for a hand-fed queue) still
// count as requests but leave verdict and score untouched.
func (s *Service) applyEvent(ev model.Event, nowMs int64) (store.SessionSummary, bool) {
	if ev.SessionKey == "" {
		return store.SessionSummary{}, false
	}
	s.sumMu.Lock()
	defer s.sumMu.Unlock()
	e, ok := s.summaries[ev.SessionKey]
	if !ok {
		if len(s.summaries) >= maxRollingSessions {
			s.evictLeastRecentlySeenLocked()
		}
		e = &summaryEntry{
			sum: store.SessionSummary{
				SessionKey: ev.SessionKey,
				FirstTsMs:  ev.TsMs,
				IPHash:     s.ipIdent(ev.ClientIP),
			},
		}
		s.summaries[ev.SessionKey] = e
	}
	e.sum.LastTsMs = ev.TsMs
	e.sum.RequestCount++
	if ev.Decision != nil {
		// The decision's Score is the session's cumulative score AFTER the
		// request (SIGNALS section 7), so the summary mirrors the engine's
		// own accounting; renewal events carry score 0 by contract, and
		// the summary follows — a rolling aggregate, not a high-water mark.
		e.sum.Score = ev.Decision.Score
		e.sum.LastVerdict = ev.Decision.Verdict
		e.sum.LastReasonCode = ev.Decision.ReasonCode
	}
	e.lastSeenMs = nowMs
	return e.sum, true
}

// ipIdent returns the identity stored in SessionSummary.IPHash: the sha256
// hex when the site's privacy config hashes IPs, the plain IP otherwise —
// both readings are documented on store.SessionSummary.IPHash.
func (s *Service) ipIdent(ip string) string {
	if s.cfg.Store.HashIPs {
		return store.HashIP(ip)
	}
	return ip
}

// evictLeastRecentlySeenLocked drops the entry with the oldest drain time
// to make room. The O(cap) scan runs only when a NEW session pushes the map
// over its bound — the same trade the engine's session store makes (design
// section 6): at these sizes one memory pass per new session is cheaper
// than the bookkeeping of an ordered structure, until profiling says
// otherwise.
func (s *Service) evictLeastRecentlySeenLocked() {
	victim, oldest := "", int64(0)
	for k, e := range s.summaries {
		if victim == "" || e.lastSeenMs < oldest {
			victim, oldest = k, e.lastSeenMs
		}
	}
	if victim != "" {
		delete(s.summaries, victim)
	}
}

// reconcileLoop pushes the desired ban state to the connectors on every
// tick until stopped.
func (s *Service) reconcileLoop(ctx context.Context, stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	t := time.NewTicker(reconcileInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.reconcileOnce(ctx)
	}
}

// reconcileOnce shows every connector the store's active ban set and probes
// its health. A ban revoked in the store — or one that simply expired —
// disappears from the set, and the connector removes it from the provider
// on this pass; a missed or crashed Apply heals the same way (connectors
// Reconcile contract, I5). Errors are logged and ignored: reconciliation is
// self-healing by construction, and a broken connector must never stop the
// loop for the healthy ones (I1).
func (s *Service) reconcileOnce(ctx context.Context) {
	if len(s.cs) == 0 {
		return
	}
	now := s.clock()
	recs, err := s.st.BanRecords(ctx, now, reconcileLimit)
	if err != nil {
		log.Printf("service: reconcile: read ban records: %v", err)
		return
	}
	active := make([]connectors.Ban, 0, len(recs))
	for _, r := range recs {
		active = append(active, connectors.Ban{
			IP:          r.IP,
			Reason:      r.Reason,
			Note:        r.Note,
			CreatedAtMs: r.CreatedAtMs,
			ExpiresAtMs: r.ExpiresAtMs,
		})
	}
	for _, c := range s.cs {
		removed, err := c.Reconcile(ctx, active, now)
		if err != nil {
			log.Printf("service: connector %s: reconcile: %v", c.Name(), err)
			continue
		}
		log.Printf("service: connector %s: reconcile removed %d stale bans", c.Name(), removed)
	}
	for _, c := range s.cs {
		hctx, cancel := context.WithTimeout(ctx, healthTimeout)
		err := c.HealthCheck(hctx)
		cancel()
		s.noteHealth(c.Name(), err, now)
	}
}

// noteHealth records the outcome of one health probe for /api/status.
func (s *Service) noteHealth(name string, err error, nowMs int64) {
	healthy := err == nil
	lastErr := ""
	if err != nil {
		lastErr = truncateString(err.Error(), maxHealthErrLen)
	}
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	for i := range s.health {
		if s.health[i].Name == name {
			s.health[i].Healthy = healthy
			s.health[i].CheckedAtMs = nowMs
			s.health[i].LastError = lastErr
			return
		}
	}
	s.health = append(s.health, connectorHealth{Name: name, Healthy: healthy, CheckedAtMs: nowMs, LastError: lastErr})
}

// healthSnapshot copies the connector health view for /api/status.
func (s *Service) healthSnapshot() []connectorHealth {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	out := make([]connectorHealth, len(s.health))
	copy(out, s.health)
	return out
}

// truncateString caps s to n bytes at a UTF-8 rune boundary, so bounded
// operational text never ends in a half-written rune (I7: length-cap on
// render, never on evidence).
func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
