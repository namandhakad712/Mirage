// Package service is Mirage Core's orchestration layer: it wires the
// detection engine, the decoy catalog, the event queue, the store, the
// gatekeeper and the enforcement connectors into the single decision path
// defined by spec/ADAPTER-PROTOCOL.md, drains the event queue into the store
// in the background, and serves the token-guarded dashboard API.
//
// The layer exists to hold the invariants no single package can enforce
// alone:
//
//   - I1 fail-open: Decide measures itself against the decision budget and
//     returns the reserved fail-open decision on overrun; a slow or broken
//     store or connector never fails a request.
//   - I3 hot path is local: Decide touches in-memory state only, with one
//     deliberate exception — the per-ban record upsert, bounded by the ban
//     budgets to a handful of rows per minute and guarded by the deadline
//     check that follows it.
//   - I9 observe by default: enforcement actions exist only in protect mode
//     with the opt-in block and the kill switch clear; every other mode
//     records verdicts but acts only on decoys.
//   - I10 everything is explainable: every decision, ban renewals included,
//     leaves as an event carrying its reason code, verdict and score.
//
// A Service is safe for concurrent use: the engine is internally locked and
// every service-owned structure carries its own mutex. Start and Stop are
// each idempotent and may be called from any goroutine.
package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
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

// connectorApplyTimeout bounds the asynchronous connector fan-out. Five
// seconds is generous for a provider call and short enough that a wedged
// provider cannot pile up goroutines for long after the request that
// spawned them is forgotten.
const connectorApplyTimeout = 5 * time.Second

// renewalEntry remembers why an address was banned. The gatekeeper's own
// records carry no reason codes (its RecordBan signature is reason-free by
// contract), but the renewal decision must report the ORIGINAL reason, not
// a rescore. expiresAtMs mirrors the gatekeeper record written in the same
// step — this Service is the gatekeeper's single writer — and is kept only
// to prune the memo; the live remaining TTL always comes from the
// gatekeeper, the one authority on what is still active.
type renewalEntry struct {
	reason      string
	expiresAtMs int64
}

// maxRenewalEntries bounds the renewal memo. One entry per banned address
// sits far below this under the default budgets (MaxConcurrentBans 100);
// the cap exists so runaway budgets or an out-of-band gatekeeper writer
// cannot grow the map without bound. Expired entries are dropped first; if
// every entry is live, the soonest-expiring one drops and its renewal
// degrades to engine scoring until the ban lapses — enforcement for the
// address still holds through every other request path.
const maxRenewalEntries = 4096

// Service is Mirage Core wired into the single decision path: one
// synchronous Decide per request, one asynchronous event per decision, one
// drainer between the queue and the store, and one dashboard on top.
type Service struct {
	// Immutable after New: the decision path reads these without locks.

	cfg *config.Config      // validated by the caller (Load/Validate); read-only here
	eng *detect.Engine      // internally locked; the scoring authority
	cat *decoy.Catalog      // nil only in look mode (ServeDecoy then errors, I1)
	st  store.Store         // events, summaries, ban records; caller owns Close
	q   *events.Queue       // nil only in look mode; TryEmit never blocks (I3)
	gk  *enforce.Gatekeeper // nil outside protect mode (I9)
	cs  []connectors.Connector

	clock    func() int64 // decision clock, Unix ms (Options.Clock)
	budgetMs int64        // decision budget (Options.DecideBudgetMs)

	// renewals memoizes ip -> the original reason of the active ban, so the
	// renewal path can answer without the engine. Guarded by renewMu.
	renewMu  sync.Mutex
	renewals map[string]renewalEntry

	// Lifecycle of the background loops; see drainer.go.
	lifeMu      sync.Mutex
	running     bool
	stopCh      chan struct{}
	genWg       *sync.WaitGroup
	startedAtMs int64

	// summaries is the bounded rolling per-session aggregate the drainer
	// keeps in memory and upserts to the store; see drainer.go.
	sumMu     sync.Mutex
	summaries map[string]*summaryEntry

	// health is the last observed health of every connector; see drainer.go.
	healthMu sync.Mutex
	health   []connectorHealth
}

// New wires the core packages into the decision path and the dashboard. The
// caller keeps ownership of every argument: the Service never closes the
// store (its owner does at shutdown) and never mutates the config. cfg must
// have passed config.Validate — New re-checks only what the decision path
// cannot survive without.
//
// Nil-ness rules, decided for the modes that actually use each component:
//
//   - cfg, eng and st must never be nil: every decision reads the config,
//     every decision scores, and the dashboard reads the store in every
//     mode.
//   - cat may be nil only in look mode: there the verdict is capped at tag
//     and no decoy is ever served (ServeDecoy then errors and the caller
//     serves the origin, I1). Tripwires and protect can serve decoys, so
//     they require the catalog.
//   - gk may be nil outside protect mode: ban enforcement and renewal
//     exist nowhere else (I9). Protect mode requires it.
//   - q may be nil only in look mode, where nothing beyond observe needs
//     recording. Tripwires and protect record verdicts that must reach the
//     store (I10), so a missing queue there is a wiring error, not a
//     choice: events silently vanishing would gut the evidence trail.
//   - cs may be nil or empty in any mode. Connectors are optional external
//     integrations — the edge enforces the ban action itself — so protect
//     mode without connectors is a valid local-enforcement deployment: bans
//     still gate renewals, persist as records and show on the dashboard,
//     and the reconcile loop simply has nothing to sync.
func New(cfg *config.Config, eng *detect.Engine, cat *decoy.Catalog, st store.Store,
	q *events.Queue, gk *enforce.Gatekeeper, cs []connectors.Connector, opts Options) (*Service, error) {
	if cfg == nil {
		return nil, errors.New("service: config must not be nil")
	}
	if eng == nil {
		return nil, errors.New("service: engine must not be nil")
	}
	if st == nil {
		return nil, errors.New("service: store must not be nil")
	}
	switch cfg.Mode {
	case config.ModeLook, config.ModeTripwires, config.ModeProtect:
	default:
		return nil, fmt.Errorf("service: mode %q is not one of %q, %q or %q (config.Validate should have caught this)",
			cfg.Mode, config.ModeLook, config.ModeTripwires, config.ModeProtect)
	}
	// The dashboard requires a token even on loopback (config.Validate
	// enforces the same rule); an empty token here would silently turn the
	// whole dashboard into a 403 wall, which is fail-safe but not a
	// service. Fail at boot instead (I1's boot-time twin: fail closed).
	if strings.TrimSpace(cfg.DashboardToken) == "" {
		return nil, errors.New("service: config.DashboardToken must not be empty: the dashboard requires a token even on loopback")
	}
	switch cfg.Mode {
	case config.ModeTripwires, config.ModeProtect:
		if cat == nil {
			return nil, fmt.Errorf("service: decoy catalog is required in %q mode (decoy_route decisions must render)", cfg.Mode)
		}
		if q == nil {
			return nil, fmt.Errorf("service: event queue is required in %q mode (recorded verdicts must reach the store, I10)", cfg.Mode)
		}
	}
	if cfg.Mode == config.ModeProtect && gk == nil {
		return nil, errors.New("service: gatekeeper is required in protect mode (ban enforcement and renewal)")
	}

	var health []connectorHealth
	for _, c := range cs {
		health = append(health, connectorHealth{Name: c.Name()})
	}
	return &Service{
		cfg:       cfg,
		eng:       eng,
		cat:       cat,
		st:        st,
		q:         q,
		gk:        gk,
		cs:        cs,
		clock:     opts.clockOrDefault(),
		budgetMs:  opts.budgetOrDefault(),
		renewals:  make(map[string]renewalEntry),
		summaries: make(map[string]*summaryEntry),
		health:    health,
	}, nil
}

// Decide is THE hot path (spec/ADAPTER-PROTOCOL.md sections 1-3): it
// scores one request and returns the action the adapter must take. The
// sequence is fixed and every step is ordered for a reason:
//
//  1. start := clock(); the whole decision is timestamped once, so the
//     deadline arithmetic, the ban bookkeeping and the store records agree.
//  2. Never-scored resolution (I6): owner, CDN and allowlisted-bot ranges
//     produce observe decisions with no session state.
//  3. Active-ban renewal (protect only, enforcement armed): a request from
//     an address with an unexpired ban renews it — action ban, the
//     ORIGINAL reason code, the remaining TTL, request score 0, score 0,
//     no signals — without rescoring. A banned address must not earn its
//     way out of the ban with clean-looking requests. The event is
//     emitted; this path performs no engine call and no store write.
//  4. The engine scores the request, deterministically, in memory (I3).
//  5. Deadline check: an overrun past the budget returns model.FailOpen()
//     with NO event — SIG-000 is reserved for fail-open and must never
//     become ban input (ADAPTER-PROTOCOL section 3).
//  6. Mode gating (I9): look caps the verdict at tag and passes;
//     tripwires serves decoys but passes throttle/ban; protect enforces,
//     and the ban action goes through the gatekeeper.
//  7. Deadline check again, after enforcement wiring; on overrun the
//     decision is discarded entirely (the ban bookkeeping already done
//     persists; the adapter sees the fail-open decision).
//  8. Event emission (I3): TryEmit never blocks; a full queue drops the
//     event and counts the drop — losing evidence is always better than
//     stalling a request.
func (s *Service) Decide(req model.Request) model.Decision {
	start := s.clock()
	allowlisted := model.NeverScored(req.ClientIP, s.cfg.OwnerRanges())

	// Renewal (protect, enforcement armed, not never-scored: a
	// never-scored address is never banned, I15, so it has nothing to
	// renew). The kill switch disarms renewal too: with enforcement off,
	// an existing ban must stop answering, or the switch would take up to
	// a full TTL to actually stop enforcement (I9).
	if s.cfg.Mode == config.ModeProtect && s.cfg.EnforcementAllowed() && !allowlisted {
		if d, ok := s.renewal(req, start); ok {
			s.emit(req, d)
			return d
		}
	}

	d := s.eng.Decide(req, allowlisted)

	// Deadline check #1 (I1, ADAPTER-PROTOCOL section 2): the engine is
	// the only non-trivial step before gating; if even it overran the
	// budget, the decision is discarded before any wiring can extend the
	// damage.
	if s.clock()-start > s.budgetMs {
		return model.FailOpen()
	}

	switch s.cfg.Mode {
	case config.ModeLook:
		observeOnly(&d)
	case config.ModeTripwires:
		tripwires(&d)
	case config.ModeProtect:
		if !s.cfg.EnforcementAllowed() {
			// Not opted in, or the kill switch is engaged (I9). The
			// re-check on every decision is what makes flipping the
			// switch take effect immediately (config.EnforcementAllowed).
			disarm(&d)
		} else if d.Action == model.ActionBan {
			s.enforceBan(&d, req, start)
		}
	}

	// Deadline check #2: the enforcement wiring (gatekeeper, record upsert)
	// is the only step that can still spend time. On overrun the decision
	// is discarded — no event, fail-open answer — while the ban state it
	// recorded stays: the next request from the address renews it.
	if s.clock()-start > s.budgetMs {
		return model.FailOpen()
	}

	s.emit(req, d)
	return d
}

// observeOnly applies look mode (I9): the verdict is capped at tag — look
// mode records, it never routes, throttles or bans — and the action always
// passes. The cap is honest about what the adapter may do: no decoy is
// named and no TTL is proposed when nothing will be served or enforced. The
// signals, scores and reason code survive the cap: the event keeps the
// evidence (I10).
func observeOnly(d *model.Decision) {
	switch d.Verdict {
	case model.VerdictDecoyRoute, model.VerdictThrottle, model.VerdictBan:
		d.Verdict = model.VerdictTag
		d.DecoyID = ""
		d.BanTTLms = nil
	}
	d.Action = model.ActionPass
}

// tripwires applies tripwires mode: decoy_route keeps serve_decoy — the
// decoys ARE the tripwires — while throttle and ban verdicts stay recorded
// but their actions pass. Mirage baits and observes; it does not touch the
// traffic.
func tripwires(d *model.Decision) {
	if d.Action != model.ActionServeDecoy {
		d.Action = model.ActionPass
	}
}

// disarm applies protect mode without enforcement (no opt-in block, or the
// kill switch engaged — I9). The action set matches tripwires: verdicts
// stay recorded with their TTLs, throttle and ban actions pass, and decoys
// keep serving — decoys are tripwires, not enforcement.
func disarm(d *model.Decision) {
	if d.Action == model.ActionThrottle || d.Action == model.ActionBan {
		d.Action = model.ActionPass
	}
}

// renewal returns the renewal decision for an address holding an active
// ban. The decision is verdict ban, action ban, the ORIGINAL reason code,
// the remaining TTL, request score 0, score 0 and no signals — the evidence
// was earned by the request that banned the address, and renewal cites it
// rather than re-earning it (I5, I10).
func (s *Service) renewal(req model.Request, nowMs int64) (model.Decision, bool) {
	expiresAt, banned := s.gk.IsBanned(req.ClientIP, nowMs)
	if !banned {
		return model.Decision{}, false
	}
	reason, ok := s.renewalReason(req.ClientIP)
	if !ok {
		// The gatekeeper holds a ban this service never recorded — it is
		// the single writer by construction, so this cannot happen through
		// the public surface. Scoring normally is the honest fallback: an
		// invented reason code would be worse evidence than a rescore.
		return model.Decision{}, false
	}
	remaining := expiresAt - nowMs
	if remaining < 0 {
		remaining = 0
	}
	d := model.Decision{
		ProtocolVersion: model.ProtocolVersion,
		SpecVersion:     model.SpecVersion,
		Verdict:         model.VerdictBan,
		Action:          model.ActionBan,
		SessionKey:      model.SessionKey(req.ClientIP),
		ReasonCode:      reason,
		RequestScore:    0,
		Score:           0,
		Signals:         []string{},
		BanTTLms:        &remaining,
	}
	return d, true
}

// renewalReason returns the recorded reason of the address's active ban.
func (s *Service) renewalReason(ip string) (string, bool) {
	s.renewMu.Lock()
	defer s.renewMu.Unlock()
	e, ok := s.renewals[ip]
	if !ok {
		return "", false
	}
	return e.reason, true
}

// recordRenewal memoizes the reason of a freshly applied ban. The entry is
// written in the same step as the gatekeeper record it mirrors; both are
// in-memory with the same process lifetime.
func (s *Service) recordRenewal(ip, reason string, expiresAtMs, nowMs int64) {
	s.renewMu.Lock()
	defer s.renewMu.Unlock()
	if len(s.renewals) >= maxRenewalEntries {
		// Expired entries go first: they can no longer renew anything.
		for k, e := range s.renewals {
			if e.expiresAtMs <= nowMs {
				delete(s.renewals, k)
			}
		}
		// Still full: every entry is live. Drop the soonest-expiring one —
		// its renewal degrades to engine scoring, which is a slowdown, not
		// a hole: the gatekeeper still holds the ban.
		if len(s.renewals) >= maxRenewalEntries {
			victim, oldest := "", int64(0)
			for k, e := range s.renewals {
				if victim == "" || e.expiresAtMs < oldest {
					victim, oldest = k, e.expiresAtMs
				}
			}
			delete(s.renewals, victim)
		}
	}
	s.renewals[ip] = renewalEntry{reason: reason, expiresAtMs: expiresAtMs}
}

// dropRenewal forgets the memoized reason, after a one-click reversal: the
// gatekeeper ban is expired by then, so the entry is dead weight until it
// is overwritten.
func (s *Service) dropRenewal(ip string) {
	s.renewMu.Lock()
	defer s.renewMu.Unlock()
	delete(s.renewals, ip)
}

// enforceBan wires one ban action through the gatekeeper (I5, I15). The
// verdict stays recorded whatever the outcome; only the action can change,
// and only downward — a ban that is denied or budget-capped degrades to
// pass, never the other way.
func (s *Service) enforceBan(d *model.Decision, req model.Request, nowMs int64) {
	switch s.gk.Evaluate(req.ClientIP, nowMs) {
	case enforce.OutcomeDeny:
		// Never-ban list (I15): private, CGNAT, loopback, link-local and
		// owner ranges are never banned, whatever the engine says.
		d.Action = model.ActionPass
	case enforce.OutcomeObserve:
		// Budget cap (I5): the proposal drops to observe; the request is
		// still recorded upstream, and the reconcile loop will remove any
		// stale provider ban.
		d.Action = model.ActionPass
	case enforce.OutcomeAllow:
		s.applyBan(d, req, nowMs)
	}
}

// applyBan makes an approved ban real, in the order the renewal path reads
// it back: the gatekeeper first (renewal asks it), then the reason memo,
// then the durable record, then the asynchronous connector fan-out.
func (s *Service) applyBan(d *model.Decision, req model.Request, nowMs int64) {
	ttl := model.BanTTL
	if d.BanTTLms != nil {
		ttl = *d.BanTTLms
	}
	expiresAt := nowMs + ttl

	s.gk.RecordBan(req.ClientIP, nowMs, expiresAt)
	s.recordRenewal(req.ClientIP, d.ReasonCode, expiresAt, nowMs)

	rec := store.BanRecord{
		IP:          req.ClientIP,
		Reason:      d.ReasonCode,
		CreatedAtMs: nowMs,
		ExpiresAtMs: expiresAt,
		Note:        fmt.Sprintf("verdict=ban score=%d session=%s", d.Score, d.SessionKey),
		Active:      true,
	}
	// The one deliberate synchronous store write on the decision path: the
	// ban budgets cap it at a handful of rows per minute, so the evidence
	// is durable before the decision returns (I10) without threatening the
	// latency budget of ordinary traffic (I3). A store failure is logged
	// and swallowed: the gatekeeper already holds the ban, and the next
	// request renews it — the request itself must never fail (I1).
	if err := s.st.UpsertBanRecord(context.Background(), rec); err != nil {
		log.Printf("service: record ban %s: %v", req.ClientIP, err)
	}
	s.fanOutBan(rec)
}

// fanOutBan hands an applied ban to every connector on a dedicated goroutine
// (ADAPTER-PROTOCOL section 1: the enforcement half is asynchronous and
// bounded). The goroutine is fire-and-forget by design — a slow provider
// must never hold the request (I1, I3) — and every error is logged and
// forgotten: a failed Apply is healed by the reconcile loop, which removes
// provider bans that no longer match the store's active set.
func (s *Service) fanOutBan(rec store.BanRecord) {
	if len(s.cs) == 0 {
		return
	}
	b := connectors.Ban{
		IP:          rec.IP,
		Reason:      rec.Reason,
		Note:        rec.Note,
		CreatedAtMs: rec.CreatedAtMs,
		ExpiresAtMs: rec.ExpiresAtMs,
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), connectorApplyTimeout)
		defer cancel()
		for _, c := range s.cs {
			if err := c.Apply(ctx, b); err != nil {
				log.Printf("service: connector %s: apply ban %s: %v", c.Name(), rec.IP, err)
			}
		}
	}()
}

// ServeDecoy renders the decoy a decoy_route decision named, for the session
// it was decided for. It is deterministic and side-effect free — a pure
// catalog render, never a network fetch (I3, ADAPTER-PROTOCOL section 3) —
// so the same session always receives byte-identical bodies and any
// session can be reproduced later for evidence (I10). Any error — no
// catalog (look mode), an empty or unknown decoy id, a missing session key —
// tells the caller to serve the origin instead (I1: fail-open).
func (s *Service) ServeDecoy(d model.Decision) (decoy.Rendered, error) {
	if s.cat == nil {
		return decoy.Rendered{}, errors.New("service: no decoy catalog loaded")
	}
	if d.DecoyID == "" {
		return decoy.Rendered{}, errors.New("service: decision carries no decoy id")
	}
	if d.SessionKey == "" {
		// Rendering against an empty key would mint tokens attributable to
		// the empty session — corrupted evidence (I10). Fail to origin.
		return decoy.Rendered{}, errors.New("service: decision carries no session key")
	}
	// Catalogs are small (v1 ships six entries), so a linear scan beats a
	// map copy that could drift from the slice — the same trade the
	// catalog's own ByPath makes.
	for _, e := range s.cat.Entries {
		if e.ID == d.DecoyID {
			return s.cat.Render(e, d.SessionKey)
		}
	}
	return decoy.Rendered{}, fmt.Errorf("service: unknown decoy id %q", d.DecoyID)
}

// emit queues the decision event (I3, ADAPTER-PROTOCOL section 4). TryEmit
// never blocks; a full queue drops THIS event (the newest, not the queued
// history) and counts the drop — losing an event is always better than
// stalling a request. No queue (look mode without events) is a documented
// no-op.
func (s *Service) emit(req model.Request, d model.Decision) {
	if s.q == nil {
		return
	}
	s.q.TryEmit(model.Event{
		ProtocolVersion: model.ProtocolVersion,
		TsMs:            req.TsMs,
		SessionKey:      d.SessionKey,
		ClientIP:        req.ClientIP,
		Method:          req.Method,
		Path:            req.Path,
		Decision:        &d,
	})
}
