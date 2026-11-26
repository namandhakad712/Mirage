// Package enforce is the last line of defense between a ban verdict and
// the enforcement connectors. Nothing reaches a connector before the
// gatekeeper has approved it (I5: bans are earned, budget-capped and
// reversible), and while the global kill switch is engaged nothing is
// enforced at all (I9: observe by default).
//
// The package is pure logic: no I/O and no clocks of its own. Every
// time-sensitive rule takes nowMs from the caller, so behavior is
// deterministic under test and reproducible from an event log.
package enforce

import (
	"net/netip"
	"sync"

	"github.com/mirage-shield/mirage/internal/model"
)

// windowMs is the trailing window for the per-minute ban budget.
const windowMs int64 = 60_000

// Outcome is the gatekeeper's verdict for one proposed ban.
type Outcome int

const (
	// OutcomeAllow approves the ban: the caller may hand it to a
	// connector and must then RecordBan it.
	OutcomeAllow Outcome = iota
	// OutcomeDeny refuses the ban outright because the address is on
	// the never-ban list (I15). Deny is a hard stop: no budget, retry
	// or override turns it into an allow.
	OutcomeDeny
	// OutcomeObserve drops this decision to observe because an
	// operational budget was exceeded (design section 5: exceeding a
	// budget drops the site to Observe automatically). Enforcement is
	// skipped; the request itself is still recorded upstream.
	OutcomeObserve
)

// String renders the outcome for logs and dashboards.
func (o Outcome) String() string {
	switch o {
	case OutcomeAllow:
		return "allow"
	case OutcomeDeny:
		return "deny"
	case OutcomeObserve:
		return "observe"
	default:
		return "unknown"
	}
}

// Budgets caps what enforcement may do in a period (design section 5).
// They exist so a bug, a false-positive storm or an attack on Mirage
// cannot turn the tool into a self-inflicted outage.
//
// A non-positive MaxBansPerMinute or MaxConcurrentBans is a ZERO cap,
// not an unlimited one: every proposal drops to observe. That is the
// fail-safe reading of an unset budget (I9).
//
// MaxSharePct is deliberately not enforced in this package:
// share-of-traffic needs request counts only the service layer has. The
// gatekeeper stores and exposes the budget (see MaxSharePct); the
// service layer applies it.
type Budgets struct {
	MaxBansPerMinute  int
	MaxConcurrentBans int
	MaxSharePct       int
}

// ban is one recorded, applied ban: when it was recorded (feeds the
// per-minute window) and when it expires (feeds the concurrency cap).
type ban struct {
	ip          string
	atMs        int64
	expiresAtMs int64
}

// Gatekeeper guards the two operational ban budgets and the never-ban
// list. It is the component a ban must pass AFTER the engine decided it
// and BEFORE any connector is called — the engine scores single
// requests, the gatekeeper sees the fleet-wide picture.
//
// State is in-memory by design: counters reset on restart, which
// re-arms the budgets. The event store owns history; the gatekeeper
// only needs the live window.
type Gatekeeper struct {
	mu          sync.Mutex
	budgets     Budgets
	neverBanned []netip.Prefix
	bans        []ban
}

// NewGatekeeper builds a gatekeeper. neverBannedRanges are the owner's
// never-ban ranges (own IPs, CDN and load balancer ranges); the model
// package adds private, CGNAT, loopback and link-local ranges on top
// (I15). The slice is copied so a later config reload cannot mutate a
// live gatekeeper out from under it.
func NewGatekeeper(b Budgets, neverBannedRanges []netip.Prefix) *Gatekeeper {
	ranges := make([]netip.Prefix, len(neverBannedRanges))
	copy(ranges, neverBannedRanges)
	return &Gatekeeper{
		budgets:     b,
		neverBanned: ranges,
	}
}

// Evaluate rules on a proposed ban, in order:
//
//  1. Never-ban list (I15): private, CGNAT, loopback, link-local and
//     owner ranges are never banned — OutcomeDeny, whatever the budgets
//     say.
//  2. Per-minute budget: bans recorded in the trailing 60_000 ms must
//     stay below MaxBansPerMinute, else OutcomeObserve.
//  3. Concurrency cap: unexpired bans must stay below
//     MaxConcurrentBans, else OutcomeObserve.
//  4. Otherwise OutcomeAllow.
//
// An unparseable address is not on the never-ban list (model returns
// false for garbage), so it falls through to the budgets; the service
// layer is expected to send only addresses the engine scored.
func (g *Gatekeeper) Evaluate(ip string, nowMs int64) Outcome {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Rule 1 — hygiene before operations: a never-ban address is denied
	// even when the budgets would allow it.
	if model.IsNeverBanned(ip, g.neverBanned) {
		return OutcomeDeny
	}

	g.pruneLocked(nowMs)

	inWindow := 0
	active := 0
	for _, b := range g.bans {
		if b.atMs > nowMs-windowMs {
			inWindow++
		}
		if b.expiresAtMs > nowMs {
			active++
		}
	}

	// Rule 2 — rate budget. >= rather than > because the count includes
	// exactly the bans we already allowed.
	if inWindow >= g.budgets.MaxBansPerMinute {
		return OutcomeObserve
	}
	// Rule 3 — concurrency budget on unexpired bans only.
	if active >= g.budgets.MaxConcurrentBans {
		return OutcomeObserve
	}
	return OutcomeAllow
}

// RecordBan records a ban that a connector applied successfully. Call it
// AFTER Apply returns nil so the budgets count real bans, not attempts.
//
// RecordBan never refuses a recording: if a caller records a ban that
// Evaluate would have rejected, the counters only over-count, which
// fails safe (future proposals drop to observe). Under-counting is the
// dangerous direction, so there is no cap to enforce here. The one
// exception is a redelivery of the identical ban (same address, same
// expiry): a queue retry must not drain the per-minute budget twice.
func (g *Gatekeeper) RecordBan(ip string, nowMs, expiresAtMs int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked(nowMs)
	for _, b := range g.bans {
		if b.ip == ip && b.expiresAtMs == expiresAtMs {
			return // same applied ban, already counted
		}
	}
	g.bans = append(g.bans, ban{ip: ip, atMs: nowMs, expiresAtMs: expiresAtMs})
}

// IsBanned reports whether ip holds a ban still active at nowMs, returning
// the expiry of the longest-running active one. A ban that expired exactly
// at nowMs is already inactive — the same strict inequality
// store.BanRecords applies. The service layer calls this on the decision
// path to renew an active ban without rescoring: a banned address must not
// earn its way out of the ban with clean-looking requests (SIGNALS section
// 7 makes history alone unable to escalate; renewal makes it equally unable
// to de-escalate). When several bans are active for one address (re-banned
// for a different reason inside the first TTL), the longest expiry wins: the
// address stays banned as long as any recorded ban does.
func (g *Gatekeeper) IsBanned(ip string, nowMs int64) (expiresAtMs int64, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	best := int64(0)
	for _, b := range g.bans {
		if b.ip == ip && b.expiresAtMs > nowMs && b.expiresAtMs > best {
			best = b.expiresAtMs
		}
	}
	if best == 0 {
		return 0, false
	}
	return best, true
}

// RevokeBan expires every active ban for ip at nowMs — the enforcement half
// of the dashboard's one-click reversal (I5: bans are always reversible). It
// never extends a ban: an expiry at or before nowMs is left untouched, so
// the call is idempotent — revoking twice, or revoking an address that was
// never banned, changes nothing. Revocation is address-scoped because the
// gatekeeper records no reason codes; the service layer drives it after
// deactivating the store record the operator clicked.
func (g *Gatekeeper) RevokeBan(ip string, nowMs int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := range g.bans {
		if g.bans[i].ip == ip && g.bans[i].expiresAtMs > nowMs {
			g.bans[i].expiresAtMs = nowMs
		}
	}
}

// MaxSharePct exposes the share-of-traffic budget for the service
// layer, which is the only place with request counts. A ban covering
// more than this percentage of recent traffic must not be enforced;
// that check cannot live here (design section 5).
func (g *Gatekeeper) MaxSharePct() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.budgets.MaxSharePct
}

// pruneLocked drops records that neither fall inside the trailing
// window nor are still active. Lazy pruning keeps Evaluate and RecordBan
// proportional to the live set instead of total history.
func (g *Gatekeeper) pruneLocked(nowMs int64) {
	kept := g.bans[:0]
	for _, b := range g.bans {
		if b.atMs > nowMs-windowMs || b.expiresAtMs > nowMs {
			kept = append(kept, b)
		}
	}
	g.bans = kept
}
