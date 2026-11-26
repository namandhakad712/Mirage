// Package detect implements Mirage's deterministic detection engine
// (spec/SIGNALS.md v1.1.0). Decide scores one request at a time against an
// in-memory, bounded session snapshot and returns a model.Decision. The
// engine never calls the network, disk or an LLM (I3), and it never
// enforces: ban and throttle verdicts are returned to the caller, and
// enforcement gating (mode opt-in, budgets, kill switch) happens upstream
// (I5, I9).
//
// This file is the line-by-line mirror target for the TypeScript worker
// port; any behavioural deviation is a parity bug caught by the golden
// vectors in spec/golden-vectors/vectors.json.
package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/mirage-shield/mirage/internal/model"
)

// Signal indices in evaluation order (SIGNALS.md section 4, table rows
// 1..11). The order is normative: a later signal may read, but never
// change, the outcome of an earlier one.
const (
	sigScannerPath = iota
	sigDecoyHit
	sigDecoyLeadFollow
	sigHoneytokenUse
	sigPathEnumeration
	sigUASuspicious
	sigUARotation
	sigNoCookiePersistence
	sigHeadersSparse
	sigUAMissing
	sigToolingCurl
	signalCount
)

// ungatingFirst is the exclusive upper bound of the ungating set: signals
// 1-5, scanner_path through path_enumeration. Only they ungate ua_rotation
// and tooling_curl; headers_sparse and every other medium signal never does
// (SIGNALS section 6; HAND-COMPUTED canon decision 1).
const ungatingFirst = sigPathEnumeration + 1

const (
	classHigh   = "high"
	classMedium = "medium"
)

// signalDef is one row of the fixed signal table (SIGNALS section 4).
type signalDef struct {
	ID     string
	Weight int
	Class  string
	Reason string
}

// signalTable is the fixed signal table, indexed by the sig* constants.
// Weight, class and reason code are normative; high classes can escalate
// and medium classes alone can never ban (I5).
var signalTable = [signalCount]signalDef{
	sigScannerPath:         {"scanner_path", 25, classHigh, "SIG-101"},
	sigDecoyHit:            {"decoy_hit", 30, classHigh, "SIG-102"},
	sigDecoyLeadFollow:     {"decoy_lead_follow", 40, classHigh, "SIG-103"},
	sigHoneytokenUse:       {"honeytoken_use", 50, classHigh, "SIG-104"},
	sigPathEnumeration:     {"path_enumeration", 25, classHigh, "SIG-105"},
	sigUASuspicious:        {"ua_suspicious", 15, classMedium, "SIG-106"},
	sigUARotation:          {"ua_rotation", 20, classMedium, "SIG-107"},
	sigNoCookiePersistence: {"no_cookie_persistence", 15, classMedium, "SIG-108"},
	sigHeadersSparse:       {"headers_sparse", 10, classMedium, "SIG-109"},
	sigUAMissing:           {"ua_missing", 10, classMedium, "SIG-110"},
	sigToolingCurl:         {"tooling_curl", 15, classMedium, "SIG-111"},
}

const (
	// defaultMaxSessions caps the in-memory session store — the "bounded
	// in-memory LRU for hot decisions" of design section 6.
	defaultMaxSessions = 50_000

	// noCookieThreshold is the request-count gate of no_cookie_persistence
	// (SIGNALS section 4.8, "Request count >= 5"). The count includes the
	// current request, so the signal fires on the 5th request at the
	// earliest (HAND-COMPUTED canon decision 5).
	noCookieThreshold = 5

	// sparseHeaderBelow is the header-count threshold of headers_sparse
	// (SIGNALS section 4.9, "header_count < 4"). The count includes Host
	// and User-Agent, so a real browser never fires it.
	sparseHeaderBelow = 4
)

// reasonNone is the reason code recorded when no signal fired. The golden
// vectors expect SIG-000 on signal-less decisions, the code model reserves
// for "nothing to report".
const reasonNone = model.FailOpenReason

// uaSample and pathSample are (value, timestamp) window entries.
type uaSample struct {
	ua string
	ts int64
}

type pathSample struct {
	path string
	ts   int64
}

// session is the per-session state of SIGNALS section 7. first_ts from the
// spec is derivable and no decision reads it, so it is not stored.
type session struct {
	lastTs       int64 // timestamp of the last scored request
	requestCount int   // scored requests in this epoch
	cumulative   int   // sum of request scores in this epoch
	cookieEver   bool  // a Cookie header was ever seen in this epoch
	uaSeen       []uaSample
	unknownPaths []pathSample
	leadsKnown   map[string]bool // lead paths of decoys served to this session
	tokensMinted []string        // honeytokens embedded in served decoys
	decoysServed map[string]bool // decoy entry ids served to this session
}

// newSession returns an empty session (first epoch).
func newSession() *session {
	return &session{
		leadsKnown:   map[string]bool{},
		decoysServed: map[string]bool{},
	}
}

// reset starts a new epoch in place (same key, all state zeroed) — SIGNALS
// section 7 expiry.
func (s *session) reset() {
	s.lastTs = 0
	s.requestCount = 0
	s.cumulative = 0
	s.cookieEver = false
	s.uaSeen = nil
	s.unknownPaths = nil
	s.leadsKnown = map[string]bool{}
	s.tokensMinted = nil
	s.decoysServed = map[string]bool{}
}

// Engine is the deterministic detection engine. It is safe for concurrent
// use; the session map is guarded by a single mutex because scoring is a
// read-modify-write of one session and must stay atomic per session.
type Engine struct {
	rules    Rules
	mu       sync.Mutex
	sessions map[string]*session
	// maxSessions caps len(sessions); the store evicts the most idle
	// session when a new one pushes it over (design section 6).
	maxSessions int
}

// New returns an Engine scoring against r, with the session store capped at
// defaultMaxSessions.
func New(r Rules) *Engine {
	return NewWithCap(r, defaultMaxSessions)
}

// NewWithCap returns an Engine whose session store is capped at cap
// sessions. Exported for tests that need a small cap; production code uses
// New. A cap below 1 is clamped to 1 so the store can always hold the
// session it is currently scoring.
func NewWithCap(r Rules, cap int) *Engine {
	if cap < 1 {
		cap = 1
	}
	r.prepare()
	return &Engine{
		rules:       r,
		sessions:    make(map[string]*session),
		maxSessions: cap,
	}
}

// Len reports the number of live sessions (test and ops hook).
func (e *Engine) Len() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.sessions)
}

// Decide scores one request (SIGNALS sections 3-8) and returns the decision.
// allowlisted marks the client IP as never-scored (owner, CDN, allowlisted
// bot — resolved by the caller); verified-bot user agents are detected here.
// Never-scored requests observe and leave session state untouched: no
// session is created or updated (I12 — bots never meet a trap).
//
// The engine trusts req.ClientIP as the identity: the adapter already
// resolved it through model.ClientIPFrom, so ForwardedFor here is
// informational only and never read (I6 — an untrusted peer cannot frame an
// innocent address).
func (e *Engine) Decide(req model.Request, allowlisted bool) model.Decision {
	key := model.SessionKey(req.ClientIP)
	ua := req.UserAgent
	ts := req.TsMs

	// Never-scored (SIGNALS section 2). No lock needed: nothing is touched.
	if allowlisted || e.rules.isVerifiedBotUA(ua) {
		return observeDecision(key)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	s, ok := e.sessions[key]
	if !ok {
		s = newSession()
		e.sessions[key] = s
	}

	// Session expiry (SIGNALS section 7): reset before scoring when the gap
	// exceeds the TTL, starting a new epoch with cumulative score 0. The
	// guard on requestCount distinguishes "no request yet" from a first
	// request at timestamp 0.
	if s.requestCount > 0 && ts-s.lastTs > e.rules.Policy.SessionTTLms {
		s.reset()
	}

	path, dotEscape := normalizePath(req.Path)
	cumBefore := s.cumulative

	// fired holds signal indices in evaluation order (section 4).
	fired := make([]int, 0, signalCount)
	fire := func(sig int) { fired = append(fired, sig) }

	// Signal 1: scanner_path (section 4.1) — scanner-list match or a ".."
	// segment clamped at the root (dot_escape).
	if e.rules.isScanner(path) || dotEscape {
		fire(sigScannerPath)
	}
	// Signal 2: decoy_hit (section 4.2) — suppressed when scanner_path
	// fired: a scanner-list hit is already fully explained.
	if _, isDecoy := e.rules.decoyAt(path); isDecoy && !hasSignal(fired, sigScannerPath) {
		fire(sigDecoyHit)
	}
	// Signal 3: decoy_lead_follow (section 4.3) — the path is a lead that
	// exists only inside a decoy served earlier to this session.
	if s.leadsKnown[path] {
		fire(sigDecoyLeadFollow)
	}
	// Signal 4: honeytoken_use (section 4.4) — credential material in the
	// request equals or embeds a honeytoken minted for this session.
	if req.AuthHint != "" {
		for _, tok := range s.tokensMinted {
			if tok != "" && (tok == req.AuthHint || strings.Contains(req.AuthHint, tok)) {
				fire(sigHoneytokenUse)
				break
			}
		}
	}
	// Signal 5: path_enumeration (section 4.5) — >= 8 distinct unknown
	// paths in the trailing 60 s, the current path counted if unknown.
	distinct := make(map[string]bool)
	for _, p := range s.unknownPaths {
		if ts-p.ts <= e.rules.Policy.EnumWindowMs {
			distinct[p.path] = true
		}
	}
	if e.rules.isUnknown(path) {
		distinct[path] = true
	}
	if len(distinct) >= e.rules.Policy.EnumThreshold {
		fire(sigPathEnumeration)
	}
	// Signal 6: ua_suspicious (section 4.6) — case-insensitive substring.
	if e.rules.isSuspiciousUA(ua) {
		fire(sigUASuspicious)
	}
	// Signal 7: ua_rotation (section 4.7, gated by section 6.2) — >= 4
	// distinct non-empty UAs in the trailing 300 s including the current
	// one, AND a same-request signal from the ungating set 1-5.
	uaSet := make(map[string]bool)
	for _, u := range s.uaSeen {
		if ts-u.ts <= e.rules.Policy.UAWindowMs && u.ua != "" {
			uaSet[u.ua] = true
		}
	}
	if ua != "" {
		uaSet[ua] = true
	}
	if len(uaSet) >= e.rules.Policy.UARotationThreshold && hasUngating(fired) {
		fire(sigUARotation)
	}
	// Signal 8: no_cookie_persistence (section 4.8, gated by section 6.3) —
	// request count >= 5 including current, no Cookie ever, cumulative
	// score 0 before, and no predecessor signal fired (canon decision 2:
	// gates on signals 1-7; the later 9-11 may co-fire). Never stacks with
	// scanner or decoy evidence.
	if s.requestCount+1 >= noCookieThreshold && !s.cookieEver && cumBefore == 0 && len(fired) == 0 {
		fire(sigNoCookiePersistence)
	}
	// Signal 9: headers_sparse (section 4.9).
	if req.HeaderCount < sparseHeaderBelow {
		fire(sigHeadersSparse)
	}
	// Signal 10: ua_missing (section 4.10).
	if ua == "" {
		fire(sigUAMissing)
	}
	// Signal 11: tooling_curl (section 4.11, gated by section 6.1) — UA
	// starts with "curl/" AND a signal from the ungating set 1-5 fired.
	// headers_sparse does not ungate; prior score does not ungate.
	if strings.HasPrefix(strings.ToLower(ua), "curl/") && hasUngating(fired) {
		fire(sigToolingCurl)
	}

	// Score and class of this request (section 5).
	requestScore := 0
	requestHigh := false
	for _, sig := range fired {
		requestScore += signalTable[sig].Weight
		if signalTable[sig].Class == classHigh {
			requestHigh = true
		}
	}

	// Verdict ladder (section 5): highest rung whose condition holds.
	verdict := model.VerdictObserve
	if requestScore >= e.rules.Policy.TagScore || cumBefore >= e.rules.Policy.TagCumBefore {
		verdict = model.VerdictTag
	}
	if _, isDecoy := e.rules.decoyAt(path); isDecoy &&
		requestScore >= e.rules.Policy.DecoyRouteScore && requestHigh && !e.rules.isProtected(path) {
		verdict = model.VerdictDecoyRoute
	}
	if requestScore >= e.rules.Policy.ThrottleScore {
		verdict = model.VerdictThrottle
	}
	if hasSignal(fired, sigHoneytokenUse) ||
		(hasSignal(fired, sigDecoyLeadFollow) && !e.rules.isProtected(path)) ||
		(requestScore >= e.rules.Policy.BanScore && requestHigh) {
		verdict = model.VerdictBan
	}
	// Protected-route cap (section 5, I4): a protected path caps at tag,
	// except honeytoken_use — a leaked fake credential in use is
	// near-certain evidence regardless of route.
	if e.rules.isProtected(path) && !hasSignal(fired, sigHoneytokenUse) {
		verdict = model.VerdictTag
	}

	// Session update (section 7): the event records the cumulative score
	// AFTER this request.
	s.requestCount++
	s.lastTs = ts
	if req.HasCookie {
		s.cookieEver = true
	}
	s.cumulative = cumBefore + requestScore

	// Windows keep only entries inside their trailing span after every
	// request (section 7). The in-place filter never copies: appends write
	// at or behind the read index.
	if ua != "" {
		s.uaSeen = append(s.uaSeen, uaSample{ua: ua, ts: ts})
	}
	kept := s.uaSeen[:0]
	for _, u := range s.uaSeen {
		if ts-u.ts <= e.rules.Policy.UAWindowMs {
			kept = append(kept, u)
		}
	}
	s.uaSeen = kept

	if e.rules.isUnknown(path) {
		s.unknownPaths = append(s.unknownPaths, pathSample{path: path, ts: ts})
	}
	keptPaths := s.unknownPaths[:0]
	for _, p := range s.unknownPaths {
		if ts-p.ts <= e.rules.Policy.EnumWindowMs {
			keptPaths = append(keptPaths, p)
		}
	}
	s.unknownPaths = keptPaths

	// Decoy serving happens only on a decoy_route verdict (canon decision
	// 6): throttle and ban do not serve, so they register no leads and mint
	// no honeytokens — the rung below them is what arms the session.
	decoyID := ""
	if verdict == model.VerdictDecoyRoute {
		entry := e.rules.DecoyPaths[path]
		decoyID = entry.ID
		for _, lead := range entry.Leads {
			s.leadsKnown[lead] = true
		}
		for _, tokenID := range entry.HoneytokenIDs {
			s.tokensMinted = append(s.tokensMinted, mintToken(key, entry.ID, tokenID))
		}
		s.decoysServed[entry.ID] = true
	}

	// Bounded session memory (design section 6): evict the most idle
	// session once a new one pushed the store over its cap.
	if len(e.sessions) > e.maxSessions {
		e.evictOldestLocked(key)
	}

	// reason_code = highest-weight fired signal; a weight tie resolves to
	// the earliest in evaluation order (canon decision 3). fired is in
	// evaluation order, so strict > keeps the earlier signal on ties.
	reason := reasonNone
	if len(fired) > 0 {
		best := fired[0]
		for _, sig := range fired[1:] {
			if signalTable[sig].Weight > signalTable[best].Weight {
				best = sig
			}
		}
		reason = signalTable[best].Reason
	}

	signals := make([]string, 0, len(fired))
	for _, sig := range fired {
		signals = append(signals, signalTable[sig].ID)
	}

	decision := model.Decision{
		ProtocolVersion: model.ProtocolVersion,
		SpecVersion:     model.SpecVersion,
		Verdict:         verdict,
		Action:          actionFor(verdict),
		DecoyID:         decoyID,
		SessionKey:      key,
		ReasonCode:      reason,
		RequestScore:    requestScore,
		Score:           s.cumulative,
		Signals:         signals,
	}
	if verdict == model.VerdictBan {
		ttl := e.rules.Policy.BanTTLms
		decision.BanTTLms = &ttl
	}
	return decision
}

// observeDecision is the never-scored decision (SIGNALS section 2): verdict
// observe, action pass, no signals, score 0, session key still reported.
func observeDecision(key string) model.Decision {
	return model.Decision{
		ProtocolVersion: model.ProtocolVersion,
		SpecVersion:     model.SpecVersion,
		Verdict:         model.VerdictObserve,
		Action:          model.ActionPass,
		SessionKey:      key,
		ReasonCode:      reasonNone,
		RequestScore:    0,
		Score:           0,
		Signals:         []string{},
	}
}

// actionFor maps a verdict to the adapter action (ADAPTER-PROTOCOL
// section 3): observe and tag pass, decoy_route serves the decoy, throttle
// and ban are enforcement requests the gatekeeper may still veto upstream.
func actionFor(verdict string) string {
	switch verdict {
	case model.VerdictDecoyRoute:
		return model.ActionServeDecoy
	case model.VerdictThrottle:
		return model.ActionThrottle
	case model.VerdictBan:
		return model.ActionBan
	default:
		return model.ActionPass
	}
}

// mintToken derives a per-session honeytoken in the token_alnum_24 format
// (data/token-formats.md): "mrg_live_" + the first 24 hex characters of
// sha256(sessionKey + ":" + entryID + ":" + tokenID). Deterministic per
// (session, entry, token), so a replayed vector file reproduces it exactly.
func mintToken(sessionKey, entryID, tokenID string) string {
	sum := sha256.Sum256([]byte(sessionKey + ":" + entryID + ":" + tokenID))
	return "mrg_live_" + hex.EncodeToString(sum[:])[:24]
}

// hasSignal reports whether sig is in the fired list.
func hasSignal(fired []int, sig int) bool {
	for _, s := range fired {
		if s == sig {
			return true
		}
	}
	return false
}

// hasUngating reports whether any signal from the ungating set 1-5 fired
// (canon decision 1).
func hasUngating(fired []int) bool {
	for _, s := range fired {
		if s < ungatingFirst {
			return true
		}
	}
	return false
}

// evictOldestLocked drops sessions with the oldest lastSeen until the store
// is back at cap, never touching the session named by keep (the one this
// request just scored).
//
// This is the bounded session memory design section 6 calls for ("a bounded
// in-memory LRU for hot decisions"). Evicting by lastSeen approximates a
// strict LRU well: every scored request refreshes lastSeen, so the victim
// is always the most idle session, and a strict access-ordered list would
// add bookkeeping for no decision-relevant difference. The scan is O(cap)
// and runs only when a NEW session pushes the store over cap — at the
// 50 000 cap that is one cheap memory-bound pass per new session, which is
// why a heap is not worth the complexity until profiling says otherwise.
func (e *Engine) evictOldestLocked(keep string) {
	for len(e.sessions) > e.maxSessions {
		oldestKey := ""
		var oldestTs int64
		for k, s := range e.sessions {
			if k == keep {
				continue
			}
			if oldestKey == "" || s.lastTs < oldestTs {
				oldestKey = k
				oldestTs = s.lastTs
			}
		}
		if oldestKey == "" {
			return // only the kept session remains: nothing to evict
		}
		delete(e.sessions, oldestKey)
	}
}
