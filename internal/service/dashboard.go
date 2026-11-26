package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/mirage-shield/mirage/internal/model"
	"github.com/mirage-shield/mirage/internal/store"
)

// Dashboard constants. Auth lives in this layer by design — config carries
// the token, the service enforces it (see config.Config.DashboardToken) —
// because the dashboard is served here, not loaded there.
const (
	// dashboardDefaultLimit is the page size when a limit parameter is
	// absent.
	dashboardDefaultLimit = 50

	// dashboardMaxLimit caps every listing read: an unbounded caller must
	// not be able to page the whole event log in one request.
	dashboardMaxLimit = 1000

	// revokeBodyLimit bounds the revoke request body (I7: the dashboard's
	// inputs are untrusted); a bigger body is an error, not a truncation.
	revokeBodyLimit = 4096
)

// Dashboard auth headers. The token rides either style.
const (
	tokenHeader  = "X-Mirage-Dashboard-Token"
	authHeader   = "Authorization"
	bearerScheme = "Bearer"
)

// errorBody is the JSON error envelope shared by every failure answer. It
// carries one fixed word — no echoed input, no token material, no internal
// detail (I7, I11).
type errorBody struct {
	Error string `json:"error"`
}

// banRecordJSON is the wire shape of store.BanRecord, whose stored struct
// carries no JSON tags of its own.
type banRecordJSON struct {
	IP          string `json:"ip"`
	Reason      string `json:"reason"`
	CreatedAtMs int64  `json:"created_at_ms"`
	ExpiresAtMs int64  `json:"expires_at_ms"`
	Note        string `json:"note"`
	Active      bool   `json:"active"`
}

// sessionSummaryJSON is the wire shape of store.SessionSummary, whose
// stored struct carries no JSON tags of its own.
type sessionSummaryJSON struct {
	SessionKey     string `json:"session_key"`
	FirstTsMs      int64  `json:"first_ts_ms"`
	LastTsMs       int64  `json:"last_ts_ms"`
	RequestCount   int    `json:"request_count"`
	Score          int    `json:"score"`
	LastVerdict    string `json:"last_verdict"`
	LastReasonCode string `json:"last_reason_code"`
	IPHash         string `json:"ip_hash"`
}

// statusResponse is the /api/status body: an honest self-description of
// the running decision path.
type statusResponse struct {
	Mode            string            `json:"mode"`
	ProtocolVersion string            `json:"protocol_version"`
	SpecVersion     string            `json:"spec_version"`
	UptimeMs        int64             `json:"uptime_ms"`
	Sessions        int               `json:"sessions"`
	Queue           statusQueue       `json:"queue"`
	Store           statusStore       `json:"store"`
	Connectors      []connectorHealth `json:"connectors"`
}

type statusQueue struct {
	Len     int    `json:"len"`
	Dropped uint64 `json:"dropped"`
}

type statusStore struct {
	// CorruptRowsSkipped is null when the store cannot report corruption
	// (the in-memory store deliberately cannot rot); the key stays present
	// so the dashboard's schema is stable across stores.
	CorruptRowsSkipped *int64 `json:"corrupt_rows_skipped"`
}

// Handler returns the dashboard API. Every route except /healthz requires
// the dashboard token — even on loopback: an unauthenticated local endpoint
// is one curl away from a full takeover. There is no directory listing, no
// HTML and no method ambiguity: a matched path with the wrong method
// answers 405 with the right one, an unmatched path answers 404, and every
// response — success or failure — is JSON with Cache-Control: no-store
// (decision evidence must never come from a cache).
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()

	// The load-balancer probe: tokenless (a probe forced to present a
	// secret would fail on every restart and leak the secret into LB
	// configs), one fixed body, and nothing else — no counts, no mode, no
	// version: a probe must not double as an information endpoint.
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("/healthz", methodNotAllowed("GET"))

	// Every API route is registered twice: the method-specific pattern
	// serves the real handler, and the method-less fallback answers every
	// other method with the JSON 405 — ServeMux would otherwise emit its
	// own plain-text 405 without the required headers.
	mux.HandleFunc("GET /api/status", s.guard(s.handleStatus))
	mux.HandleFunc("/api/status", s.guard(methodNotAllowed("GET")))
	mux.HandleFunc("GET /api/events", s.guard(s.handleEvents))
	mux.HandleFunc("/api/events", s.guard(methodNotAllowed("GET")))
	mux.HandleFunc("GET /api/sessions", s.guard(s.handleSessions))
	mux.HandleFunc("/api/sessions", s.guard(methodNotAllowed("GET")))
	mux.HandleFunc("GET /api/bans", s.guard(s.handleBans))
	mux.HandleFunc("/api/bans", s.guard(methodNotAllowed("GET")))
	mux.HandleFunc("POST /api/bans/revoke", s.guard(s.handleRevoke))
	mux.HandleFunc("/api/bans/revoke", s.guard(methodNotAllowed("POST")))

	// The catch-all answers every unmatched path; auth runs first, so an
	// unauthenticated scan learns nothing but the fixed 403 body.
	mux.HandleFunc("/", s.guard(notFound))
	return mux
}

// guard wraps a dashboard handler with token authentication. The check is
// constant-time (see authorized); a failed check answers with a fixed body
// and no detail about what was wrong.
func (s *Service) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			writeJSON(w, http.StatusForbidden, errorBody{Error: "unauthorized"})
			return
		}
		h(w, r)
	}
}

// authorized extracts the dashboard token from either header style and
// compares it in constant time. Both sides are hashed before the
// crypto/subtle comparison: ConstantTimeCompare returns early on unequal
// lengths, so hashing first removes even the token LENGTH from timing
// observation. The token value itself never appears in any response, log
// or error (I11) — failures answer with the fixed unauthorized body.
func (s *Service) authorized(r *http.Request) bool {
	token := strings.TrimSpace(r.Header.Get(tokenHeader))
	if token == "" {
		auth := r.Header.Get(authHeader)
		scheme, rest, ok := strings.Cut(auth, " ")
		if !ok || !strings.EqualFold(scheme, bearerScheme) {
			return false
		}
		token = strings.TrimSpace(rest)
	}
	if token == "" {
		return false
	}
	got := sha256.Sum256([]byte(token))
	want := sha256.Sum256([]byte(s.cfg.DashboardToken))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// writeJSON is the single response writer: every dashboard response —
// success, 4xx, 405, 404 — carries Content-Type: application/json and
// Cache-Control: no-store, and nothing is ever served but JSON.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The client is gone or the body is unwritable; nothing remains
		// that could help the caller.
		log.Printf("service: dashboard: encode response: %v", err)
	}
}

// handleHealthz answers the load-balancer probe.
func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

// methodNotAllowed answers a matched path with the wrong method, naming
// the right one. Auth has already run by the time it answers.
func methodNotAllowed(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", allow)
		writeJSON(w, http.StatusMethodNotAllowed, errorBody{Error: "method not allowed"})
	}
}

// notFound answers every path that is not a route: a fixed body, no
// enumeration, no directory listing.
func notFound(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotFound, errorBody{Error: "not found"})
}

// parseLimit reads the ?limit=N parameter: absent means the default; a
// non-integer is rejected rather than silently defaulted, so a caller bug
// cannot masquerade as a page size; any integer is clamped to
// 1..dashboardMaxLimit. The clamp is the dashboard's own — the store would
// re-clamp, but the dashboard's default (50) differs from the store's (100)
// and must not be overridden by it.
func parseLimit(r *http.Request) (int, bool) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return dashboardDefaultLimit, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	if n < 1 {
		n = 1
	}
	if n > dashboardMaxLimit {
		n = dashboardMaxLimit
	}
	return n, true
}

// handleStatus reports the running decision path's honest self-description:
// mode, versions, uptime (0 when the background loops are not running),
// live engine sessions, queue depth and drops, the store's corruption
// counter where the store can report one, and each connector's last
// observed health.
func (s *Service) handleStatus(w http.ResponseWriter, _ *http.Request) {
	now := s.clock()
	s.lifeMu.Lock()
	var uptime int64
	if s.running {
		uptime = now - s.startedAtMs
	}
	s.lifeMu.Unlock()
	if uptime < 0 {
		// A clock that moved backwards must not report a negative uptime.
		uptime = 0
	}

	var corrupt *int64
	if c, ok := s.st.(store.CorruptRowCounter); ok {
		n := c.CorruptRowsSkipped()
		corrupt = &n
	}
	var ql int
	var qd uint64
	if s.q != nil {
		ql = s.q.Len()
		qd = s.q.Dropped()
	}
	writeJSON(w, http.StatusOK, statusResponse{
		Mode:            s.cfg.Mode,
		ProtocolVersion: model.ProtocolVersion,
		SpecVersion:     model.SpecVersion,
		UptimeMs:        uptime,
		Sessions:        s.eng.Len(),
		Queue:           statusQueue{Len: ql, Dropped: qd},
		Store:           statusStore{CorruptRowsSkipped: corrupt},
		Connectors:      s.healthSnapshot(),
	})
}

// handleEvents lists stored decision events, newest first.
func (s *Service) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit, ok := parseLimit(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid limit"})
		return
	}
	events, err := s.st.RecentEvents(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{Error: "store unavailable"})
		return
	}
	if events == nil {
		events = []model.Event{}
	}
	writeJSON(w, http.StatusOK, events)
}

// handleSessions lists the rolling per-session summaries, newest first.
func (s *Service) handleSessions(w http.ResponseWriter, r *http.Request) {
	limit, ok := parseLimit(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid limit"})
		return
	}
	summaries, err := s.st.SessionSummaries(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{Error: "store unavailable"})
		return
	}
	out := make([]sessionSummaryJSON, 0, len(summaries))
	for _, sum := range summaries {
		out = append(out, sessionSummaryJSON{
			SessionKey:     sum.SessionKey,
			FirstTsMs:      sum.FirstTsMs,
			LastTsMs:       sum.LastTsMs,
			RequestCount:   sum.RequestCount,
			Score:          sum.Score,
			LastVerdict:    sum.LastVerdict,
			LastReasonCode: sum.LastReasonCode,
			IPHash:         sum.IPHash,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleBans lists the active ban records, newest first.
func (s *Service) handleBans(w http.ResponseWriter, r *http.Request) {
	limit, ok := parseLimit(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid limit"})
		return
	}
	records, err := s.st.BanRecords(r.Context(), s.clock(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{Error: "store unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, banRecordsJSONList(records))
}

// revokeRequest is the one-click reversal body (I5): the address and the
// reason code of the ban record the operator clicked.
type revokeRequest struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

// handleRevoke deactivates one ban record (see revokeBan) and answers with
// the updated record set. The body is validated strictly — a bare valid IP
// (netip; garbage is rejected, I7) and a well-formed reason code — because
// the value travels into store keys and provider-facing records. Reversal
// reaches the connectors through the reconcile loop, within one 30 s pass,
// rather than a direct connector call: the loop is the self-healing path
// that also removes the ban when a direct call was missed or crashed.
func (s *Service) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var body revokeRequest
	r.Body = http.MaxBytesReader(w, r.Body, revokeBodyLimit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid body"})
		return
	}
	ip := strings.TrimSpace(body.IP)
	if _, err := netip.ParseAddr(ip); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid ip"})
		return
	}
	if !validReasonCode(body.Reason) {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid reason"})
		return
	}
	now := s.clock()
	if err := s.revokeBan(r.Context(), ip, body.Reason, now); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{Error: "store unavailable"})
		return
	}
	records, err := s.st.BanRecords(r.Context(), now, dashboardDefaultLimit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{Error: "store unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, banRecordsJSONList(records))
}

// revokeBan deactivates the (ip, reason) ban record — the store's upsert
// key — keeping its original note and creation time, and ends the
// address's renewal at the gatekeeper. Idempotent: revoking a record that
// is already inactive, or never existed, is a success with nothing to do —
// reversal must always be safe to click again (I5).
func (s *Service) revokeBan(ctx context.Context, ip, reason string, nowMs int64) error {
	records, err := s.st.BanRecords(ctx, nowMs, reconcileLimit)
	if err != nil {
		return err
	}
	for _, rec := range records {
		if rec.IP != ip || rec.Reason != reason {
			continue
		}
		rec.Active = false
		rec.ExpiresAtMs = nowMs
		if err := s.st.UpsertBanRecord(ctx, rec); err != nil {
			return err
		}
	}
	if s.gk != nil {
		s.gk.RevokeBan(ip, nowMs)
	}
	s.dropRenewal(ip)
	return nil
}

// validReasonCode accepts the system's reason-code shape — "SIG-" plus one
// to four digits, the form of every code in data/reason-texts.txt. The
// value selects a stored ban record, so anything else is a caller bug, and
// a bounded shape keeps it out of store keys and provider records (I7).
func validReasonCode(reason string) bool {
	const prefix = "SIG-"
	if len(reason) < len(prefix)+1 || len(reason) > len(prefix)+4 {
		return false
	}
	if !strings.HasPrefix(reason, prefix) {
		return false
	}
	for _, c := range reason[len(prefix):] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// banRecordsJSONList maps stored records to their wire shape; an empty set
// is an empty JSON array, not null.
func banRecordsJSONList(records []store.BanRecord) []banRecordJSON {
	out := make([]banRecordJSON, 0, len(records))
	for _, r := range records {
		out = append(out, banRecordJSON{
			IP:          r.IP,
			Reason:      r.Reason,
			CreatedAtMs: r.CreatedAtMs,
			ExpiresAtMs: r.ExpiresAtMs,
			Note:        r.Note,
			Active:      r.Active,
		})
	}
	return out
}
