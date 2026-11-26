package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mirage-shield/mirage/internal/config"
	"github.com/mirage-shield/mirage/internal/connectors"
	"github.com/mirage-shield/mirage/internal/model"
	"github.com/mirage-shield/mirage/internal/store"
)

// Dashboard test plumbing.

// doReq performs a request against the handler, presenting the token in
// the given style: "header" (X-Mirage-Dashboard-Token), "bearer"
// (Authorization: Bearer), or "" (no token). The response body is returned
// for the token-leak assertions.
func doReq(t *testing.T, h http.Handler, method, target, tokenStyle, token string, body string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rdr)
	switch tokenStyle {
	case "header":
		req.Header.Set("X-Mirage-Dashboard-Token", token)
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+token)
	case "bad-scheme":
		req.Header.Set("Authorization", "Basic "+token)
	case "empty-bearer":
		req.Header.Set("Authorization", "Bearer")
	case "":
	default:
		t.Fatalf("unknown token style %q", tokenStyle)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, rec.Body.String()
}

func assertJSONHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestHealthzIsOpenAndExact(t *testing.T) {
	// The LB probe: tokenless, one fixed body, nothing else — no counts,
	// no mode, no version.
	h := newHarness(t, config.ModeLook, nil)
	rec, body := doReq(t, h.svc.Handler(), "GET", "/healthz", "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the probe carries no token)", rec.Code)
	}
	assertJSONHeaders(t, rec)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("body %q is not JSON: %v", body, err)
	}
	if len(parsed) != 1 || parsed["status"] != "ok" {
		t.Fatalf("body = %q, want exactly {\"status\":\"ok\"}", body)
	}
	// The wrong method on the probe path is still answered in JSON.
	rec, _ = doReq(t, h.svc.Handler(), "POST", "/healthz", "", "", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /healthz = %d, want 405", rec.Code)
	}
	assertJSONHeaders(t, rec)
}

func TestDashboardRequiresToken(t *testing.T) {
	// I11 + the config rule: the token is required even on loopback, in
	// either header style, and a wrong or missing one answers 403 with a
	// fixed body.
	h := newHarness(t, config.ModeLook, nil)
	handler := h.svc.Handler()

	for _, tc := range []struct {
		name  string
		style string
		token string
		want  int
	}{
		{"no token", "", "", http.StatusForbidden},
		{"wrong token, header style", "header", "wrong-token", http.StatusForbidden},
		{"wrong token, bearer style", "bearer", "wrong-token", http.StatusForbidden},
		{"non-bearer scheme", "bad-scheme", testToken, http.StatusForbidden},
		{"bearer without value", "empty-bearer", "", http.StatusForbidden},
		{"empty header token", "header", "", http.StatusForbidden},
		{"right token, header style", "header", testToken, http.StatusOK},
		{"right token, bearer style", "bearer", testToken, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := doReq(t, handler, "GET", "/api/status", tc.style, tc.token, "")
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			assertJSONHeaders(t, rec)
			if tc.want == http.StatusForbidden {
				var parsed map[string]any
				if err := json.Unmarshal([]byte(body), &parsed); err != nil {
					t.Fatalf("body %q is not JSON: %v", body, err)
				}
				if parsed["error"] != "unauthorized" {
					t.Fatalf("body = %q, want {\"error\":\"unauthorized\"}", body)
				}
				if len(parsed) != 1 {
					t.Fatalf("body = %q, want exactly one field", body)
				}
			}
		})
	}
}

func TestDashboardMethodAndRouteDiscipline(t *testing.T) {
	h := newHarness(t, config.ModeLook, nil)
	handler := h.svc.Handler()

	for _, tc := range []struct {
		name   string
		method string
		target string
		want   int
	}{
		{"POST to a GET route", "POST", "/api/events", http.StatusMethodNotAllowed},
		{"PUT to a GET route", "PUT", "/api/bans", http.StatusMethodNotAllowed},
		{"GET to the POST route", "GET", "/api/bans/revoke", http.StatusMethodNotAllowed},
		{"unknown api path", "GET", "/api/nope", http.StatusNotFound},
		{"root path", "GET", "/", http.StatusNotFound},
		{"nested unknown path", "POST", "/api/bans/nope/deeper", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := doReq(t, handler, tc.method, tc.target, "header", testToken, "")
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", tc.want, rec.Code)
			}
			assertJSONHeaders(t, rec)
			var parsed map[string]any
			if err := json.Unmarshal([]byte(body), &parsed); err != nil {
				t.Fatalf("body %q is not JSON: %v", body, err)
			}
		})
	}
	// An unknown path without a token is still 403: auth runs first, so an
	// unauthenticated scan learns nothing about the route table.
	rec, _ := doReq(t, handler, "GET", "/api/nope", "", "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown path without token = %d, want 403", rec.Code)
	}
}

func TestDashboardLimitClamping(t *testing.T) {
	// The limit rules: absent = 50, provided = clamped to 1..1000,
	// non-integer = 400.
	h := newHarness(t, config.ModeLook, nil)
	handler := h.svc.Handler()

	h.svc.Start(context.Background())
	for i := 0; i < 60; i++ {
		h.svc.Decide(cleanRequest("203.0.113.60", frozenMs+int64(i)))
	}
	if err := h.svc.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}

	for _, tc := range []struct {
		name   string
		target string
		want   int
		status int
	}{
		{"absent defaults to 50", "/api/events", 50, http.StatusOK},
		{"small limit honored", "/api/events?limit=2", 2, http.StatusOK},
		{"zero clamps to 1", "/api/events?limit=0", 1, http.StatusOK},
		{"negative clamps to 1", "/api/events?limit=-5", 1, http.StatusOK},
		{"large clamps to 1000, bounded by stored 60", "/api/events?limit=9999", 60, http.StatusOK},
		{"non-integer is rejected", "/api/events?limit=abc", 0, http.StatusBadRequest},
		{"sessions limit honored", "/api/sessions?limit=1", 1, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := doReq(t, handler, "GET", tc.target, "header", testToken, "")
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			assertJSONHeaders(t, rec)
			if tc.status != http.StatusOK {
				return
			}
			var items []any
			if err := json.Unmarshal([]byte(body), &items); err != nil {
				t.Fatalf("body %q is not a JSON array: %v", body, err)
			}
			if len(items) != tc.want {
				t.Fatalf("got %d items, want %d", len(items), tc.want)
			}
		})
	}
}

func TestDashboardEventsVisibleAfterFlush(t *testing.T) {
	// The I10 loop end to end: decide through the service, flush via
	// Start/Stop, read the evidence back through the dashboard — no
	// sleeps anywhere; Stop's flush is the synchronization point.
	fc := newFakeConnector(nil)
	h := newHarness(t, config.ModeProtect, []connectors.Connector{fc})
	handler := h.svc.Handler()
	ip := "203.0.113.61"

	h.svc.Start(context.Background())
	seq := banGradeSequence(ip, frozenMs)
	for _, r := range seq {
		h.svc.Decide(r)
	}
	if err := h.svc.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	fc.waitApplied(t, 1)

	// Events: newest first, with the decisions they recorded.
	_, body := doReq(t, handler, "GET", "/api/events", "header", testToken, "")
	var evs []model.Event
	if err := json.Unmarshal([]byte(body), &evs); err != nil {
		t.Fatalf("body %q is not events: %v", body, err)
	}
	if len(evs) != 3 {
		t.Fatalf("got %d events, want 3", len(evs))
	}
	if evs[0].Path != "/api/v1/auth" || evs[0].Decision.Verdict != model.VerdictBan ||
		evs[0].Decision.Action != model.ActionBan || evs[0].Decision.ReasonCode != "SIG-104" {
		t.Fatalf("newest event = %+v, want the enforced ban on /api/v1/auth", evs[0])
	}
	if evs[2].Path != "/.env" || evs[2].Decision.Action != model.ActionServeDecoy {
		t.Fatalf("oldest event = %+v, want the decoy serve on /.env", evs[2])
	}
	if evs[0].SessionKey != model.SessionKey(ip) || evs[0].ClientIP != ip {
		t.Fatalf("event identity = %s/%s, want %s/%s", evs[0].SessionKey, evs[0].ClientIP, model.SessionKey(ip), ip)
	}

	// Sessions: one rolling summary with the whole sequence folded in.
	_, body = doReq(t, handler, "GET", "/api/sessions", "header", testToken, "")
	var sums []struct {
		SessionKey   string `json:"session_key"`
		RequestCount int    `json:"request_count"`
		Score        int    `json:"score"`
		LastVerdict  string `json:"last_verdict"`
		IPHash       string `json:"ip_hash"`
	}
	if err := json.Unmarshal([]byte(body), &sums); err != nil {
		t.Fatalf("body %q is not summaries: %v", body, err)
	}
	if len(sums) != 1 || sums[0].RequestCount != 3 || sums[0].Score != 115 ||
		sums[0].LastVerdict != model.VerdictBan || sums[0].SessionKey != model.SessionKey(ip) {
		t.Fatalf("summaries = %+v, want one session, 3 requests, score 115, verdict ban", sums)
	}
	// This test config keeps the default hash_ips=true, so the stored
	// identity is the sha256 hex of the IP, never the plain IP.
	if sums[0].IPHash != store.HashIP(ip) {
		t.Fatalf("stored ip identity = %q, want %q", sums[0].IPHash, store.HashIP(ip))
	}

	// Bans: the enforced ban with its bounded-context note.
	_, body = doReq(t, handler, "GET", "/api/bans", "header", testToken, "")
	var bans []struct {
		IP          string `json:"ip"`
		Reason      string `json:"reason"`
		Note        string `json:"note"`
		Active      bool   `json:"active"`
		ExpiresAtMs int64  `json:"expires_at_ms"`
	}
	if err := json.Unmarshal([]byte(body), &bans); err != nil {
		t.Fatalf("body %q is not bans: %v", body, err)
	}
	if len(bans) != 1 || bans[0].IP != ip || bans[0].Reason != "SIG-104" || !bans[0].Active {
		t.Fatalf("bans = %+v, want one active SIG-104 ban for %s", bans, ip)
	}
	if bans[0].Note != "verdict=ban score=115 session="+model.SessionKey(ip) {
		t.Fatalf("ban note = %q, want the bounded context", bans[0].Note)
	}
}

func TestDashboardStatus(t *testing.T) {
	// The honest self-description: mode, versions, engine sessions, queue
	// depth and drops, the memory store's null corruption counter, and
	// each connector's never-probed health (the reconcile loop has not
	// ticked in this test).
	fc := newFakeConnector(nil)
	h := newHarness(t, config.ModeProtect, []connectors.Connector{fc})
	handler := h.svc.Handler()
	h.svc.Start(context.Background())
	h.svc.Decide(cleanRequest("203.0.113.62", frozenMs))
	if err := h.svc.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}

	_, body := doReq(t, handler, "GET", "/api/status", "header", testToken, "")
	var st struct {
		Mode            string `json:"mode"`
		ProtocolVersion string `json:"protocol_version"`
		SpecVersion     string `json:"spec_version"`
		UptimeMs        int64  `json:"uptime_ms"`
		Sessions        int    `json:"sessions"`
		Queue           struct {
			Len     int    `json:"len"`
			Dropped uint64 `json:"dropped"`
		} `json:"queue"`
		Store struct {
			CorruptRowsSkipped *int64 `json:"corrupt_rows_skipped"`
		} `json:"store"`
		Connectors []struct {
			Name        string `json:"name"`
			Healthy     bool   `json:"healthy"`
			CheckedAtMs int64  `json:"checked_at_ms"`
		} `json:"connectors"`
	}
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("body %q is not status: %v", body, err)
	}
	if st.Mode != config.ModeProtect || st.ProtocolVersion != model.ProtocolVersion || st.SpecVersion != model.SpecVersion {
		t.Fatalf("identity = %s %s %s, want protect %s %s", st.Mode, st.ProtocolVersion, st.SpecVersion,
			config.ModeProtect, model.ProtocolVersion)
	}
	if st.UptimeMs != 0 {
		t.Fatalf("uptime after Stop = %d, want 0 (the loops are not running)", st.UptimeMs)
	}
	if st.Sessions != 1 {
		t.Fatalf("engine sessions = %d, want 1", st.Sessions)
	}
	if st.Queue.Len != 0 || st.Queue.Dropped != 0 {
		t.Fatalf("queue = %+v, want empty with no drops", st.Queue)
	}
	if st.Store.CorruptRowsSkipped != nil {
		t.Fatalf("memory store reports a corruption counter %v, want null (it cannot rot)", st.Store.CorruptRowsSkipped)
	}
	if len(st.Connectors) != 1 || st.Connectors[0].Name != "fake" || st.Connectors[0].CheckedAtMs != 0 {
		t.Fatalf("connectors = %+v, want the never-probed fake", st.Connectors)
	}
}

func TestDashboardRevoke(t *testing.T) {
	// One-click reversal (I5): the stored record deactivates, the
	// gatekeeper stops renewing, the updated record set comes back — and
	// reversal is idempotent and rejects garbage strictly (I7).
	fc := newFakeConnector(nil)
	h := newHarness(t, config.ModeProtect, []connectors.Connector{fc})
	handler := h.svc.Handler()
	ip := "203.0.113.63"
	runSequence(t, h.svc, banGradeSequence(ip, frozenMs))
	fc.waitApplied(t, 1)

	// Happy path: the record disappears from the active set.
	rec, body := doReq(t, handler, "POST", "/api/bans/revoke", "header", testToken,
		`{"ip":"`+ip+`","reason":"SIG-104"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200 (body %s)", rec.Code, body)
	}
	var bans []map[string]any
	if err := json.Unmarshal([]byte(body), &bans); err != nil {
		t.Fatalf("body %q is not a ban list: %v", body, err)
	}
	if len(bans) != 0 {
		t.Fatalf("updated record set = %s, want empty", body)
	}
	_, body = doReq(t, handler, "GET", "/api/bans", "header", testToken, "")
	if err := json.Unmarshal([]byte(body), &bans); err != nil {
		t.Fatalf("body %q is not a ban list: %v", body, err)
	}
	if len(bans) != 0 {
		t.Fatalf("bans after revoke = %s, want none", body)
	}
	// The gatekeeper no longer renews: the next request is scored fresh.
	d := h.svc.Decide(cleanRequest(ip, frozenMs+3000))
	if d.Action == model.ActionBan {
		t.Fatalf("next request still banned after revoke: %s/%s", d.Verdict, d.Action)
	}
	if d.Verdict != model.VerdictTag {
		t.Fatalf("next request verdict = %q, want tag via session history (fresh rescore)", d.Verdict)
	}
	// The connector never saw a direct Revoke: reversal reaches providers
	// through the reconcile loop, not the request path.
	fc.mu.Lock()
	revoked := len(fc.revoked)
	fc.mu.Unlock()
	if revoked != 0 {
		t.Fatalf("connector Revoke called %d times, want 0 (reconcile owns reversal)", revoked)
	}

	// Idempotent: revoking again succeeds with nothing to do.
	rec, _ = doReq(t, handler, "POST", "/api/bans/revoke", "header", testToken,
		`{"ip":"`+ip+`","reason":"SIG-104"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("second revoke status = %d, want 200 (idempotent)", rec.Code)
	}

	// Strictly validated bodies (I7): garbage IP, missing or malformed
	// reason, non-JSON and empty bodies.
	for _, tc := range []struct {
		name string
		body string
	}{
		{"garbage ip", `{"ip":"not-an-ip","reason":"SIG-104"}`},
		{"ip with junk around it", `{"ip":" 203.0.113.63 x","reason":"SIG-104"}`},
		{"missing reason", `{"ip":"203.0.113.63"}`},
		{"malformed reason", `{"ip":"203.0.113.63","reason":"because"}`},
		{"empty reason", `{"ip":"203.0.113.63","reason":""}`},
		{"not JSON", `ip=203.0.113.63`},
		{"empty body", ``},
		{"unknown field", `{"ip":"203.0.113.63","reason":"SIG-104","why":"x"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := doReq(t, handler, "POST", "/api/bans/revoke", "header", testToken, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", rec.Code, body)
			}
			assertJSONHeaders(t, rec)
		})
	}
}

func TestDashboardTokenNeverAppearsInAnyResponse(t *testing.T) {
	// I11, asserted: hit every endpoint and every failure shape, and the
	// dashboard token must not appear in any response body.
	fc := newFakeConnector(nil)
	h := newHarness(t, config.ModeProtect, []connectors.Connector{fc})
	handler := h.svc.Handler()
	runSequence(t, h.svc, banGradeSequence("203.0.113.64", frozenMs))

	requests := []struct {
		method string
		target string
		style  string
		token  string
		body   string
	}{
		{"GET", "/healthz", "", "", ""},
		{"GET", "/api/status", "header", testToken, ""},
		{"GET", "/api/events", "header", testToken, ""},
		{"GET", "/api/events?limit=0", "header", testToken, ""},
		{"GET", "/api/events?limit=zzz", "header", testToken, ""},
		{"GET", "/api/sessions", "header", testToken, ""},
		{"GET", "/api/bans", "header", testToken, ""},
		{"GET", "/api/bans?limit=1", "header", testToken, ""},
		{"POST", "/api/bans/revoke", "header", testToken, `{"ip":"203.0.113.64","reason":"SIG-104"}`},
		{"POST", "/api/bans/revoke", "header", testToken, `{"ip":"bad","reason":"SIG-104"}`},
		{"POST", "/api/bans/revoke", "header", testToken, `not json`},
		{"POST", "/api/bans/revoke", "", "", `{"ip":"203.0.113.64","reason":"SIG-104"}`},
		{"GET", "/api/status", "bearer", testToken, ""},
		{"GET", "/api/status", "header", "wrong-token", ""},
		{"GET", "/api/status", "", "", ""},
		{"POST", "/api/events", "header", testToken, ""},
		{"GET", "/nope", "header", testToken, ""},
		{"GET", "/", "header", testToken, ""},
	}
	for _, rq := range requests {
		rec, body := doReq(t, handler, rq.method, rq.target, rq.style, rq.token, rq.body)
		if strings.Contains(body, testToken) {
			t.Fatalf("%s %s leaked the dashboard token in its %d body: %s", rq.method, rq.target, rec.Code, body)
		}
		assertJSONHeaders(t, rec)
	}
}

func TestDashboardEventsFlushedWithoutStart(t *testing.T) {
	// Decide without Start still leaves the queue holding the events; a
	// later Stop flushes them — the lifecycle is forgiving by design.
	h := newHarness(t, config.ModeLook, nil)
	handler := h.svc.Handler()
	for i := 0; i < 2; i++ {
		h.svc.Decide(cleanRequest("203.0.113.65", frozenMs+int64(i)))
	}
	if got := h.q.Len(); got != 2 {
		t.Fatalf("queue holds %d events before any flush, want 2", got)
	}
	if err := h.svc.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	_, body := doReq(t, handler, "GET", "/api/events", "header", testToken, "")
	var evs []model.Event
	if err := json.Unmarshal([]byte(body), &evs); err != nil {
		t.Fatalf("body %q is not events: %v", body, err)
	}
	if len(evs) != 2 {
		t.Fatalf("got %d events after the stop-flush, want 2", len(evs))
	}
}

func TestDashboardStartStopRaceSafe(t *testing.T) {
	// Start and Stop are each idempotent and race-safe; hammering both
	// from several goroutines must be clean under -race and must never
	// panic or leak a generation into another's wait.
	h := newHarness(t, config.ModeLook, nil)
	h.svc.Start(context.Background())
	h.svc.Start(context.Background()) // idempotent

	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(2)
		go func() { defer wg.Done(); h.svc.Stop(context.Background()) }()
		go func() { defer wg.Done(); h.svc.Start(context.Background()) }()
	}
	wg.Wait()
	if err := h.svc.Stop(context.Background()); err != nil {
		t.Fatalf("final stop: %v", err)
	}
}

// TestDrainerFoldsSummariesThroughStore pins the folding arithmetic the
// rolling summaries use: interleaved decisions from two sessions land in
// two per-session aggregates, each counted exactly.
func TestDrainerFoldsSummariesThroughStore(t *testing.T) {
	h := newHarness(t, config.ModeLook, nil)
	h.svc.Start(context.Background())
	for i := 0; i < 3; i++ {
		h.svc.Decide(cleanRequest("203.0.113.66", frozenMs+int64(i)))
		h.svc.Decide(cleanRequest("203.0.113.67", frozenMs+int64(i)))
	}
	if err := h.svc.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	_, body := doReq(t, h.svc.Handler(), "GET", "/api/sessions", "header", testToken, "")
	var sums []struct {
		RequestCount int `json:"request_count"`
		Score        int `json:"score"`
	}
	if err := json.Unmarshal([]byte(body), &sums); err != nil {
		t.Fatalf("body %q is not summaries: %v", body, err)
	}
	if len(sums) != 2 {
		t.Fatalf("got %d summaries, want 2 (one per session)", len(sums))
	}
	for _, sum := range sums {
		if sum.RequestCount != 3 || sum.Score != 0 {
			t.Fatalf("summary = %+v, want 3 clean requests, score 0", sum)
		}
	}
}
