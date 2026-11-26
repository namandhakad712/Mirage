package connectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCrowdSecApplyRequestShape(t *testing.T) {
	log := &reqLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	clock := int64(1_700_000_000_000)
	c := NewCrowdSec(srv.URL, "test-token", func() int64 { return clock })
	p, _ := fastPolicy()
	c.policy = p

	ban := Ban{IP: "203.0.113.7", Reason: "SIG-104", CreatedAtMs: clock, ExpiresAtMs: clock + 1_800_000}
	if err := c.Apply(context.Background(), ban); err != nil {
		t.Fatalf("apply: %v", err)
	}

	req := log.at(0)
	if req.Method != http.MethodPost || req.Path != "/v1/alerts" {
		t.Fatalf("request = %s %s, want POST /v1/alerts", req.Method, req.Path)
	}
	if auth := req.Header.Get("Authorization"); auth != "Bearer test-token" {
		t.Fatalf("authorization = %q, want Bearer test-token", auth)
	}

	var body struct {
		Capacity int    `json:"capacity"`
		Source   string `json:"source"`
		StartAt  string `json:"start_at"`
		Events   []struct {
			Meta      map[string]string `json:"meta"`
			Timestamp string            `json:"timestamp"`
		} `json:"events"`
		Decisions []struct {
			Duration string `json:"duration"`
			Reason   string `json:"reason"`
			Scope    string `json:"scope"`
			Type     string `json:"type"`
			Origin   string `json:"origin"`
		} `json:"decisions"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body.Capacity != 0 || body.Source != "mirage" {
		t.Fatalf("capacity/source = %d/%q, want 0/mirage", body.Capacity, body.Source)
	}
	if _, err := time.Parse(time.RFC3339, body.StartAt); err != nil {
		t.Fatalf("start_at %q is not RFC3339: %v", body.StartAt, err)
	}
	if len(body.Events) != 1 || body.Events[0].Meta["log_source"] != "mirage" {
		t.Fatalf("events = %+v, want one mirage log_source event", body.Events)
	}
	if _, err := time.Parse(time.RFC3339, body.Events[0].Timestamp); err != nil {
		t.Fatalf("event timestamp %q is not RFC3339: %v", body.Events[0].Timestamp, err)
	}
	if len(body.Decisions) != 1 {
		t.Fatalf("decisions = %+v, want exactly one", body.Decisions)
	}
	d := body.Decisions[0]
	// The TTL is OURS: 1_800_000 ms becomes exactly "30m", the reason
	// carries the mirage prefix, and scope carries the address.
	if d.Duration != "30m" || d.Reason != "mirage: SIG-104" || d.Scope != "203.0.113.7" || d.Type != "ban" || d.Origin != "mirage" {
		t.Fatalf("decision = %+v, want 30m / mirage: SIG-104 / 203.0.113.7 / ban / mirage", d)
	}
}

func TestCrowdSecDurationString(t *testing.T) {
	cases := []struct {
		ttlMs int64
		want  string
	}{
		{1_800_000, "30m"},
		{1_800_001, "31m"}, // ceil: the provider must never expire before we do
		{3_600_000, "60m"},
		{3_600_001, "61m"},
		{60_000, "1m"},
		{30_000, "1m"}, // sub-minute remainder clamps up
		{0, "1m"},
		{-5_000, "1m"},
	}
	for _, c := range cases {
		if got := crowdsecDuration(c.ttlMs); got != c.want {
			t.Fatalf("crowdsecDuration(%d) = %q, want %q", c.ttlMs, got, c.want)
		}
	}
}

func TestCrowdSecApplyIdempotentWhileUnexpired(t *testing.T) {
	log := &reqLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	clock := int64(1_700_000_000_000)
	c := NewCrowdSec(srv.URL, "test-token", func() int64 { return clock })
	p, _ := fastPolicy()
	c.policy = p

	// Same address+reason applied twice while unexpired: one POST.
	ban := Ban{IP: "203.0.113.7", Reason: "SIG-104", ExpiresAtMs: clock + 60_000}
	for i := 0; i < 2; i++ {
		if err := c.Apply(context.Background(), ban); err != nil {
			t.Fatalf("apply #%d: %v", i+1, err)
		}
	}
	if got := log.count(); got != 1 {
		t.Fatalf("requests = %d, want 1 (second apply is a no-op)", got)
	}

	// Once our tracked entry has lapsed, a renewed ban with the same
	// key must reach the provider again.
	clock += 61_000
	renewed := Ban{IP: "203.0.113.7", Reason: "SIG-104", ExpiresAtMs: clock + 60_000}
	if err := c.Apply(context.Background(), renewed); err != nil {
		t.Fatalf("apply renewal: %v", err)
	}
	if got := log.count(); got != 2 {
		t.Fatalf("requests = %d, want 2 after renewal", got)
	}
}

func TestCrowdSecApplyRefusesExpiredBan(t *testing.T) {
	log := &reqLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	clock := int64(1_700_000_000_000)
	c := NewCrowdSec(srv.URL, "test-token", func() int64 { return clock })
	p, _ := fastPolicy()
	c.policy = p

	stale := Ban{IP: "203.0.113.7", Reason: "SIG-104", ExpiresAtMs: clock}
	if err := c.Apply(context.Background(), stale); err == nil {
		t.Fatal("apply must refuse a ban that is already expired")
	}
	if got := log.count(); got != 0 {
		t.Fatalf("requests = %d, want 0", got)
	}
}

func TestCrowdSecRevokeDeletesByIP(t *testing.T) {
	log := &reqLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	clock := int64(1_700_000_000_000)
	c := NewCrowdSec(srv.URL, "test-token", func() int64 { return clock })
	p, _ := fastPolicy()
	c.policy = p

	if err := c.Apply(context.Background(), Ban{IP: "203.0.113.7", Reason: "SIG-104", ExpiresAtMs: clock + 60_000}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := c.Revoke(context.Background(), Ban{IP: "203.0.113.7"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	req := log.at(1)
	if req.Method != http.MethodDelete || req.Path != "/v1/decisions" {
		t.Fatalf("revoke request = %s %s, want DELETE /v1/decisions", req.Method, req.Path)
	}
	if got := req.Query.Get("ip"); got != "203.0.113.7" {
		t.Fatalf("revoke query ip = %q, want 203.0.113.7", got)
	}
	if auth := req.Header.Get("Authorization"); auth != "Bearer test-token" {
		t.Fatalf("authorization = %q", auth)
	}
}

func TestCrowdSecRevokeMissingIsSuccess(t *testing.T) {
	// The decisions endpoint answers 404 when nothing matches; revoking
	// a non-existent ban is success, not an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewCrowdSec(srv.URL, "test-token", nil)
	p, _ := fastPolicy()
	c.policy = p

	if err := c.Revoke(context.Background(), Ban{IP: "203.0.113.7"}); err != nil {
		t.Fatalf("revoke missing: %v", err)
	}
}

func TestCrowdSecReconcileRemovesOnlyStaleMirageDecisions(t *testing.T) {
	log := &reqLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		switch {
		case r.Method == http.MethodGet:
			// Two of ours (one stale, one active) and one foreign.
			w.Write([]byte(`[
				{"scope": "203.0.113.7", "origin": "mirage"},
				{"scope": "198.51.100.9", "origin": "mirage"},
				{"scope": "192.0.2.5", "origin": "cscli"}
			]`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	now := int64(1_700_000_000_000)
	c := NewCrowdSec(srv.URL, "test-token", func() int64 { return now })
	p, _ := fastPolicy()
	c.policy = p

	// 198.51.100.9 stays (unexpired); 203.0.113.7 is gone from the
	// desired set; the cscli decision is not ours to touch.
	active := []Ban{{IP: "198.51.100.9", Reason: "SIG-099", ExpiresAtMs: now + 60_000}}
	removed, err := c.Reconcile(context.Background(), active, now)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}

	list := log.at(0)
	if list.Method != http.MethodGet || list.Path != "/v1/decisions" || list.Query.Get("origin") != "mirage" {
		t.Fatalf("list request = %s %s?origin=%s", list.Method, list.Path, list.Query.Get("origin"))
	}
	del := log.at(1)
	if del.Method != http.MethodDelete || del.Query.Get("ip") != "203.0.113.7" {
		t.Fatalf("delete request targets %q, want 203.0.113.7 only", del.Query.Get("ip"))
	}
	if got := log.count(); got != 2 {
		t.Fatalf("requests = %d, want 2 (list + one delete; foreign decision untouched)", got)
	}
}

func TestCrowdSecHealthCheck(t *testing.T) {
	log := &reqLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		if r.URL.Path == "/v1/decisions" {
			w.Write([]byte(`[]`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := NewCrowdSec(srv.URL, "test-token", nil)
	p, _ := fastPolicy()
	c.policy = p

	if err := c.HealthCheck(context.Background()); err != nil {
		t.Fatalf("healthy: %v", err)
	}
	req := log.at(0)
	if req.Path != "/v1/decisions" || req.Query.Get("limit") != "1" {
		t.Fatalf("health request = %s?limit=%s, want /v1/decisions?limit=1", req.Path, req.Query.Get("limit"))
	}

	// Wrong token or bad role → 403, and the error must carry the
	// status but never the token (I11).
	c2 := NewCrowdSec(srv.URL+"/broken", "test-token", nil)
	p2, _ := fastPolicy()
	c2.policy = p2
	err := c2.HealthCheck(context.Background())
	if err == nil || !strings.Contains(err.Error(), "crowdsec: health check failed") {
		t.Fatalf("err = %v, want crowdsec health check failure", err)
	}
	if strings.Contains(err.Error(), "test-token") {
		t.Fatal("error leaks the token")
	}
}
