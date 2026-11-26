package connectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCloudflareApplyRequestShape(t *testing.T) {
	log := &reqLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rule-9"}}`))
	}))
	defer srv.Close()

	c := NewCloudflare(srv.URL, "zone-1", "cf-token")
	p, _ := fastPolicy()
	c.policy = p

	if err := c.Apply(context.Background(), Ban{IP: "203.0.113.7", Reason: "SIG-104", ExpiresAtMs: 61_000}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	req := log.at(0)
	if req.Method != http.MethodPost || req.Path != "/zones/zone-1/firewall/access_rules/rules" {
		t.Fatalf("request = %s %s, want POST /zones/zone-1/firewall/access_rules/rules", req.Method, req.Path)
	}
	if auth := req.Header.Get("Authorization"); auth != "Bearer cf-token" {
		t.Fatalf("authorization = %q, want Bearer cf-token", auth)
	}
	// The notes prefix is the ownership marker every delete path relies
	// on, and mode/configuration carry the block target.
	wantBody := `{"mode":"block","configuration":{"target":"ip","value":"203.0.113.7"},"notes":"mirage: SIG-104"}`
	if got := string(req.Body); got != wantBody {
		t.Fatalf("body = %s, want %s", got, wantBody)
	}
}

func TestCloudflareApplyIdempotentTracked(t *testing.T) {
	log := &reqLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rule-9"}}`))
	}))
	defer srv.Close()

	c := NewCloudflare(srv.URL, "zone-1", "cf-token")
	p, _ := fastPolicy()
	c.policy = p

	ban := Ban{IP: "203.0.113.7", Reason: "SIG-104", ExpiresAtMs: 61_000}
	for i := 0; i < 2; i++ {
		if err := c.Apply(context.Background(), ban); err != nil {
			t.Fatalf("apply #%d: %v", i+1, err)
		}
	}
	if got := log.count(); got != 1 {
		t.Fatalf("requests = %d, want 1 (tracked apply is a no-op)", got)
	}
}

func TestCloudflareRevokeUsesTrackedID(t *testing.T) {
	log := &reqLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		switch r.Method {
		case http.MethodPost:
			w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rule-9"}}`))
		case http.MethodDelete:
			w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rule-9"}}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	c := NewCloudflare(srv.URL, "zone-1", "cf-token")
	p, _ := fastPolicy()
	c.policy = p

	if err := c.Apply(context.Background(), Ban{IP: "203.0.113.7", Reason: "SIG-104", ExpiresAtMs: 61_000}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := c.Revoke(context.Background(), Ban{IP: "203.0.113.7"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// The tracked rule ID lets revoke skip the listing entirely.
	if got := log.count(); got != 2 {
		t.Fatalf("requests = %d, want 2 (create + delete, no list)", got)
	}
	del := log.at(1)
	if del.Method != http.MethodDelete || del.Path != "/zones/zone-1/firewall/access_rules/rules/rule-9" {
		t.Fatalf("delete = %s %s, want DELETE .../rules/rule-9", del.Method, del.Path)
	}

	// After the revoke the address is untracked: a new apply creates a
	// fresh rule instead of no-op-ing on stale state.
	if err := c.Apply(context.Background(), Ban{IP: "203.0.113.7", Reason: "SIG-104", ExpiresAtMs: 61_000}); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if got := log.count(); got != 3 {
		t.Fatalf("requests = %d, want 3 after re-apply", got)
	}
}

func TestCloudflareRevokeMissingIsSuccess(t *testing.T) {
	log := &reqLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Write([]byte(`{"success":true,"errors":[],"result":[],"result_info":{"page":1,"per_page":100,"total_pages":1}}`))
	}))
	defer srv.Close()

	c := NewCloudflare(srv.URL, "zone-1", "cf-token")
	p, _ := fastPolicy()
	c.policy = p

	// No tracked ID and no mirage rule at the provider: success, and no
	// DELETE was ever issued.
	if err := c.Revoke(context.Background(), Ban{IP: "203.0.113.7"}); err != nil {
		t.Fatalf("revoke missing: %v", err)
	}
	if got := log.count(); got != 1 {
		t.Fatalf("requests = %d, want 1 (the lookup list only)", got)
	}
	if got := log.at(0).Method; got != http.MethodGet {
		t.Fatalf("request = %s, want GET", got)
	}
}

func TestCloudflareReconcileDeletesOnlyMirageNotes(t *testing.T) {
	log := &reqLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		switch r.Method {
		case http.MethodGet:
			// m-stale: ours, no longer desired. m-active: ours and
			// wanted. foreign: an owner rule that happens to block the
			// same address as m-stale — prefix, not IP, decides.
			// m-expired: ours, desired but past our TTL.
			w.Write([]byte(`{"success":true,"errors":[],"result":[
                                {"id":"m-stale","notes":"mirage: SIG-104","mode":"block","configuration":{"target":"ip","value":"203.0.113.7"}},
                                {"id":"m-active","notes":"mirage: SIG-099","mode":"block","configuration":{"target":"ip","value":"198.51.100.9"}},
                                {"id":"foreign","notes":"block bad bot","mode":"block","configuration":{"target":"ip","value":"203.0.113.7"}},
                                {"id":"m-expired","notes":"mirage: SIG-101","mode":"block","configuration":{"target":"ip","value":"192.0.2.5"}}
                        ],"result_info":{"page":1,"per_page":100,"total_pages":1}}`))
		case http.MethodDelete:
			w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"gone"}}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	now := int64(1_700_000_000_000)
	c := NewCloudflare(srv.URL, "zone-1", "cf-token")
	p, _ := fastPolicy()
	c.policy = p

	// 198.51.100.9 is active and unexpired; 192.0.2.5 is active but
	// already past our TTL — we own expiry, so its rule must go.
	active := []Ban{
		{IP: "198.51.100.9", Reason: "SIG-099", ExpiresAtMs: now + 60_000},
		{IP: "192.0.2.5", Reason: "SIG-101", ExpiresAtMs: now - 1},
	}
	removed, err := c.Reconcile(context.Background(), active, now)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2 (stale + expired)", removed)
	}

	var deleted []string
	for i := 1; i < log.count(); i++ {
		req := log.at(i)
		if req.Method != http.MethodDelete {
			t.Fatalf("request %d = %s, want DELETE", i, req.Method)
		}
		deleted = append(deleted, strings.TrimPrefix(req.Path, "/zones/zone-1/firewall/access_rules/rules/"))
	}
	if strings.Join(deleted, ",") != "m-stale,m-expired" {
		t.Fatalf("deleted = %v, want [m-stale m-expired]; the foreign rule must be untouched", deleted)
	}
}

func TestCloudflareReconcilePaginates(t *testing.T) {
	log := &reqLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		if r.Method == http.MethodDelete {
			w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"gone"}}`))
			return
		}
		switch r.URL.Query().Get("page") {
		case "1":
			w.Write([]byte(`{"success":true,"errors":[],"result":[
                                {"id":"m-a","notes":"mirage: SIG-104","configuration":{"target":"ip","value":"203.0.113.7"}}
                        ],"result_info":{"page":1,"per_page":100,"total_pages":2}}`))
		case "2":
			w.Write([]byte(`{"success":true,"errors":[],"result":[
                                {"id":"m-b","notes":"mirage: SIG-099","configuration":{"target":"ip","value":"198.51.100.9"}}
                        ],"result_info":{"page":2,"per_page":100,"total_pages":2}}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	c := NewCloudflare(srv.URL, "zone-1", "cf-token")
	p, _ := fastPolicy()
	c.policy = p

	removed, err := c.Reconcile(context.Background(), nil, 1_700_000_000_000)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2 (one stale rule per page)", removed)
	}
	first, second := log.at(0), log.at(1)
	if first.Query.Get("page") != "1" || second.Query.Get("page") != "2" {
		t.Fatalf("pages walked = %s, %s", first.Query.Get("page"), second.Query.Get("page"))
	}
	if first.Query.Get("per_page") != "100" {
		t.Fatalf("per_page = %s, want 100", first.Query.Get("per_page"))
	}
}

func TestCloudflareHealthCheck(t *testing.T) {
	log := &reqLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		if r.URL.Path == "/zones/zone-1" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := NewCloudflare(srv.URL, "zone-1", "cf-token")
	p, _ := fastPolicy()
	c.policy = p

	if err := c.HealthCheck(context.Background()); err != nil {
		t.Fatalf("healthy: %v", err)
	}
	req := log.at(0)
	if req.Path != "/zones/zone-1" || req.Header.Get("Authorization") != "Bearer cf-token" {
		t.Fatalf("health request = %s %s, want GET /zones/zone-1 with bearer auth", req.Method, req.Path)
	}

	// Bad token or wrong zone → 403, and the error must carry the
	// status but never the token (I11).
	c2 := NewCloudflare(srv.URL, "zone-denied", "cf-token")
	p2, _ := fastPolicy()
	c2.policy = p2
	err := c2.HealthCheck(context.Background())
	if err == nil || !strings.Contains(err.Error(), "cloudflare: health check failed: status 403") {
		t.Fatalf("err = %v, want cloudflare health check status 403", err)
	}
	if strings.Contains(err.Error(), "cf-token") {
		t.Fatal("error leaks the token")
	}
}
