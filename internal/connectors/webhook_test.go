package connectors

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebhookApplySignatureAndBody(t *testing.T) {
	log := &reqLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := NewWebhook(srv.URL, []byte("test-secret"))
	p, _ := fastPolicy()
	wh.policy = p

	ban := Ban{IP: "203.0.113.7", Reason: "SIG-104", Note: "tarpit drained", CreatedAtMs: 1_000, ExpiresAtMs: 61_000}
	if err := wh.Apply(context.Background(), ban); err != nil {
		t.Fatalf("apply: %v", err)
	}

	req := log.at(0)
	if req.Method != http.MethodPost || req.Path != "/" {
		t.Fatalf("request = %s %s, want POST /", req.Method, req.Path)
	}
	if ct := req.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	// Recompute the HMAC over the exact bytes received.
	mac := hmac.New(sha256.New, []byte("test-secret"))
	mac.Write(req.Body)
	wantSig := hex.EncodeToString(mac.Sum(nil))
	if got := req.Header.Get("X-Mirage-Signature"); got != wantSig {
		t.Fatalf("signature = %q, want %q", got, wantSig)
	}

	var got webhookPayload
	if err := json.Unmarshal(req.Body, &got); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	want := webhookPayload{
		IP: "203.0.113.7", Reason: "SIG-104", Note: "tarpit drained",
		CreatedAtMs: 1_000, ExpiresAtMs: 61_000, Action: "ban",
	}
	if got != want {
		t.Fatalf("payload = %+v, want %+v", got, want)
	}
}

func TestWebhookUnbanBody(t *testing.T) {
	log := &reqLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := NewWebhook(srv.URL, []byte("s"))
	p, _ := fastPolicy()
	wh.policy = p

	if err := wh.Revoke(context.Background(), Ban{IP: "203.0.113.7", Reason: "SIG-104", CreatedAtMs: 1_000, ExpiresAtMs: 61_000}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	var got webhookPayload
	if err := json.Unmarshal(log.at(0).Body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Action != "unban" || got.IP != "203.0.113.7" || got.Reason != "SIG-104" {
		t.Fatalf("payload = %+v, want unban for 203.0.113.7 with SIG-104", got)
	}
}

func TestWebhookRetries5xxThenSucceeds(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := NewWebhook(srv.URL, []byte("s"))
	p, sleeps := fastPolicy()
	wh.policy = p

	if err := wh.Apply(context.Background(), Ban{IP: "203.0.113.7", Reason: "SIG-104", ExpiresAtMs: 61_000}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := n.Load(); got != 3 {
		t.Fatalf("requests = %d, want 3 (two failures then success)", got)
	}
	delays := sleeps.snapshot()
	if len(delays) != 2 || delays[0] != 500*time.Millisecond || delays[1] != 1000*time.Millisecond {
		t.Fatalf("delays = %v, want [500ms 1s]", delays)
	}
}

func TestWebhookHonorsRetryAfter(t *testing.T) {
	cases := []struct {
		name      string
		header    string
		wantDelay time.Duration
	}{
		{"retry-after seconds", "2", 2 * time.Second},
		{"retry-after capped at 30s", "600", 30 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var n atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if n.Add(1) == 1 {
					w.Header().Set("Retry-After", c.header)
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			wh := NewWebhook(srv.URL, []byte("s"))
			p, sleeps := fastPolicy()
			wh.policy = p

			if err := wh.Apply(context.Background(), Ban{IP: "203.0.113.7", Reason: "SIG-104", ExpiresAtMs: 61_000}); err != nil {
				t.Fatalf("apply: %v", err)
			}
			delays := sleeps.snapshot()
			if len(delays) != 1 || delays[0] != c.wantDelay {
				t.Fatalf("delays = %v, want [%v]", delays, c.wantDelay)
			}
		})
	}
}

func TestWebhookPermanent4xxFailsFastWithoutLeakingSecret(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	const secret = "s3cret-hmac-key"
	wh := NewWebhook(srv.URL, []byte(secret))
	p, sleeps := fastPolicy()
	wh.policy = p

	err := wh.Apply(context.Background(), Ban{IP: "203.0.113.7", Reason: "SIG-104", ExpiresAtMs: 61_000})
	if err == nil {
		t.Fatal("apply must fail on 400")
	}
	if !strings.Contains(err.Error(), "webhook: ban failed: status 400") {
		t.Fatalf("err = %q, want webhook: ban failed: status 400", err)
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1: 4xx is permanent", got)
	}
	if len(sleeps.snapshot()) != 0 {
		t.Fatal("permanent failure must not sleep")
	}
	// I11: the secret must never surface in error text.
	if strings.Contains(err.Error(), secret) {
		t.Fatal("error leaks the HMAC secret")
	}
}

func TestWebhookHealthCheckValidatesWithoutSending(t *testing.T) {
	// A health check must never fire the receiver's ban pipeline, so it
	// validates the endpoint only and sends nothing.
	wh := NewWebhook("https://example.com/hook", []byte("s"))
	if err := wh.HealthCheck(context.Background()); err != nil {
		t.Fatalf("valid endpoint: %v", err)
	}

	bad := NewWebhook("ftp://example.com/hook", []byte("s"))
	if err := bad.HealthCheck(context.Background()); err == nil {
		t.Fatal("non-http scheme must fail health check")
	}

	noHost := NewWebhook("http://", []byte("s"))
	if err := noHost.HealthCheck(context.Background()); err == nil {
		t.Fatal("hostless endpoint must fail health check")
	}
}
