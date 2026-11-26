package connectors

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Webhook is the generic enforcement connector: it POSTs a signed JSON
// ban/unban notice to an owner-configured URL. The receiver is opaque
// to Mirage — anything from a firewall script to an incident bot — so
// the contract stays minimal and verifiable:
//
//   - POST {endpoint} with a JSON body {"ip","reason","note",
//     "created_at_ms","expires_at_ms","action":"ban"|"unban"}.
//   - X-Mirage-Signature carries hex(HMAC-SHA256(secret, body)),
//     computed over the exact bytes sent, so the receiver can
//     authenticate the call end to end.
//
// The secret is copied at construction and never appears in logs or
// error text (I11). Reconcile is a no-op: an opaque receiver offers no
// state to list, and redelivery is the queue's job. HealthCheck only
// validates the endpoint URL — probing an unknown receiver with a real
// request could trigger enforcement side effects, which is exactly what
// a health check must never do.
type Webhook struct {
	endpoint string
	secret   []byte
	client   *http.Client
	policy   retryPolicy
}

// webhookPayload is the wire body; field order matches the documented
// contract.
type webhookPayload struct {
	IP          string `json:"ip"`
	Reason      string `json:"reason"`
	Note        string `json:"note"`
	CreatedAtMs int64  `json:"created_at_ms"`
	ExpiresAtMs int64  `json:"expires_at_ms"`
	Action      string `json:"action"`
}

// NewWebhook sends signed ban notices to endpoint, authenticating with
// an HMAC over the secret. The secret is defensively copied: callers
// may reuse or zero their slice afterwards.
func NewWebhook(endpoint string, secret []byte) *Webhook {
	s := make([]byte, len(secret))
	copy(s, secret)
	return &Webhook{
		endpoint: endpoint,
		secret:   s,
		client:   &http.Client{Timeout: 5 * time.Second},
		policy:   defaultRetryPolicy(),
	}
}

// Name identifies the connector in logs and dashboards.
func (w *Webhook) Name() string { return "webhook" }

// Apply notifies the receiver of a ban (action "ban"). Idempotence is
// the receiver's choice; we guarantee at-least-once delivery with
// authentication.
func (w *Webhook) Apply(ctx context.Context, b Ban) error {
	addr, err := parseBanIP(b)
	if err != nil {
		return fmt.Errorf("webhook: apply: %w", err)
	}
	return w.send(ctx, webhookPayload{
		IP:          addr.String(),
		Reason:      b.Reason,
		Note:        b.Note,
		CreatedAtMs: b.CreatedAtMs,
		ExpiresAtMs: b.ExpiresAtMs,
		Action:      "ban",
	})
}

// Revoke notifies the receiver that a ban is lifted (action "unban").
func (w *Webhook) Revoke(ctx context.Context, b Ban) error {
	addr, err := parseBanIP(b)
	if err != nil {
		return fmt.Errorf("webhook: revoke: %w", err)
	}
	return w.send(ctx, webhookPayload{
		IP:          addr.String(),
		Reason:      b.Reason,
		Note:        b.Note,
		CreatedAtMs: b.CreatedAtMs,
		ExpiresAtMs: b.ExpiresAtMs,
		Action:      "unban",
	})
}

// Reconcile is a no-op: the receiver is opaque, there is no state to
// list, compare or correct. Missed deliveries are the queue's concern.
func (w *Webhook) Reconcile(ctx context.Context, active []Ban, nowMs int64) (int, error) {
	return 0, nil
}

// HealthCheck validates the endpoint configuration without sending
// anything (see the type comment for why a live probe is unsafe here).
func (w *Webhook) HealthCheck(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	u, err := url.Parse(w.endpoint)
	if err != nil {
		return fmt.Errorf("webhook: health check: endpoint URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("webhook: health check: endpoint scheme %q is not http or https", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("webhook: health check: endpoint has no host")
	}
	return nil
}

// send signs and delivers one payload, retrying per the shared policy.
func (w *Webhook) send(ctx context.Context, p webhookPayload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("webhook: encode payload: %w", err)
	}
	// Sign the exact bytes that go on the wire.
	mac := hmac.New(sha256.New, w.secret)
	mac.Write(body) // hash.Write never fails
	sig := hex.EncodeToString(mac.Sum(nil))

	resp, err := w.policy.do(ctx, func() (*http.Response, error) {
		req, rerr := newRequest(ctx, http.MethodPost, w.endpoint, body, "")
		if rerr != nil {
			return nil, rerr
		}
		req.Header.Set("X-Mirage-Signature", sig)
		return w.client.Do(req)
	})
	if err != nil {
		return fmt.Errorf("webhook: %s failed: %w", p.Action, err)
	}
	drainAndClose(resp.Body)
	return nil
}
