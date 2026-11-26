package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Vendor pin (design section 5: provider APIs are pinned): CrowdSec
// LAPI v1, the /v1/* surface, with these endpoints and shapes:
//
//	POST   {lapi}/v1/alerts                    — create alert + decision
//	GET    {lapi}/v1/decisions?origin=mirage   — list our decisions
//	DELETE {lapi}/v1/decisions?ip=ADDR         — delete decisions for ADDR
//	Auth:  Authorization: Bearer <token>
//
// The POST body carries one alert with a single ban decision:
// {"capacity":0,"events":[{"meta":{"log_source":"mirage"},"timestamp":
// <RFC3339>}],"decisions":[{"duration":"30m","reason":"mirage: SIG-104",
// "scope":"1.2.3.4","type":"ban","origin":"mirage"}],"source":"mirage",
// "start_at":<RFC3339>}. In this profile the decision "scope" carries
// the address itself.
//
// Revoke deliberately does NOT use the alerts delete endpoint: removing
// whole alerts proved unreliable for per-address removal, so
// revocation goes through the decisions endpoint filtered by ip.
//
// TTLs are computed by Mirage: duration is ceil((ExpiresAtMs - now)/1m)
// from the injected clock, and the provider's own expiry is never read
// back. Idempotency is enforced at our layer (applied-set keyed by
// address+reason) because the alerts endpoint would happily accept
// duplicates.

// mirageOrigin is stamped on every CrowdSec object we create so list
// and delete operations can recognize our own decisions and never touch
// anyone else's.
const mirageOrigin = "mirage"

// CrowdSec bans addresses through a local CrowdSec LAPI.
type CrowdSec struct {
	mu      sync.Mutex
	lapi    string // base URL, no trailing slash
	token   string
	now     func() int64
	client  *http.Client
	policy  retryPolicy
	applied map[banKey]int64 // ban → our imposed expiry, for idempotence
}

// banKey identifies an applied ban at our layer: address plus reason.
// A new reason for the same address is a new ban (new evidence) and
// must reach the provider again.
type banKey struct {
	ip     string
	reason string
}

// csAlert is the POST /v1/alerts body (vendor-pinned shape).
type csAlert struct {
	Capacity  int          `json:"capacity"`
	Events    []csEvent    `json:"events"`
	Decisions []csDecision `json:"decisions"`
	Source    string       `json:"source"`
	StartAt   string       `json:"start_at"`
}

type csEvent struct {
	Meta      map[string]string `json:"meta"`
	Timestamp string            `json:"timestamp"`
}

type csDecision struct {
	Duration string `json:"duration"`
	Reason   string `json:"reason"`
	Scope    string `json:"scope"`
	Type     string `json:"type"`
	Origin   string `json:"origin"`
}

// csDecisionInfo is one entry of what GET /v1/decisions returns: the
// fields needed to find and delete our own decisions.
type csDecisionInfo struct {
	Scope  string `json:"scope"`
	Origin string `json:"origin"`
}

// NewCrowdSec talks to the LAPI at lapiURL with a Bearer token. now is
// the clock TTLs are computed from; nil means wall time.
func NewCrowdSec(lapiURL, token string, now func() int64) *CrowdSec {
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	return &CrowdSec{
		lapi:    strings.TrimRight(lapiURL, "/"),
		token:   token,
		now:     now,
		client:  &http.Client{Timeout: 5 * time.Second},
		policy:  defaultRetryPolicy(),
		applied: make(map[banKey]int64),
	}
}

// Name identifies the connector in logs and dashboards.
func (c *CrowdSec) Name() string { return "crowdsec" }

// Apply creates the ban decision. Idempotent at our layer: re-applying
// the same address+reason while our previous entry is unexpired is a
// no-op success, so queue retries do not spam duplicate alerts.
func (c *CrowdSec) Apply(ctx context.Context, b Ban) error {
	addr, err := parseBanIP(b)
	if err != nil {
		return fmt.Errorf("crowdsec: apply: %w", err)
	}
	now := c.now()
	if b.ExpiresAtMs <= now {
		// The engine already retired this ban; enforcing stale evidence
		// is never right. Refuse so the queue can drop and log it.
		return fmt.Errorf("crowdsec: apply: ban for %q expired before apply", addr.String())
	}

	key := banKey{ip: addr.String(), reason: b.Reason}
	c.mu.Lock()
	if exp, ok := c.applied[key]; ok && exp > now {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	nowRFC := time.UnixMilli(now).UTC().Format(time.RFC3339)
	payload := csAlert{
		Capacity: 0,
		Events: []csEvent{{
			Meta:      map[string]string{"log_source": mirageOrigin},
			Timestamp: nowRFC,
		}},
		Decisions: []csDecision{{
			Duration: crowdsecDuration(b.ExpiresAtMs - now),
			Reason:   "mirage: " + b.Reason,
			Scope:    addr.String(),
			Type:     "ban",
			Origin:   mirageOrigin,
		}},
		Source:  mirageOrigin,
		StartAt: nowRFC,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("crowdsec: apply: encode payload: %w", err)
	}

	resp, err := c.policy.do(ctx, func() (*http.Response, error) {
		req, rerr := newRequest(ctx, http.MethodPost, c.lapi+"/v1/alerts", body, c.token)
		if rerr != nil {
			return nil, rerr
		}
		return c.client.Do(req)
	})
	if err != nil {
		return fmt.Errorf("crowdsec: apply failed: %w", err)
	}
	drainAndClose(resp.Body)

	c.mu.Lock()
	c.applied[key] = b.ExpiresAtMs
	c.mu.Unlock()
	return nil
}

// Revoke deletes every CrowdSec decision for the address. The endpoint
// removes by ip regardless of reason, so all our tracked entries for
// the address go too.
func (c *CrowdSec) Revoke(ctx context.Context, b Ban) error {
	addr, err := parseBanIP(b)
	if err != nil {
		return fmt.Errorf("crowdsec: revoke: %w", err)
	}
	ip := addr.String()
	if _, err := c.deleteDecisionsForIP(ctx, ip); err != nil {
		return fmt.Errorf("crowdsec: revoke failed: %w", err)
	}
	c.mu.Lock()
	for k := range c.applied {
		if k.ip == ip {
			delete(c.applied, k)
		}
	}
	c.mu.Unlock()
	return nil
}

// Reconcile lists our decisions at the provider and deletes the stale
// ones: anything not covered by an unexpired active ban. Foreign-origin
// decisions are never touched, even in answer to a provider bug.
func (c *CrowdSec) Reconcile(ctx context.Context, active []Ban, nowMs int64) (int, error) {
	keep := make(map[string]struct{}, len(active))
	for _, b := range active {
		if b.ExpiresAtMs <= nowMs {
			continue // expired: we stop enforcing it
		}
		addr, err := parseBanIP(b)
		if err != nil {
			continue // not enforceable; the service layer logs it
		}
		keep[addr.String()] = struct{}{}
	}

	resp, err := c.policy.do(ctx, func() (*http.Response, error) {
		u := c.lapi + "/v1/decisions?" + url.Values{"origin": {mirageOrigin}}.Encode()
		req, rerr := newRequest(ctx, http.MethodGet, u, nil, c.token)
		if rerr != nil {
			return nil, rerr
		}
		return c.client.Do(req)
	})
	if err != nil {
		return 0, fmt.Errorf("crowdsec: reconcile: list decisions: %w", err)
	}
	var decisions []csDecisionInfo
	if err := decodeJSON(resp, &decisions); err != nil {
		return 0, fmt.Errorf("crowdsec: reconcile: %w", err)
	}

	removed := 0
	for _, d := range decisions {
		// Defense in depth: the query already filters by origin, but we
		// only ever delete decisions we actually created.
		if d.Origin != mirageOrigin {
			continue
		}
		if _, ok := keep[d.Scope]; ok {
			continue // still desired and unexpired
		}
		gone, err := c.deleteDecisionsForIP(ctx, d.Scope)
		if err != nil {
			return removed, fmt.Errorf("crowdsec: reconcile: %w", err)
		}
		if gone {
			removed++
		}
	}

	// Forget applied-set entries that expired or were removed, so a
	// future Apply re-creates them instead of no-op-ing on stale state.
	c.mu.Lock()
	for k, exp := range c.applied {
		if _, ok := keep[k.ip]; !ok || exp <= nowMs {
			delete(c.applied, k)
		}
	}
	c.mu.Unlock()
	return removed, nil
}

// HealthCheck proves the LAPI answers with valid auth: a one-decision
// list request, 2xx means healthy.
func (c *CrowdSec) HealthCheck(ctx context.Context) error {
	resp, err := c.policy.do(ctx, func() (*http.Response, error) {
		u := c.lapi + "/v1/decisions?" + url.Values{"limit": {"1"}}.Encode()
		req, rerr := newRequest(ctx, http.MethodGet, u, nil, c.token)
		if rerr != nil {
			return nil, rerr
		}
		return c.client.Do(req)
	})
	if err != nil {
		return fmt.Errorf("crowdsec: health check failed: %w", err)
	}
	drainAndClose(resp.Body)
	return nil
}

// deleteDecisionsForIP removes all provider decisions for one address.
// A 404 is success with nothing removed: there was nothing to delete.
func (c *CrowdSec) deleteDecisionsForIP(ctx context.Context, ip string) (bool, error) {
	resp, err := c.policy.do(ctx, func() (*http.Response, error) {
		u := c.lapi + "/v1/decisions?" + url.Values{"ip": {ip}}.Encode()
		req, rerr := newRequest(ctx, http.MethodDelete, u, nil, c.token)
		if rerr != nil {
			return nil, rerr
		}
		return c.client.Do(req)
	})
	if err != nil {
		var se statusError
		if errors.As(err, &se) && se.code == http.StatusNotFound {
			return false, nil
		}
		return false, fmt.Errorf("delete decisions for %q: %w", ip, err)
	}
	drainAndClose(resp.Body)
	return true, nil
}

// crowdsecDuration renders our TTL as CrowdSec's "NNm" duration string:
// minutes, rounded up so the provider never expires a ban before we do.
// Values at or below zero clamp to one minute — CrowdSec rejects
// non-positive durations — but Apply refuses already-expired bans long
// before this matters; the clamp only covers sub-minute remainders.
func crowdsecDuration(ttlMs int64) string {
	mins := (ttlMs + 59_999) / 60_000
	if mins < 1 {
		mins = 1
	}
	return strconv.FormatInt(mins, 10) + "m"
}
