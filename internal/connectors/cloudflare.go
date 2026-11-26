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

// Vendor pin (design section 5: provider APIs are pinned): the
// Cloudflare IP access-rules API under
// api.cloudflare.com/client/v4, zone-scoped:
//
//	POST   {api}/zones/{zone}/firewall/access_rules/rules           — create
//	GET    {api}/zones/{zone}/firewall/access_rules/rules?per_page= — list
//	DELETE {api}/zones/{zone}/firewall/access_rules/rules/{id}      — remove
//	GET    {api}/zones/{zone}                                       — health
//	Auth:  Authorization: Bearer <token>, scoped to one zone (I11)
//
// Ownership and safety: every rule Mirage manages carries the notes
// prefix "mirage: ". Reconcile deletes ONLY rules with that prefix —
// the owner's own rules, and rules belonging to other tools, are never
// touched even when they block the same address.
//
// TTLs: access rules have no native expiry. Mirage owns expiry:
// Reconcile removes mirage-prefixed rules whose address is no longer
// covered by an unexpired ban.

const (
	defaultCloudflareAPI = "https://api.cloudflare.com/client/v4"
	// cfNotePrefix marks a rule as managed by Mirage. It is the safety
	// boundary for every delete path.
	cfNotePrefix = "mirage: "
	// cfMaxPages bounds the pagination walk so a provider bug cannot
	// make us list forever.
	cfMaxPages = 100
	cfPerPage  = 100
)

// Cloudflare blocks addresses with IP access rules in one zone.
type Cloudflare struct {
	mu      sync.Mutex
	api     string // base URL, no trailing slash
	zoneID  string
	token   string
	client  *http.Client
	policy  retryPolicy
	applied map[string]string // normalized IP → rule ID we created
}

// cfConfiguration targets one address; cfRule/cfCreateRule are the
// vendor-pinned payload shapes.
type cfConfiguration struct {
	Target string `json:"target"`
	Value  string `json:"value"`
}

type cfRule struct {
	ID            string          `json:"id"`
	Notes         string          `json:"notes"`
	Mode          string          `json:"mode"`
	Configuration cfConfiguration `json:"configuration"`
}

type cfCreateRule struct {
	Mode          string          `json:"mode"`
	Configuration cfConfiguration `json:"configuration"`
	Notes         string          `json:"notes"`
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
}

type cfListEnvelope struct {
	Success    bool         `json:"success"`
	Errors     []cfAPIError `json:"errors"`
	Result     []cfRule     `json:"result"`
	ResultInfo cfResultInfo `json:"result_info"`
}

type cfMutateEnvelope struct {
	Success bool         `json:"success"`
	Errors  []cfAPIError `json:"errors"`
	Result  cfRule       `json:"result"`
}

// NewCloudflare manages access rules in one zone. An empty apiBase
// selects the production API; tests inject an httptest URL.
func NewCloudflare(apiBase, zoneID, token string) *Cloudflare {
	if apiBase == "" {
		apiBase = defaultCloudflareAPI
	}
	return &Cloudflare{
		api:     strings.TrimRight(apiBase, "/"),
		zoneID:  zoneID,
		token:   token,
		client:  &http.Client{Timeout: 5 * time.Second},
		policy:  defaultRetryPolicy(),
		applied: make(map[string]string),
	}
}

// Name identifies the connector in logs and dashboards.
func (c *Cloudflare) Name() string { return "cloudflare" }

// Apply creates a blocking access rule for the address. Idempotent at
// our layer: if we already track a rule for the address, Apply is a
// no-op. Rules have no TTL, so there is no expiry to recompute.
func (c *Cloudflare) Apply(ctx context.Context, b Ban) error {
	addr, err := parseBanIP(b)
	if err != nil {
		return fmt.Errorf("cloudflare: apply: %w", err)
	}
	ip := addr.String()

	c.mu.Lock()
	if _, ok := c.applied[ip]; ok {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	body, err := json.Marshal(cfCreateRule{
		Mode:          "block",
		Configuration: cfConfiguration{Target: "ip", Value: ip},
		Notes:         cfNotePrefix + b.Reason,
	})
	if err != nil {
		return fmt.Errorf("cloudflare: apply: encode payload: %w", err)
	}

	resp, err := c.policy.do(ctx, func() (*http.Response, error) {
		req, rerr := newRequest(ctx, http.MethodPost, c.rulesURL(), body, c.token)
		if rerr != nil {
			return nil, rerr
		}
		return c.client.Do(req)
	})
	if err != nil {
		return fmt.Errorf("cloudflare: apply failed: %w", err)
	}
	var env cfMutateEnvelope
	if err := decodeJSON(resp, &env); err != nil {
		return fmt.Errorf("cloudflare: apply: %w", err)
	}
	if !env.Success || env.Result.ID == "" {
		return fmt.Errorf("cloudflare: apply failed: %s", cfAPIErrorMessage(env.Errors))
	}

	c.mu.Lock()
	c.applied[ip] = env.Result.ID
	c.mu.Unlock()
	return nil
}

// Revoke removes our rule for the address. It uses the tracked rule ID
// when it has one, and otherwise lists rules to find ours — so a
// restart cannot orphan a rule at the provider. Missing rule is
// success.
func (c *Cloudflare) Revoke(ctx context.Context, b Ban) error {
	addr, err := parseBanIP(b)
	if err != nil {
		return fmt.Errorf("cloudflare: revoke: %w", err)
	}
	ip := addr.String()

	c.mu.Lock()
	id := c.applied[ip]
	c.mu.Unlock()
	if id == "" {
		found, ferr := c.findRule(ctx, ip)
		if ferr != nil {
			return fmt.Errorf("cloudflare: revoke failed: %w", ferr)
		}
		if found == "" {
			return nil // nothing of ours to revoke
		}
		id = found
	}
	if _, err := c.deleteRule(ctx, id); err != nil {
		return fmt.Errorf("cloudflare: revoke failed: %w", err)
	}
	c.mu.Lock()
	delete(c.applied, ip)
	c.mu.Unlock()
	return nil
}

// Reconcile lists the zone's access rules and deletes the stale ones —
// mirage-prefixed rules whose address is not covered by an unexpired
// active ban. Rules without our prefix are never touched.
func (c *Cloudflare) Reconcile(ctx context.Context, active []Ban, nowMs int64) (int, error) {
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

	rules, err := c.listRules(ctx)
	if err != nil {
		return 0, fmt.Errorf("cloudflare: reconcile: %w", err)
	}

	removed := 0
	for _, r := range rules {
		// SAFETY: only rules whose notes carry our prefix are ours.
		// Everything else belongs to the owner or another tool and is
		// untouchable, even when it blocks the same address.
		if !strings.HasPrefix(r.Notes, cfNotePrefix) {
			continue
		}
		if _, ok := keep[r.Configuration.Value]; ok {
			continue // still desired and unexpired
		}
		gone, err := c.deleteRule(ctx, r.ID)
		if err != nil {
			return removed, fmt.Errorf("cloudflare: reconcile: %w", err)
		}
		if gone {
			removed++
		}
	}

	// Forget tracked IDs whose addresses are no longer desired, so a
	// later Apply re-creates the rule.
	c.mu.Lock()
	for ip := range c.applied {
		if _, ok := keep[ip]; !ok {
			delete(c.applied, ip)
		}
	}
	c.mu.Unlock()
	return removed, nil
}

// HealthCheck proves the API answers with valid auth for the zone.
func (c *Cloudflare) HealthCheck(ctx context.Context) error {
	resp, err := c.policy.do(ctx, func() (*http.Response, error) {
		req, rerr := newRequest(ctx, http.MethodGet, c.zoneURL(), nil, c.token)
		if rerr != nil {
			return nil, rerr
		}
		return c.client.Do(req)
	})
	if err != nil {
		return fmt.Errorf("cloudflare: health check failed: %w", err)
	}
	drainAndClose(resp.Body)
	return nil
}

func (c *Cloudflare) zoneURL() string {
	return c.api + "/zones/" + url.PathEscape(c.zoneID)
}

func (c *Cloudflare) rulesURL() string {
	return c.zoneURL() + "/firewall/access_rules/rules"
}

// listRules walks all pages of access rules.
func (c *Cloudflare) listRules(ctx context.Context) ([]cfRule, error) {
	var all []cfRule
	for page := 1; page <= cfMaxPages; page++ {
		q := url.Values{
			"per_page": {strconv.Itoa(cfPerPage)},
			"page":     {strconv.Itoa(page)},
		}
		resp, err := c.policy.do(ctx, func() (*http.Response, error) {
			req, rerr := newRequest(ctx, http.MethodGet, c.rulesURL()+"?"+q.Encode(), nil, c.token)
			if rerr != nil {
				return nil, rerr
			}
			return c.client.Do(req)
		})
		if err != nil {
			return nil, fmt.Errorf("list rules: %w", err)
		}
		var env cfListEnvelope
		if err := decodeJSON(resp, &env); err != nil {
			return nil, fmt.Errorf("list rules: %w", err)
		}
		if !env.Success {
			return nil, fmt.Errorf("list rules: %s", cfAPIErrorMessage(env.Errors))
		}
		all = append(all, env.Result...)
		if len(env.Result) == 0 || page >= env.ResultInfo.TotalPages {
			return all, nil
		}
	}
	// A zone with more than cfMaxPages*100 mirage rules means either a
	// runaway process or a lying provider; stop walking rather than
	// loop forever.
	return nil, fmt.Errorf("list rules: more than %d pages of access rules", cfMaxPages)
}

// findRule looks up the mirage-owned rule blocking an address. Returns
// "" when there is none.
func (c *Cloudflare) findRule(ctx context.Context, ip string) (string, error) {
	rules, err := c.listRules(ctx)
	if err != nil {
		return "", err
	}
	for _, r := range rules {
		if r.Configuration.Value == ip && strings.HasPrefix(r.Notes, cfNotePrefix) {
			return r.ID, nil
		}
	}
	return "", nil
}

// deleteRule removes one access rule. A 404 is success with nothing
// removed: the rule was already gone.
func (c *Cloudflare) deleteRule(ctx context.Context, id string) (bool, error) {
	resp, err := c.policy.do(ctx, func() (*http.Response, error) {
		u := c.rulesURL() + "/" + url.PathEscape(id)
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
		return false, fmt.Errorf("delete rule: %w", err)
	}
	var env cfMutateEnvelope
	if err := decodeJSON(resp, &env); err != nil {
		return false, fmt.Errorf("delete rule: %w", err)
	}
	if !env.Success {
		return false, fmt.Errorf("delete rule: %s", cfAPIErrorMessage(env.Errors))
	}
	return true, nil
}

// cfAPIErrorMessage renders a provider error envelope; provider text
// contains no Mirage secrets.
func cfAPIErrorMessage(errs []cfAPIError) string {
	if len(errs) == 0 {
		return "api reported failure without error details"
	}
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, strconv.Itoa(e.Code)+": "+e.Message)
	}
	return strings.Join(parts, "; ")
}
