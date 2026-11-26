// Package connectors implements the enforcement connectors (design
// section 5): the adapters that make a ban exist — and stop existing —
// at a provider, whether that provider is a local deny map file,
// CrowdSec, Cloudflare or an owner's webhook.
//
// Contract shared by every connector:
//
//   - Apply and Revoke are idempotent: a retry after success is a no-op
//     or a harmless duplicate the provider tolerates.
//   - Revoking a ban that does not exist is success.
//   - Reconcile walks provider state and removes bans that are expired
//     or no longer desired but still enforced there, so a missed or
//     crashed call heals itself. It only removes; re-adding desired
//     bans is the service layer's job.
//   - TTLs belong to Mirage: durations sent to providers are computed
//     from Ban.ExpiresAtMs and never read back from the provider.
//   - HTTP calls retry with exponential backoff plus jitter and honor
//     429 Retry-After.
//   - Secrets (tokens, HMAC keys) appear in headers only — never in
//     URLs, logs or error text (I11).
//
// The design's dry-run "Plan" step is a service-layer concern: it
// composes the same Ban values these connectors consume, so the
// connector surface stays small and side-effecting.
package connectors

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// Ban is one enforcement record as the service layer sees it. IP is a
// bare address (no port, no CIDR); connectors validate and normalize
// it, because the value travels into deny files, URL query strings and
// provider payloads, and only a validated address is safe in all three
// (I7). Reason is a stable reason code (SIG-nnn); Note carries bounded
// context for receivers that want it.
type Ban struct {
	IP          string
	Reason      string
	Note        string
	CreatedAtMs int64
	ExpiresAtMs int64
}

// Connector is the provider-facing half of enforcement. Implementations
// must be safe for concurrent use.
type Connector interface {
	// Name identifies the connector in logs and dashboards.
	Name() string

	// Apply makes the ban exist at the provider. Idempotent.
	Apply(ctx context.Context, b Ban) error

	// Revoke removes it. Idempotent: revoking a non-existent ban is
	// success.
	Revoke(ctx context.Context, b Ban) error

	// Reconcile syncs desired vs actual state: it removes expired bans
	// that still exist at the provider. active is the set of bans the
	// service still wants enforced; nowMs is the evaluation time.
	// Returns the number of corrections applied.
	Reconcile(ctx context.Context, active []Ban, nowMs int64) (removed int, err error)

	// HealthCheck verifies the connector can reach its provider (or,
	// for the deny file, that its directory is writable).
	HealthCheck(ctx context.Context) error
}

// Compile-time proof that every built-in satisfies the interface.
var (
	_ Connector = (*DenyFile)(nil)
	_ Connector = (*Webhook)(nil)
	_ Connector = (*CrowdSec)(nil)
	_ Connector = (*Cloudflare)(nil)
)

// parseBanIP validates and normalizes a ban address, stripping any
// incidental whitespace. Connectors refuse anything that is not a
// single bare IP: a crafted value must not become file, URL or log
// injection (I7).
func parseBanIP(b Ban) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(b.IP))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid ip %q", b.IP)
	}
	return a.Unmap(), nil
}
