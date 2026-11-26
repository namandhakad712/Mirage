// Package store persists decision events, session summaries and ban records
// for Mirage Core. Two interchangeable implementations back the same Store
// interface: a durable SQLite store (WAL mode, append-only events) and an
// in-process memory store used by tests and the worker-parity harness.
//
// Everything that reaches a Store originates from attacker-observable traffic
// (I7): paths, IPs, user agents. The store layer persists evidence verbatim
// (I10) and performs no rendering, so it applies no escaping or truncation of
// its own — every render path (dashboard, logs, exports) must escape and
// length-cap at output time. SQL goes through parameter binding only; SQL
// text is never built from stored or attacker-influenced data.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/mirage-shield/mirage/internal/model"
)

// Limit handling shared by every Store method that takes a limit.
const (
	// DefaultLimit is used when a caller passes limit <= 0.
	DefaultLimit = 100
	// MaxLimit caps unbounded reads; the dashboard never needs more and a
	// runaway caller must not be able to page the whole event log in one go.
	MaxLimit = 1000
)

// ErrClosed is returned once Close has been called. SQLite stores check the
// flag up front so callers see a uniform sentinel; a call that raced past
// the check still fails with a driver error — never silently succeeds.
var ErrClosed = errors.New("store: closed")

// Store is the persistence contract used by Core, the dashboard and the
// parity harness. Every method with a limit follows the same rule: limit
// <= 0 means DefaultLimit, anything above MaxLimit is capped at MaxLimit.
// All methods are safe for concurrent use; after Close every method returns
// an error and Close itself is idempotent.
type Store interface {
	// AppendEvent persists one decision event. Must be safe for concurrent use.
	AppendEvent(ctx context.Context, ev model.Event) error

	// RecentEvents returns events newest-first, at most limit. "Newest" is
	// reverse insertion order: it tracks arrival time and stays well-defined
	// even when adapter-supplied timestamps (attacker-adjacent, I7) collide
	// or skew.
	RecentEvents(ctx context.Context, limit int) ([]model.Event, error)

	// UpsertSessionSummary stores/updates one session summary keyed by SessionKey.
	UpsertSessionSummary(ctx context.Context, s SessionSummary) error

	// SessionSummaries returns summaries newest-first by LastTsMs, at most
	// limit.
	SessionSummaries(ctx context.Context, limit int) ([]SessionSummary, error)

	// BanRecords returns active ban records (ExpiresAtMs > nowMs) newest-first
	// by CreatedAtMs. A ban whose ExpiresAtMs == nowMs is already expired and
	// excluded.
	BanRecords(ctx context.Context, nowMs int64, limit int) ([]BanRecord, error)

	// UpsertBanRecord records a ban decision (idempotent by IP+Reason: a
	// repeat write updates the same row).
	UpsertBanRecord(ctx context.Context, b BanRecord) error

	// Close releases resources. Idempotent; after Close every other method
	// returns an error.
	Close() error
}

// SessionSummary is the rolling per-session aggregate shown on the dashboard.
type SessionSummary struct {
	SessionKey     string
	FirstTsMs      int64
	LastTsMs       int64
	RequestCount   int
	Score          int
	LastVerdict    string
	LastReasonCode string
	// IPHash holds sha256 hex of the client IP when the site's privacy
	// config enables IP hashing (see HashIP). When hash_ips=false the PLAIN
	// IP is stored here unchanged — the field name stays so the schema and
	// interface do not churn per config; render code must consult the
	// privacy config before displaying it.
	IPHash string
}

// BanRecord is one earned ban (I5): high-confidence, short TTL, reversible.
type BanRecord struct {
	// IP is the PLAIN client IP, not a hash. Enforcement matches incoming
	// connections by exact address and one-click reversal (I5) needs the
	// exact address too, so hashing here would break the feature. This is
	// security data: it never leaves the box (I15) and every render path
	// must escape it (I7).
	IP          string
	Reason      string
	CreatedAtMs int64
	ExpiresAtMs int64
	Note        string
	Active      bool
}

// CorruptRowCounter is optionally implemented by stores that can detect
// corrupted payloads on read. Corrupt rows are skipped and counted rather
// than failing the whole read — storage corruption must not take the
// dashboard or Core down (I1 spirit) while the surviving evidence stays
// visible (I10). The in-memory store holds typed structs that cannot rot,
// so it deliberately does not implement this.
type CorruptRowCounter interface {
	// CorruptRowsSkipped reports how many rows have been skipped on read
	// since the store was opened (cumulative: re-reading the same bad row
	// counts again).
	CorruptRowsSkipped() int64
}

// HashIP returns the sha256 hex of a client IP — the value stored in
// SessionSummary.IPHash when the site's privacy config enables IP hashing.
// With hash_ips=false callers store the plain IP instead (see the
// SessionSummary.IPHash doc).
func HashIP(ip string) string {
	sum := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(sum[:])
}

// clampLimit normalizes a caller-supplied limit: <=0 becomes DefaultLimit,
// anything above MaxLimit is capped at MaxLimit.
func clampLimit(limit int) int {
	switch {
	case limit <= 0:
		return DefaultLimit
	case limit > MaxLimit:
		return MaxLimit
	default:
		return limit
	}
}
