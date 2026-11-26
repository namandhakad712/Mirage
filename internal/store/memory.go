package store

import (
	"context"
	"sort"
	"sync"

	"github.com/mirage-shield/mirage/internal/model"
)

// MemoryStore is the in-process Store for tests and the worker-parity
// harness. Its semantics mirror SQLiteStore exactly — same limit clamping,
// same newest-first orders, same upsert keys, same closed-store behavior —
// so a harness can run both side by side and diff the results. It holds
// typed structs that cannot rot, so it deliberately does not implement
// CorruptRowCounter.
//
// One mutex guards everything: the traffic here is test and harness volume,
// not production load, and a single lock makes the parity semantics trivial
// to reason about.
type MemoryStore struct {
	mu     sync.Mutex
	closed bool
	// events is in insertion order; the tail is the newest.
	events   []model.Event
	sessions map[string]SessionSummary
	bans     map[banKey]BanRecord
}

// banKey is the composite (ip, reason) upsert key. A struct key cannot
// collide the way string concatenation can when attacker data contains the
// separator.
type banKey struct {
	ip     string
	reason string
}

// NewMemoryStore returns an empty in-process store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]SessionSummary),
		bans:     make(map[banKey]BanRecord),
	}
}

// AppendEvent implements Store. ctx is accepted for interface parity;
// in-memory operations never block, so there is nothing to cancel.
func (m *MemoryStore) AppendEvent(_ context.Context, ev model.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.events = append(m.events, ev)
	return nil
}

// RecentEvents implements Store: newest-first is reverse insertion order,
// matching the SQLite id ordering.
func (m *MemoryStore) RecentEvents(_ context.Context, limit int) ([]model.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	limit = clampLimit(limit)
	out := make([]model.Event, 0, min(limit, len(m.events)))
	for i := len(m.events) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, m.events[i])
	}
	return out, nil
}

// UpsertSessionSummary implements Store.
func (m *MemoryStore) UpsertSessionSummary(_ context.Context, sum SessionSummary) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.sessions[sum.SessionKey] = sum
	return nil
}

// SessionSummaries implements Store, with the same (last_ts_ms, session_key)
// DESC ordering as SQLite so tie cases page identically.
func (m *MemoryStore) SessionSummaries(_ context.Context, limit int) ([]SessionSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	limit = clampLimit(limit)
	out := make([]SessionSummary, 0, min(limit, len(m.sessions)))
	for _, sum := range m.sessions {
		out = append(out, sum)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastTsMs != out[j].LastTsMs {
			return out[i].LastTsMs > out[j].LastTsMs
		}
		return out[i].SessionKey > out[j].SessionKey
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// BanRecords implements Store: active, unexpired bans newest-first, with
// the same (created_at_ms, ip, reason) DESC tiebreak as SQLite.
func (m *MemoryStore) BanRecords(_ context.Context, nowMs int64, limit int) ([]BanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	limit = clampLimit(limit)
	out := make([]BanRecord, 0)
	for _, b := range m.bans {
		if b.Active && b.ExpiresAtMs > nowMs {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAtMs != out[j].CreatedAtMs {
			return out[i].CreatedAtMs > out[j].CreatedAtMs
		}
		if out[i].IP != out[j].IP {
			return out[i].IP > out[j].IP
		}
		return out[i].Reason > out[j].Reason
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// UpsertBanRecord implements Store: idempotent on (IP, Reason).
func (m *MemoryStore) UpsertBanRecord(_ context.Context, b BanRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.bans[banKey{ip: b.IP, reason: b.Reason}] = b
	return nil
}

// Close implements Store. It drops all held state — the memory store is not
// durable by design; persistence is SQLiteStore's job.
func (m *MemoryStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	m.events = nil
	m.sessions = nil
	m.bans = nil
	return nil
}
