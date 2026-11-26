package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/mirage-shield/mirage/internal/model"
)

// newStores returns every Store implementation so the whole suite runs
// against both (the parity requirement): memory in-process, SQLite on a
// temp file. Tests needing white-box access to SQLite type-assert
// *SQLiteStore — this file lives in the package on purpose.
func newStores(t *testing.T) []struct {
	name string
	s    Store
} {
	t.Helper()
	memory := NewMemoryStore()
	dir := t.TempDir()
	sq, err := OpenSQLite(context.Background(), filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatalf("open sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = memory.Close()
		_ = sq.Close()
	})
	return []struct {
		name string
		s    Store
	}{
		{"memory", memory},
		{"sqlite", sq},
	}
}

// testDecision is a fully populated decision for roundtrip checks.
func testDecision() *model.Decision {
	ttl := int64(1_800_000)
	return &model.Decision{
		ProtocolVersion: model.ProtocolVersion,
		SpecVersion:     model.SpecVersion,
		Verdict:         model.VerdictDecoyRoute,
		Action:          model.ActionServeDecoy,
		DecoyID:         "env-file-staging",
		SessionKey:      "fec52565aa0cf18f57d7cf5b3ac72850",
		ReasonCode:      "SIG-101",
		RequestScore:    25,
		Score:           25,
		Signals:         []string{"scanner_path", "suspicious_ua"},
		BanTTLms:        &ttl,
	}
}

// testEvent builds a fixture. IPs stay in the reserved documentation ranges
// (I14) so test data can never look like a real host.
func testEvent(ts int64, session, path string, d *model.Decision) model.Event {
	return model.Event{
		ProtocolVersion: model.ProtocolVersion,
		TsMs:            ts,
		SessionKey:      session,
		ClientIP:        "203.0.113.7",
		Method:          "GET",
		Path:            path,
		Decision:        d,
	}
}

func TestClampLimit(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{in: -5, want: DefaultLimit},
		{in: 0, want: DefaultLimit},
		{in: 1, want: 1},
		{in: 99, want: 99},
		{in: 100, want: 100},
		{in: 1000, want: 1000},
		{in: 1001, want: MaxLimit},
		{in: 1_000_000, want: MaxLimit},
	}
	for _, tc := range cases {
		if got := clampLimit(tc.in); got != tc.want {
			t.Errorf("clampLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestHashIP(t *testing.T) {
	// Known-answer vectors: sha256 of the reserved-range IP and of "".
	cases := map[string]string{
		"203.0.113.7": "fec52565aa0cf18f57d7cf5b3ac728503b8992d2d6f7d46da1d1201090902b02",
		"":            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	for ip, want := range cases {
		if got := HashIP(ip); got != want {
			t.Errorf("HashIP(%q) = %q, want %q", ip, got, want)
		}
	}
	// The session key is a truncation of the same digest; the full hash must
	// be longer, never equal.
	if HashIP("203.0.113.7") == model.SessionKey("203.0.113.7") {
		t.Error("HashIP must return the full 64-char digest, not the 32-char session key")
	}
}

func TestRecentEventsEmpty(t *testing.T) {
	for _, tc := range newStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.s.RecentEvents(context.Background(), 0)
			if err != nil {
				t.Fatalf("RecentEvents on empty store: %v", err)
			}
			if got == nil {
				t.Fatal("RecentEvents must return a non-nil slice, got nil")
			}
			if len(got) != 0 {
				t.Fatalf("RecentEvents on empty store returned %d events, want 0", len(got))
			}
		})
	}
}

func TestRecentEventsRoundtripNewestFirst(t *testing.T) {
	for _, tc := range newStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			appended := []model.Event{
				testEvent(1000, "sess-a", "/.env", testDecision()),
				testEvent(2000, "sess-a", "/wp-admin/setup.php", nil),
				testEvent(3000, "sess-b", "/admin/config.yml", testDecision()),
			}
			for _, ev := range appended {
				if err := tc.s.AppendEvent(ctx, ev); err != nil {
					t.Fatalf("AppendEvent: %v", err)
				}
			}
			got, err := tc.s.RecentEvents(ctx, 0)
			if err != nil {
				t.Fatalf("RecentEvents: %v", err)
			}
			if len(got) != len(appended) {
				t.Fatalf("RecentEvents returned %d events, want %d", len(got), len(appended))
			}
			// Newest-first: reverse of the append order.
			for i, want := range []model.Event{appended[2], appended[1], appended[0]} {
				if got[i].TsMs != want.TsMs || got[i].SessionKey != want.SessionKey ||
					got[i].ClientIP != want.ClientIP || got[i].Method != want.Method ||
					got[i].Path != want.Path || got[i].ProtocolVersion != want.ProtocolVersion {
					t.Errorf("event %d = %+v, want %+v", i, got[i], want)
				}
				if (got[i].Decision == nil) != (want.Decision == nil) {
					t.Errorf("event %d decision presence = %v, want %v", i, got[i].Decision != nil, want.Decision != nil)
				}
			}
		})
	}
}

func TestRecentEventsLimit(t *testing.T) {
	for _, tc := range newStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			for i := 1; i <= 3; i++ {
				if err := tc.s.AppendEvent(ctx, testEvent(int64(i)*1000, "sess", fmt.Sprintf("/p%d", i), nil)); err != nil {
					t.Fatalf("AppendEvent: %v", err)
				}
			}
			// Explicit limit below the stored count: the newest win.
			got, err := tc.s.RecentEvents(ctx, 2)
			if err != nil {
				t.Fatalf("RecentEvents(2): %v", err)
			}
			if len(got) != 2 || got[0].TsMs != 3000 || got[1].TsMs != 2000 {
				t.Fatalf("RecentEvents(2) = %+v, want ts [3000 2000]", got)
			}
			// Negative limit takes the default (100), which covers all 3.
			got, err = tc.s.RecentEvents(ctx, -1)
			if err != nil {
				t.Fatalf("RecentEvents(-1): %v", err)
			}
			if len(got) != 3 {
				t.Fatalf("RecentEvents(-1) returned %d events, want 3 (default limit)", len(got))
			}
		})
	}
}

func TestAppendEventDecisionRoundtrip(t *testing.T) {
	for _, tc := range newStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			// nil decision must survive as nil (stored as NULL).
			if err := tc.s.AppendEvent(ctx, testEvent(1000, "sess-nil", "/a", nil)); err != nil {
				t.Fatalf("AppendEvent(nil decision): %v", err)
			}
			// Fully populated decision must survive field-for-field.
			full := testDecision()
			if err := tc.s.AppendEvent(ctx, testEvent(2000, "sess-full", "/b", full)); err != nil {
				t.Fatalf("AppendEvent(full decision): %v", err)
			}
			got, err := tc.s.RecentEvents(ctx, 10)
			if err != nil {
				t.Fatalf("RecentEvents: %v", err)
			}
			if len(got) != 2 {
				t.Fatalf("got %d events, want 2", len(got))
			}
			if got[0].Decision == nil || !reflect.DeepEqual(got[0].Decision, full) {
				t.Errorf("full decision = %+v, want %+v", got[0].Decision, full)
			}
			if got[1].Decision != nil {
				t.Errorf("nil decision came back as %+v, want nil", got[1].Decision)
			}
		})
	}
}

func TestSessionSummaryUpsertOverwrite(t *testing.T) {
	for _, tc := range newStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			first := SessionSummary{
				SessionKey: "sess-a", FirstTsMs: 1000, LastTsMs: 2000,
				RequestCount: 5, Score: 40, LastVerdict: model.VerdictTag,
				LastReasonCode: "SIG-201", IPHash: HashIP("203.0.113.7"),
			}
			if err := tc.s.UpsertSessionSummary(ctx, first); err != nil {
				t.Fatalf("UpsertSessionSummary(first): %v", err)
			}
			other := SessionSummary{
				SessionKey: "sess-b", FirstTsMs: 1500, LastTsMs: 2500,
				RequestCount: 2, Score: 10, LastVerdict: model.VerdictObserve,
				LastReasonCode: "SIG-000", IPHash: HashIP("198.51.100.9"),
			}
			if err := tc.s.UpsertSessionSummary(ctx, other); err != nil {
				t.Fatalf("UpsertSessionSummary(other): %v", err)
			}
			// Overwrite sess-a: same key, new values.
			overwrite := SessionSummary{
				SessionKey: "sess-a", FirstTsMs: 1000, LastTsMs: 9000,
				RequestCount: 42, Score: 95, LastVerdict: model.VerdictBan,
				LastReasonCode: "SIG-401", IPHash: HashIP("203.0.113.7"),
			}
			if err := tc.s.UpsertSessionSummary(ctx, overwrite); err != nil {
				t.Fatalf("UpsertSessionSummary(overwrite): %v", err)
			}
			got, err := tc.s.SessionSummaries(ctx, 10)
			if err != nil {
				t.Fatalf("SessionSummaries: %v", err)
			}
			if len(got) != 2 {
				t.Fatalf("got %d summaries, want 2 (overwrite must not add a row)", len(got))
			}
			if got[0] != overwrite || got[1] != other {
				t.Errorf("summaries = [%+v %+v], want [overwrite %+v, other %+v] (newest first)",
					got[0], got[1], overwrite, other)
			}
		})
	}
}

func TestSessionSummariesNewestFirstAndTiebreak(t *testing.T) {
	for _, tc := range newStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mk := func(key string, lastTs int64) SessionSummary {
				return SessionSummary{SessionKey: key, FirstTsMs: 1, LastTsMs: lastTs,
					LastVerdict: model.VerdictObserve, LastReasonCode: "SIG-000"}
			}
			for _, sum := range []SessionSummary{mk("sess-old", 1000), mk("sess-tie-a", 5000), mk("sess-tie-b", 5000), mk("sess-new", 9000)} {
				if err := tc.s.UpsertSessionSummary(ctx, sum); err != nil {
					t.Fatalf("UpsertSessionSummary: %v", err)
				}
			}
			got, err := tc.s.SessionSummaries(ctx, 10)
			if err != nil {
				t.Fatalf("SessionSummaries: %v", err)
			}
			wantOrder := []string{"sess-new", "sess-tie-b", "sess-tie-a", "sess-old"}
			if len(got) != len(wantOrder) {
				t.Fatalf("got %d summaries, want %d", len(got), len(wantOrder))
			}
			for i, want := range wantOrder {
				if got[i].SessionKey != want {
					t.Errorf("summaries[%d] = %s, want %s", i, got[i].SessionKey, want)
				}
			}
			// Limit keeps the newest.
			got, err = tc.s.SessionSummaries(ctx, 2)
			if err != nil {
				t.Fatalf("SessionSummaries(2): %v", err)
			}
			if len(got) != 2 || got[0].SessionKey != "sess-new" || got[1].SessionKey != "sess-tie-b" {
				t.Errorf("SessionSummaries(2) = %+v, want the two newest", got)
			}
		})
	}
}

func TestBanUpsertIdempotent(t *testing.T) {
	for _, tc := range newStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			first := BanRecord{
				IP: "203.0.113.7", Reason: "SIG-401",
				CreatedAtMs: 1000, ExpiresAtMs: 1000 + model.BanTTL,
				Note: "scanner flood", Active: true,
			}
			if err := tc.s.UpsertBanRecord(ctx, first); err != nil {
				t.Fatalf("UpsertBanRecord(first): %v", err)
			}
			// Same (IP, reason) again with refreshed fields: must update, not add.
			refreshed := first
			refreshed.CreatedAtMs = 5000
			refreshed.ExpiresAtMs = 5000 + model.BanTTL
			refreshed.Note = "renewed"
			if err := tc.s.UpsertBanRecord(ctx, refreshed); err != nil {
				t.Fatalf("UpsertBanRecord(refreshed): %v", err)
			}
			// Different reason for the same IP is a separate record.
			other := BanRecord{
				IP: "203.0.113.7", Reason: "SIG-411",
				CreatedAtMs: 6000, ExpiresAtMs: 6000 + model.BanTTL, Active: true,
			}
			if err := tc.s.UpsertBanRecord(ctx, other); err != nil {
				t.Fatalf("UpsertBanRecord(other): %v", err)
			}
			got, err := tc.s.BanRecords(ctx, 1000, 100)
			if err != nil {
				t.Fatalf("BanRecords: %v", err)
			}
			if len(got) != 2 {
				t.Fatalf("got %d bans, want 2 (idempotent upsert must not add a row)", len(got))
			}
			// Newest-first by CreatedAtMs.
			if got[0] != other {
				t.Errorf("newest ban = %+v, want %+v", got[0], other)
			}
			if got[1] != refreshed {
				t.Errorf("refreshed ban = %+v, want %+v", got[1], refreshed)
			}
		})
	}
}

func TestBanRecordsActiveOnlyAndExpiryBoundary(t *testing.T) {
	for _, tc := range newStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			const now = int64(10_000)
			activeNew := BanRecord{IP: "203.0.113.7", Reason: "SIG-401", CreatedAtMs: 8000, ExpiresAtMs: now + 2000, Active: true}
			activeOlder := BanRecord{IP: "198.51.100.4", Reason: "SIG-401", CreatedAtMs: 7000, ExpiresAtMs: now + 1000, Active: true}
			// Boundary: expires exactly at now — already expired, excluded.
			expiredExactlyNow := BanRecord{IP: "192.0.2.9", Reason: "SIG-401", CreatedAtMs: 9000, ExpiresAtMs: now, Active: true}
			expiredEarlier := BanRecord{IP: "192.0.2.8", Reason: "SIG-401", CreatedAtMs: 9500, ExpiresAtMs: now - 1, Active: true}
			inactive := BanRecord{IP: "198.51.100.5", Reason: "SIG-411", CreatedAtMs: 9000, ExpiresAtMs: now + 5000, Active: false}
			for _, b := range []BanRecord{activeNew, activeOlder, expiredExactlyNow, expiredEarlier, inactive} {
				if err := tc.s.UpsertBanRecord(ctx, b); err != nil {
					t.Fatalf("UpsertBanRecord: %v", err)
				}
			}
			got, err := tc.s.BanRecords(ctx, now, 100)
			if err != nil {
				t.Fatalf("BanRecords: %v", err)
			}
			want := []BanRecord{activeNew, activeOlder}
			if len(got) != len(want) {
				t.Fatalf("got %d bans %+v, want the %d active unexpired ones", len(got), got, len(want))
			}
			for i, w := range want {
				if got[i] != w {
					t.Errorf("ban %d = %+v, want %+v", i, got[i], w)
				}
			}
		})
	}
}

func TestBanRecordsLimit(t *testing.T) {
	for _, tc := range newStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			for i := int64(1); i <= 3; i++ {
				b := BanRecord{
					IP: "203.0.113.9", Reason: fmt.Sprintf("SIG-40%d", i),
					CreatedAtMs: i * 1000, ExpiresAtMs: i*1000 + 10_000, Active: true,
				}
				if err := tc.s.UpsertBanRecord(ctx, b); err != nil {
					t.Fatalf("UpsertBanRecord: %v", err)
				}
			}
			got, err := tc.s.BanRecords(ctx, 0, 2)
			if err != nil {
				t.Fatalf("BanRecords(2): %v", err)
			}
			if len(got) != 2 {
				t.Fatalf("got %d bans, want 2", len(got))
			}
			// Newest-first: the limit keeps the most recent records.
			if got[0].CreatedAtMs != 3000 || got[1].CreatedAtMs != 2000 {
				t.Errorf("BanRecords(2) = [%d %d] CreatedAtMs, want [3000 2000]",
					got[0].CreatedAtMs, got[1].CreatedAtMs)
			}
		})
	}
}

func TestCorruptDecisionJSONSkippedAndCounted(t *testing.T) {
	for _, tc := range newStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if err := tc.s.AppendEvent(ctx, testEvent(1000, "sess-a", "/good-oldest", testDecision())); err != nil {
				t.Fatalf("AppendEvent: %v", err)
			}
			if err := tc.s.AppendEvent(ctx, testEvent(2000, "sess-b", "/good-newest", testDecision())); err != nil {
				t.Fatalf("AppendEvent: %v", err)
			}

			sq, ok := tc.s.(*SQLiteStore)
			if !ok {
				// Typed in-memory structs cannot rot; only the durable store
				// can hold (and skip) corrupt rows.
				t.Skip("memory store cannot hold corrupt rows")
			}
			// Corrupt the oldest row's decision payload directly in the
			// database — the only way corruption can occur (the write path
			// always marshals valid JSON).
			if _, err := sq.db.ExecContext(ctx,
				`UPDATE events SET decision_json = ? WHERE id = (SELECT MIN(id) FROM events)`,
				`{"verdict": broken beyond repair`,
			); err != nil {
				t.Fatalf("corrupt decision_json: %v", err)
			}

			got, err := tc.s.RecentEvents(ctx, 10)
			if err != nil {
				t.Fatalf("RecentEvents must tolerate corrupt rows, got %v", err)
			}
			if len(got) != 1 || got[0].Path != "/good-newest" {
				t.Fatalf("RecentEvents = %+v, want only the intact newest event", got)
			}
			if n := sq.CorruptRowsSkipped(); n != 1 {
				t.Fatalf("CorruptRowsSkipped() = %d after first read, want 1", n)
			}
			// The counter is cumulative: the same bad row counts again.
			if _, err := tc.s.RecentEvents(ctx, 10); err != nil {
				t.Fatalf("RecentEvents (second read): %v", err)
			}
			if n := sq.CorruptRowsSkipped(); n != 2 {
				t.Fatalf("CorruptRowsSkipped() = %d after second read, want 2 (cumulative)", n)
			}
		})
	}
}

func TestConcurrentAppendEvents(t *testing.T) {
	for _, tc := range newStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			const goroutines = 10
			const perGoroutine = 50
			var wg sync.WaitGroup
			var mu sync.Mutex
			var errs []error
			for g := 0; g < goroutines; g++ {
				wg.Add(1)
				go func(g int) {
					defer wg.Done()
					for i := 0; i < perGoroutine; i++ {
						// Unique ts and session per event so the final set
						// can be checked for losses and duplicates.
						ev := testEvent(int64(g*100_000+i), fmt.Sprintf("sess-%d-%d", g, i), "/p", nil)
						if err := tc.s.AppendEvent(ctx, ev); err != nil {
							mu.Lock()
							errs = append(errs, err)
							mu.Unlock()
							return
						}
					}
				}(g)
			}
			wg.Wait()
			if len(errs) != 0 {
				t.Fatalf("concurrent AppendEvent errors: %v", errs)
			}
			got, err := tc.s.RecentEvents(ctx, MaxLimit)
			if err != nil {
				t.Fatalf("RecentEvents: %v", err)
			}
			if len(got) != goroutines*perGoroutine {
				t.Fatalf("got %d events, want %d", len(got), goroutines*perGoroutine)
			}
			seen := make(map[int64]bool, len(got))
			for _, ev := range got {
				if seen[ev.TsMs] {
					t.Fatalf("event with ts %d returned twice", ev.TsMs)
				}
				seen[ev.TsMs] = true
			}
			for g := 0; g < goroutines; g++ {
				for i := 0; i < perGoroutine; i++ {
					if ts := int64(g*100_000 + i); !seen[ts] {
						t.Fatalf("event with ts %d missing", ts)
					}
				}
			}
		})
	}
}

func TestClosedStoreReturnsErrors(t *testing.T) {
	for _, tc := range newStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if err := tc.s.AppendEvent(ctx, testEvent(1000, "sess", "/p", nil)); err != nil {
				t.Fatalf("AppendEvent before Close: %v", err)
			}
			if err := tc.s.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if err := tc.s.Close(); err != nil {
				t.Fatalf("second Close must be a no-op, got %v", err)
			}
			ops := map[string]func() error{
				"AppendEvent": func() error {
					return tc.s.AppendEvent(ctx, testEvent(2000, "sess", "/p", nil))
				},
				"RecentEvents": func() error {
					_, err := tc.s.RecentEvents(ctx, 10)
					return err
				},
				"UpsertSessionSummary": func() error {
					return tc.s.UpsertSessionSummary(ctx, SessionSummary{SessionKey: "sess"})
				},
				"SessionSummaries": func() error {
					_, err := tc.s.SessionSummaries(ctx, 10)
					return err
				},
				"BanRecords": func() error {
					_, err := tc.s.BanRecords(ctx, 1000, 10)
					return err
				},
				"UpsertBanRecord": func() error {
					return tc.s.UpsertBanRecord(ctx, BanRecord{IP: "203.0.113.7", Reason: "SIG-401"})
				},
			}
			for name, op := range ops {
				if err := op(); err == nil {
					t.Errorf("%s after Close must return an error, got nil", name)
				}
			}
		})
	}
}

func TestSQLitePersistsAndMigratesAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "persist.db")

	sq, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := sq.AppendEvent(ctx, testEvent(1000, "sess-a", "/.env", testDecision())); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	if err := sq.UpsertSessionSummary(ctx, SessionSummary{
		SessionKey: "sess-a", FirstTsMs: 1000, LastTsMs: 1000,
		LastVerdict: model.VerdictObserve, LastReasonCode: "SIG-000",
		IPHash: HashIP("203.0.113.7"),
	}); err != nil {
		t.Fatalf("UpsertSessionSummary: %v", err)
	}
	if err := sq.UpsertBanRecord(ctx, BanRecord{
		IP: "203.0.113.7", Reason: "SIG-401", CreatedAtMs: 1000,
		ExpiresAtMs: 999_999, Active: true,
	}); err != nil {
		t.Fatalf("UpsertBanRecord: %v", err)
	}
	if err := sq.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen: migrations must no-op on the recorded version and all data
	// must still be there.
	sq, err = OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer sq.Close()

	var version string
	if err := sq.db.QueryRowContext(ctx,
		`SELECT value FROM schema_meta WHERE key = 'schema_version'`).Scan(&version); err != nil {
		t.Fatalf("read schema_version: %v", err)
	}
	if version != "1" {
		t.Fatalf("schema_version = %q, want \"1\"", version)
	}
	events, err := sq.RecentEvents(ctx, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events after reopen: %d, err %v; want 1, nil", len(events), err)
	}
	summaries, err := sq.SessionSummaries(ctx, 10)
	if err != nil || len(summaries) != 1 {
		t.Fatalf("summaries after reopen: %d, err %v; want 1, nil", len(summaries), err)
	}
	bans, err := sq.BanRecords(ctx, 500, 10)
	if err != nil || len(bans) != 1 {
		t.Fatalf("bans after reopen: %d, err %v; want 1, nil", len(bans), err)
	}
}

func TestSQLiteDSNEscapesPath(t *testing.T) {
	ctx := context.Background()
	// '#', '?' and '%' are exactly the characters SQLite's URI parser treats
	// specially; unescaped, a '#' silently truncates the filename.
	path := filepath.Join(t.TempDir(), "weird #name?100%.db")

	sq, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := sq.AppendEvent(ctx, testEvent(1000, "sess-a", "/.env", nil)); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	if err := sq.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database file must exist at the exact requested path: %v", err)
	}

	// A second open at the same path must see the same file, proving the
	// escaping is stable (a mis-escaped path would open a different file).
	sq, err = OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer sq.Close()
	events, err := sq.RecentEvents(ctx, 10)
	if err != nil {
		t.Fatalf("RecentEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events after reopen = %d, want 1 (path escaping must address the same file)", len(events))
	}
}
