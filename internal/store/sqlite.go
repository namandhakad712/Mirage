package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/mirage-shield/mirage/internal/model"

	// Registers the "sqlite" driver (pure Go, no cgo). Imported for its
	// side effect only.
	_ "modernc.org/sqlite"
)

// Compile-time checks that both implementations satisfy the contract and
// that the optional corruption counter is where it belongs.
var (
	_ Store             = (*SQLiteStore)(nil)
	_ Store             = (*MemoryStore)(nil)
	_ CorruptRowCounter = (*SQLiteStore)(nil)
)

// SQLiteStore is the durable Store: one SQLite database file in WAL mode.
// Concurrency safety comes from the database/sql connection pool plus WAL
// and a 5 s busy timeout (writers serialize instead of erroring) — an extra
// mutex would only duplicate what the driver already provides.
type SQLiteStore struct {
	db *sql.DB
	// closed is checked first on every call so a closed store reports the
	// uniform ErrClosed sentinel; calls that race past the check fail with
	// a driver error instead. Either way: error, never panic.
	closed atomic.Bool

	// Hot statements, prepared once at open so the per-event and dashboard
	// paths never re-parse SQL.
	stmtAppendEvent      *sql.Stmt
	stmtRecentEvents     *sql.Stmt
	stmtUpsertSession    *sql.Stmt
	stmtSessionSummaries *sql.Stmt
	stmtBanRecords       *sql.Stmt
	stmtUpsertBan        *sql.Stmt

	// corruptSkipped counts rows whose decision_json failed to decode.
	corruptSkipped atomic.Int64
}

// OpenSQLite opens (creating if needed) the SQLite database at path and
// brings its schema up to date before returning a ready store. path is a
// filesystem path (absolute recommended), never a DSN. The context bounds
// open and migration work.
func OpenSQLite(ctx context.Context, path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("store: sqlite path must not be empty")
	}
	if strings.HasPrefix(path, "file:") {
		return nil, errors.New("store: sqlite path must be a filesystem path, not a DSN")
	}
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}
	// Ping forces a real connection now, so DSN/pragma/path errors surface
	// from OpenSQLite instead of the first query.
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: connect sqlite: %w", err)
	}
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	s := &SQLiteStore{db: db}
	if err := s.prepareStatements(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// dsn builds the connection string:
//
//	journal_mode(WAL)   — readers never block the writer, so the pool can
//	                      serve concurrent dashboard reads during ingestion.
//	busy_timeout(5000)  — concurrent writers wait instead of failing with
//	                      SQLITE_BUSY.
//	foreign_keys(ON)    — no FKs in schema v1 yet; enabled now so a future
//	                      migration cannot forget it.
//
// The path is percent-escaped for the three characters SQLite's URI parser
// treats specially ('%', '?', '#'). Without this a configured path cannot
// smuggle query parameters, and '#' would silently truncate the filename
// (SQLite opens "a b" for "a b#c").
func dsn(path string) string {
	const hexDigits = "0123456789abcdef"
	var b strings.Builder
	b.Grow(len(path) + len("?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)"))
	b.WriteString("file:")
	for i := 0; i < len(path); i++ {
		switch c := path[i]; c {
		case '%', '?', '#':
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0xf])
		default:
			b.WriteByte(c)
		}
	}
	b.WriteString("?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)")
	return b.String()
}

// migration is one ordered schema step. Each runs inside its own transaction
// together with the schema_meta version bump, so a crash leaves the database
// at the previous version and the step simply re-runs on the next open.
type migration struct {
	version int
	stmts   []string
}

// schemaVersion is the version this binary's migration list ends at.
// Derived, not hardcoded, so adding a migration can never leave the
// supported version behind.
var schemaVersion = len(migrations)

// migrations lists every schema step in order. v1 is the initial schema.
// Future changes append a migration with the next version — never edit an
// applied one; OpenSQLite picks up where the database left off.
var migrations = []migration{
	{
		version: 1,
		stmts: []string{
			// Append-only event log (the evidence trail, I10). decision_json
			// is the only nullable column: a nil Decision stores NULL. Ids
			// are AUTOINCREMENT so rowids are never recycled — deleted
			// evidence ids stay unique. No extra index is needed: id is the
			// rowid, so "ORDER BY id DESC" is already an index scan, and the
			// other two tables are one-row-per-key and small.
			`CREATE TABLE IF NOT EXISTS events(
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                ts_ms INTEGER NOT NULL,
                                session_key TEXT NOT NULL,
                                client_ip TEXT NOT NULL,
                                method TEXT NOT NULL,
                                path TEXT NOT NULL,
                                decision_json TEXT
                        )`,
			`CREATE TABLE IF NOT EXISTS session_summaries(
                                session_key TEXT PRIMARY KEY,
                                first_ts_ms INTEGER NOT NULL,
                                last_ts_ms INTEGER NOT NULL,
                                request_count INTEGER NOT NULL,
                                score INTEGER NOT NULL,
                                last_verdict TEXT NOT NULL,
                                last_reason_code TEXT NOT NULL,
                                ip_hash TEXT NOT NULL
                        )`,
			`CREATE TABLE IF NOT EXISTS bans(
                                ip TEXT NOT NULL,
                                reason TEXT NOT NULL,
                                created_at_ms INTEGER NOT NULL,
                                expires_at_ms INTEGER NOT NULL,
                                note TEXT NOT NULL,
                                active INTEGER NOT NULL,
                                PRIMARY KEY(ip, reason)
                        )`,
		},
	},
}

// migrate brings the database up to schemaVersion. Safe to call on every
// open: applied versions are recorded in schema_meta and skipped.
func migrate(ctx context.Context, db *sql.DB) error {
	// Bootstrap table, created outside any version: the version number
	// itself has to live somewhere before v1 exists.
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_meta(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
        )`); err != nil {
		return fmt.Errorf("store: create schema_meta: %w", err)
	}
	current, err := readSchemaVersion(ctx, db)
	if err != nil {
		return err
	}
	if current > schemaVersion {
		// The file was written by a newer binary; refuse instead of
		// guessing at unknown schema.
		return fmt.Errorf("store: database schema version %d is newer than this binary supports (%d)", current, schemaVersion)
	}
	for i, m := range migrations {
		if got, want := m.version, i+1; got != want {
			// Guards the migration list itself: a gap would silently skip
			// steps on databases sitting before the gap.
			return fmt.Errorf("store: migrations[%d] has version %d, want %d (list must be contiguous from 1)", i, got, want)
		}
		if m.version <= current {
			continue
		}
		if err := applyMigration(ctx, db, m); err != nil {
			return err
		}
	}
	return nil
}

func readSchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var v string
	err := db.QueryRowContext(ctx, `SELECT value FROM schema_meta WHERE key = 'schema_version'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil // fresh database
	}
	if err != nil {
		return 0, fmt.Errorf("store: read schema_version: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("store: schema_version %q is not a number: %w", v, err)
	}
	return n, nil
}

// applyMigration runs one migration's statements and records its version in
// a single transaction.
func applyMigration(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin migration v%d: %w", m.version, err)
	}
	defer tx.Rollback() // no-op after a successful commit
	for _, stmt := range m.stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("store: migration v%d: %w", m.version, err)
		}
	}
	// The version bump shares the transaction with the schema change: it
	// lands only if the schema did.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES('schema_version', ?)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		strconv.Itoa(m.version)); err != nil {
		return fmt.Errorf("store: migration v%d version bump: %w", m.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit migration v%d: %w", m.version, err)
	}
	return nil
}

func (s *SQLiteStore) prepareStatements() error {
	type binding struct {
		query string
		dst   **sql.Stmt
	}
	for _, b := range []binding{
		{
			query: `INSERT INTO events(ts_ms, session_key, client_ip, method, path, decision_json)
                                VALUES(?, ?, ?, ?, ?, ?)`,
			dst: &s.stmtAppendEvent,
		},
		{
			query: `SELECT ts_ms, session_key, client_ip, method, path, decision_json
                                FROM events ORDER BY id DESC LIMIT ?`,
			dst: &s.stmtRecentEvents,
		},
		{
			query: `INSERT INTO session_summaries(
                                        session_key, first_ts_ms, last_ts_ms, request_count, score,
                                        last_verdict, last_reason_code, ip_hash)
                                VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                                ON CONFLICT(session_key) DO UPDATE SET
                                        first_ts_ms      = excluded.first_ts_ms,
                                        last_ts_ms       = excluded.last_ts_ms,
                                        request_count    = excluded.request_count,
                                        score            = excluded.score,
                                        last_verdict     = excluded.last_verdict,
                                        last_reason_code = excluded.last_reason_code,
                                        ip_hash          = excluded.ip_hash`,
			dst: &s.stmtUpsertSession,
		},
		{
			// session_key is the deterministic tiebreak so paging stays
			// stable when sessions share a last-seen millisecond.
			query: `SELECT session_key, first_ts_ms, last_ts_ms, request_count, score,
                                        last_verdict, last_reason_code, ip_hash
                                FROM session_summaries
                                ORDER BY last_ts_ms DESC, session_key DESC LIMIT ?`,
			dst: &s.stmtSessionSummaries,
		},
		{
			// ip+reason tiebreak keeps the order deterministic when bans
			// share a created millisecond.
			query: `SELECT ip, reason, created_at_ms, expires_at_ms, note, active
                                FROM bans
                                WHERE active = 1 AND expires_at_ms > ?
                                ORDER BY created_at_ms DESC, ip DESC, reason DESC
                                LIMIT ?`,
			dst: &s.stmtBanRecords,
		},
		{
			query: `INSERT INTO bans(ip, reason, created_at_ms, expires_at_ms, note, active)
                                VALUES(?, ?, ?, ?, ?, ?)
                                ON CONFLICT(ip, reason) DO UPDATE SET
                                        created_at_ms = excluded.created_at_ms,
                                        expires_at_ms = excluded.expires_at_ms,
                                        note          = excluded.note,
                                        active        = excluded.active`,
			dst: &s.stmtUpsertBan,
		},
	} {
		stmt, err := s.db.Prepare(b.query)
		if err != nil {
			s.closeStatements()
			return fmt.Errorf("store: prepare statement: %w", err)
		}
		*b.dst = stmt
	}
	return nil
}

// AppendEvent implements Store.
func (s *SQLiteStore) AppendEvent(ctx context.Context, ev model.Event) error {
	if s.closed.Load() {
		return ErrClosed
	}
	// I7: every attacker-influenced field is bound as a parameter. A nil
	// Decision binds as SQL NULL (the only nullable column by design).
	var decision any
	if ev.Decision != nil {
		b, err := json.Marshal(ev.Decision)
		if err != nil {
			return fmt.Errorf("store: marshal decision: %w", err)
		}
		decision = string(b)
	}
	if _, err := s.stmtAppendEvent.ExecContext(ctx,
		ev.TsMs, ev.SessionKey, ev.ClientIP, ev.Method, ev.Path, decision,
	); err != nil {
		return fmt.Errorf("store: append event: %w", err)
	}
	return nil
}

// RecentEvents implements Store. Rows whose decision_json fails to decode
// are skipped and counted (see CorruptRowsSkipped) instead of failing the
// read: storage corruption must not take the dashboard down (I1 spirit)
// while the surviving evidence stays visible (I10).
//
// The protocol version is not a column (schema v1 predates per-row
// versioning); it is re-derived from this build's constant, which is the
// version the event was written with.
func (s *SQLiteStore) RecentEvents(ctx context.Context, limit int) ([]model.Event, error) {
	if s.closed.Load() {
		return nil, ErrClosed
	}
	rows, err := s.stmtRecentEvents.QueryContext(ctx, clampLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("store: query events: %w", err)
	}
	defer rows.Close()

	events := make([]model.Event, 0)
	for rows.Next() {
		var (
			ev       model.Event
			decision sql.NullString
		)
		if err := rows.Scan(&ev.TsMs, &ev.SessionKey, &ev.ClientIP, &ev.Method, &ev.Path, &decision); err != nil {
			return nil, fmt.Errorf("store: scan event: %w", err)
		}
		ev.ProtocolVersion = model.ProtocolVersion
		if decision.Valid && decision.String != "" {
			var d model.Decision
			if err := json.Unmarshal([]byte(decision.String), &d); err != nil {
				// Corrupt payload: skip the row, keep the rest of the feed.
				s.corruptSkipped.Add(1)
				continue
			}
			ev.Decision = &d
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate events: %w", err)
	}
	return events, nil
}

// UpsertSessionSummary implements Store.
func (s *SQLiteStore) UpsertSessionSummary(ctx context.Context, sum SessionSummary) error {
	if s.closed.Load() {
		return ErrClosed
	}
	if _, err := s.stmtUpsertSession.ExecContext(ctx,
		sum.SessionKey, sum.FirstTsMs, sum.LastTsMs, sum.RequestCount, sum.Score,
		sum.LastVerdict, sum.LastReasonCode, sum.IPHash,
	); err != nil {
		return fmt.Errorf("store: upsert session summary: %w", err)
	}
	return nil
}

// SessionSummaries implements Store.
func (s *SQLiteStore) SessionSummaries(ctx context.Context, limit int) ([]SessionSummary, error) {
	if s.closed.Load() {
		return nil, ErrClosed
	}
	rows, err := s.stmtSessionSummaries.QueryContext(ctx, clampLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("store: query session summaries: %w", err)
	}
	defer rows.Close()

	summaries := make([]SessionSummary, 0)
	for rows.Next() {
		var sum SessionSummary
		if err := rows.Scan(&sum.SessionKey, &sum.FirstTsMs, &sum.LastTsMs, &sum.RequestCount,
			&sum.Score, &sum.LastVerdict, &sum.LastReasonCode, &sum.IPHash); err != nil {
			return nil, fmt.Errorf("store: scan session summary: %w", err)
		}
		summaries = append(summaries, sum)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate session summaries: %w", err)
	}
	return summaries, nil
}

// BanRecords implements Store: active bans whose expiry is strictly in the
// future, newest first.
func (s *SQLiteStore) BanRecords(ctx context.Context, nowMs int64, limit int) ([]BanRecord, error) {
	if s.closed.Load() {
		return nil, ErrClosed
	}
	rows, err := s.stmtBanRecords.QueryContext(ctx, nowMs, clampLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("store: query bans: %w", err)
	}
	defer rows.Close()

	bans := make([]BanRecord, 0)
	for rows.Next() {
		var (
			b      BanRecord
			active int
		)
		if err := rows.Scan(&b.IP, &b.Reason, &b.CreatedAtMs, &b.ExpiresAtMs, &b.Note, &active); err != nil {
			return nil, fmt.Errorf("store: scan ban: %w", err)
		}
		b.Active = active != 0
		bans = append(bans, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate bans: %w", err)
	}
	return bans, nil
}

// UpsertBanRecord implements Store: idempotent on (IP, Reason); a repeat
// write refreshes TTL, note and active flag on the same row.
func (s *SQLiteStore) UpsertBanRecord(ctx context.Context, b BanRecord) error {
	if s.closed.Load() {
		return ErrClosed
	}
	active := 0
	if b.Active {
		active = 1
	}
	if _, err := s.stmtUpsertBan.ExecContext(ctx,
		b.IP, b.Reason, b.CreatedAtMs, b.ExpiresAtMs, b.Note, active,
	); err != nil {
		return fmt.Errorf("store: upsert ban: %w", err)
	}
	return nil
}

// CorruptRowsSkipped implements CorruptRowCounter. The count is cumulative
// over the store's lifetime: re-reading the same corrupt row counts again.
func (s *SQLiteStore) CorruptRowsSkipped() int64 {
	return s.corruptSkipped.Load()
}

// Close implements Store. It is idempotent. After Close every method
// returns ErrClosed; a call that raced past the closed check returns a
// driver error instead — either way an error, never a panic.
func (s *SQLiteStore) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.closeStatements()
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store: close sqlite: %w", err)
	}
	return nil
}

// closeStatements releases prepared statements. Errors are ignored: the
// only failure mode is double-closing, which is the goal here.
func (s *SQLiteStore) closeStatements() {
	for _, stmt := range []*sql.Stmt{
		s.stmtAppendEvent, s.stmtRecentEvents, s.stmtUpsertSession,
		s.stmtSessionSummaries, s.stmtBanRecords, s.stmtUpsertBan,
	} {
		if stmt != nil {
			_ = stmt.Close()
		}
	}
}
