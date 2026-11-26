package connectors

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// recordedRequest captures what a connector actually put on the wire.
type recordedRequest struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   []byte
}

// reqLog collects requests across handler goroutines. The mutex is not
// optional: handlers run on server goroutines while the test asserts on
// the main one, and the race detector must see the synchronization.
type reqLog struct {
	mu       sync.Mutex
	requests []recordedRequest
}

func (l *reqLog) record(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.requests = append(l.requests, recordedRequest{
		Method: r.Method,
		Path:   r.URL.Path,
		Query:  r.URL.Query(),
		Header: r.Header.Clone(),
		Body:   body,
	})
}

func (l *reqLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.requests)
}

func (l *reqLog) at(i int) recordedRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.requests[i]
}

// sleepLog records retry sleeps instead of pausing.
type sleepLog struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (s *sleepLog) record(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delays = append(s.delays, d)
	return nil
}

func (s *sleepLog) snapshot() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.delays...)
}

// fastPolicy swaps in instant recorded sleeps and zero jitter so tests
// run fast and deterministic.
func fastPolicy() (retryPolicy, *sleepLog) {
	log := &sleepLog{}
	p := defaultRetryPolicy()
	p.jitter = func(time.Duration) time.Duration { return 0 }
	p.sleep = log.record
	return p, log
}

// wantNoTempLeftovers asserts the atomic-write plumbing left nothing
// behind: the only file in play is the deny map itself.
func wantNoTempLeftovers(t *testing.T, dir string) {
	t.Helper()
	left, err := filepath.Glob(filepath.Join(dir, ".mirage-*"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
}
