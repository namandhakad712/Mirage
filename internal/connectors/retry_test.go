package connectors

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"testing"
	"time"
)

// synth builds a synthetic response with a disposable body; the helper
// must be able to close non-success bodies without touching the network.
func synth(status int, header ...string) *http.Response {
	r := &http.Response{
		StatusCode: status,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("body")),
	}
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	return r
}

func TestRetryBackoffDoublesWithSeededJitter(t *testing.T) {
	// Jitter must come from an injectable seeded source so backoff is
	// reproducible: base*2^n plus a draw in [0, 200ms].
	rng := rand.New(rand.NewSource(1))
	p := defaultRetryPolicy()
	p.jitter = func(max time.Duration) time.Duration {
		return time.Duration(rng.Int63n(int64(max) + 1))
	}
	expect := rand.New(rand.NewSource(1))
	for n, base := range []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second} {
		jitter := time.Duration(expect.Int63n(int64(200*time.Millisecond) + 1))
		if got, want := p.backoff(n), base+jitter; got != want {
			t.Fatalf("backoff(%d) = %v, want %v (base %v + jitter %v)", n, got, want, base, jitter)
		}
	}
}

func TestRetryParseRetryAfter(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{"seconds", "2", 2 * time.Second},
		{"spaces trimmed", " 7 ", 7 * time.Second},
		{"zero", "0", 0},
		{"negative", "-3", 0},
		{"missing", "", 0},
		{"garbage", "next tuesday", 0},
		{"http-date not parsed", "Wed, 21 Oct 2015 07:28:00 GMT", 0},
		{"capped at 30s", "600", 30 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := retryAfter(c.header, 30*time.Second); got != c.want {
				t.Fatalf("retryAfter(%q) = %v, want %v", c.header, got, c.want)
			}
		})
	}
}

func TestRetryRetries5xxThenSucceeds(t *testing.T) {
	p, sleeps := fastPolicy()
	responses := []*http.Response{synth(500), synth(503), synth(200)}
	i := 0
	resp, err := p.do(context.Background(), func() (*http.Response, error) {
		r := responses[i]
		i++
		return r, nil
	})
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final status = %d, want 200", resp.StatusCode)
	}
	delays := sleeps.snapshot()
	if len(delays) != 2 || delays[0] != 500*time.Millisecond || delays[1] != 1000*time.Millisecond {
		t.Fatalf("delays = %v, want [500ms 1s]", delays)
	}
}

func TestRetry429UsesRetryAfterInsteadOfBackoff(t *testing.T) {
	p, sleeps := fastPolicy()
	responses := []*http.Response{
		synth(429, "Retry-After", "3"),
		synth(429, "Retry-After", "9"),
		synth(200),
	}
	i := 0
	if _, err := p.do(context.Background(), func() (*http.Response, error) {
		r := responses[i]
		i++
		return r, nil
	}); err != nil {
		t.Fatalf("do: %v", err)
	}
	delays := sleeps.snapshot()
	if len(delays) != 2 || delays[0] != 3*time.Second || delays[1] != 9*time.Second {
		t.Fatalf("delays = %v, want [3s 9s]: the provider's Retry-After replaces our backoff", delays)
	}
}

func TestRetry429WithoutHeaderFallsBackToBackoff(t *testing.T) {
	p, sleeps := fastPolicy()
	responses := []*http.Response{synth(429), synth(200)}
	i := 0
	if _, err := p.do(context.Background(), func() (*http.Response, error) {
		r := responses[i]
		i++
		return r, nil
	}); err != nil {
		t.Fatalf("do: %v", err)
	}
	delays := sleeps.snapshot()
	if len(delays) != 1 || delays[0] != 500*time.Millisecond {
		t.Fatalf("delays = %v, want [500ms]", delays)
	}
}

func TestRetryPermanentStatusFailsFast(t *testing.T) {
	p, sleeps := fastPolicy()
	attempts := 0
	_, err := p.do(context.Background(), func() (*http.Response, error) {
		attempts++
		return synth(403), nil
	})
	if err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("err = %v, want status 403", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1: 4xx is permanent, no retry", attempts)
	}
	if len(sleeps.snapshot()) != 0 {
		t.Fatal("permanent failure must not sleep")
	}
}

func TestRetryExhaustsAttemptsOnNetworkError(t *testing.T) {
	p, sleeps := fastPolicy()
	boom := errors.New("connection refused")
	attempts := 0
	_, err := p.do(context.Background(), func() (*http.Response, error) {
		attempts++
		return nil, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the network error back", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
	delays := sleeps.snapshot()
	if len(delays) != 2 || delays[0] != 500*time.Millisecond || delays[1] != 1000*time.Millisecond {
		t.Fatalf("delays = %v, want [500ms 1s]", delays)
	}
}

func TestRetryStopsWhenSleepIsCanceled(t *testing.T) {
	// A canceled context must abort mid-retry, not after the sleep.
	p := defaultRetryPolicy()
	p.jitter = func(time.Duration) time.Duration { return 0 }
	p.sleep = func(context.Context, time.Duration) error { return context.Canceled }
	attempts := 0
	_, err := p.do(context.Background(), func() (*http.Response, error) {
		attempts++
		return synth(500), nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestRetryRefusesPreCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p, sleeps := fastPolicy()
	attempts := 0
	_, err := p.do(ctx, func() (*http.Response, error) {
		attempts++
		return synth(200), nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if attempts != 0 {
		t.Fatalf("attempts = %d, want 0", attempts)
	}
	if len(sleeps.snapshot()) != 0 {
		t.Fatal("canceled context must not sleep")
	}
}
