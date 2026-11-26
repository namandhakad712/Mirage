package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Shared HTTP plumbing for the network connectors (design section 5):
// bounded retries with exponential backoff plus jitter, 429s honored
// via Retry-After, and bounded body handling. Sleep and jitter are
// injectable so tests run in microseconds and stay deterministic.

const (
	defaultAttempts      = 3
	defaultBaseDelay     = 500 * time.Millisecond
	defaultMaxJitter     = 200 * time.Millisecond
	defaultRetryAfterCap = 30 * time.Second
	maxBodyDrain         = 8 << 10
	maxDecodeBody        = 1 << 20
)

// responseClass drives the retry decision for an HTTP status.
type responseClass int

const (
	classSuccess   responseClass = iota // 2xx: done
	classThrottle                       // 429: sleep Retry-After, retry
	classRetriable                      // 5xx: backoff, retry
	classPermanent                      // other 4xx and surprises: fail now
)

func classifyStatus(code int) responseClass {
	switch {
	case code >= 200 && code < 300:
		return classSuccess
	case code == http.StatusTooManyRequests:
		return classThrottle
	case code >= 500:
		return classRetriable
	default:
		return classPermanent
	}
}

// statusError reports the final HTTP status of a failed call. It
// carries the status only — never the URL (query strings can embed
// data) and never a token (I11).
type statusError struct{ code int }

func (e statusError) Error() string { return fmt.Sprintf("status %d", e.code) }

type sleeper func(ctx context.Context, d time.Duration) error
type jitterer func(max time.Duration) time.Duration

type retryPolicy struct {
	attempts      int
	baseDelay     time.Duration
	maxJitter     time.Duration
	retryAfterCap time.Duration
	jitter        jitterer
	sleep         sleeper
}

// defaultRetryPolicy returns the production policy: three attempts,
// 500ms base doubling per failure, up to 200ms jitter, Retry-After
// capped at 30s. Jitter draws from the package-level math/rand source,
// which is auto-seeded and safe for concurrent use; tests swap in their
// own seeded source for determinism.
func defaultRetryPolicy() retryPolicy {
	return retryPolicy{
		attempts:      defaultAttempts,
		baseDelay:     defaultBaseDelay,
		maxJitter:     defaultMaxJitter,
		retryAfterCap: defaultRetryAfterCap,
		jitter: func(max time.Duration) time.Duration {
			return time.Duration(rand.Int63n(int64(max) + 1))
		},
		sleep: sleepContext,
	}
}

// sleepContext pauses for d, returning early if ctx is canceled.
func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// backoff returns baseDelay*2^failures plus jitter, where failures is
// the number of attempts already made: one failure → 500ms, two → 1s.
// failures is bounded by attempts, so the shift cannot overflow.
func (p retryPolicy) backoff(failures int) time.Duration {
	return p.baseDelay<<failures + p.jitter(p.maxJitter)
}

// retryAfter parses Retry-After as delta-seconds (the only form our
// providers send), capped at cap. Zero means "not usable" and the
// caller falls back to plain backoff. HTTP-date values are deliberately
// not parsed: misreading one is worse than backing off.
func retryAfter(header string, cap time.Duration) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil || secs <= 0 {
		return 0
	}
	d := time.Duration(secs) * time.Second
	if d > cap {
		return cap
	}
	return d
}

// do runs attempt until it yields a 2xx response. Throttled (429) and
// retriable (5xx) responses sleep and retry; permanent 4xx fails at
// once; network errors retry like 5xxs. A 429 replaces the computed
// backoff with the provider's Retry-After for that attempt. Non-success
// bodies are closed here; the caller owns the returned response's body.
func (p retryPolicy) do(ctx context.Context, attempt func() (*http.Response, error)) (*http.Response, error) {
	var lastErr error
	for i := 0; i < p.attempts; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resp, err := attempt()
		if err == nil && resp != nil {
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return resp, nil
			}
			class := classifyStatus(resp.StatusCode)
			lastErr = statusError{code: resp.StatusCode}
			delay := time.Duration(0)
			if class == classThrottle {
				// The provider said when to come back; that replaces
				// our backoff for this attempt.
				delay = retryAfter(resp.Header.Get("Retry-After"), p.retryAfterCap)
			}
			drainAndClose(resp.Body)
			if class == classPermanent {
				return nil, lastErr
			}
			if i < p.attempts-1 {
				if delay == 0 {
					delay = p.backoff(i)
				}
				if serr := p.sleep(ctx, delay); serr != nil {
					return nil, serr
				}
			}
			continue
		}
		if err != nil {
			lastErr = err
		} else {
			// Defensive: an attempt that returns neither a response nor
			// an error is a connector bug; treat it as a failure.
			lastErr = fmt.Errorf("attempt returned no response")
		}
		if i < p.attempts-1 {
			if serr := p.sleep(ctx, p.backoff(i)); serr != nil {
				return nil, serr
			}
		}
	}
	return nil, lastErr
}

// newRequest builds an HTTP request with a JSON content type and Bearer
// auth. The token lives in the header only: request-construction errors
// quote the URL but never the token (I11).
func newRequest(ctx context.Context, method, url string, body []byte, token string) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

// decodeJSON decodes a bounded success body into v and closes it.
func decodeJSON(resp *http.Response, v any) error {
	defer drainAndClose(resp.Body)
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxDecodeBody))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode response body: %w", err)
	}
	return nil
}

// drainAndClose discards a bounded prefix of the body (keeping the
// connection reusable) and closes it. Errors are ignored: the response
// is being abandoned anyway.
func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxBodyDrain))
	_ = body.Close()
}
