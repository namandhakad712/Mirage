// Package edge is Mirage's in-process HTTP adapter: it converts each
// request into a model.Request, runs the decision path, applies the
// action, and never identifies itself in responses (ADR-0001).
//
// It is the Go-native twin of the Cloudflare Worker adapter
// (packages/mirage-worker/src/worker.ts) and mirrors its semantics
// request-field by request-field: the raw request-target (dot segments and
// query intact), the full header count including Host, cookie presence,
// the Authorization-plus-query credential hint, and the fail-open posture
// around the decision call. Where the two must differ, the difference is
// deliberate and documented at the divergence:
//
//   - Client identity: the worker reads the platform-set CF-Connecting-IP;
//     the Go core owns the trusted-proxy walk, so this adapter resolves the
//     client with model.ClientIPFrom over RemoteAddr and X-Forwarded-For
//     (I6) and reports TrustedPeer alongside (ADAPTER-PROTOCOL section 2).
//   - Header hygiene: the worker stamps Cache-Control and X-Mirage-Ban-Ttl
//     on its throttle/ban answers; this adapter adds NOTHING beyond the
//     action contract (Retry-After on throttle). A response header naming
//     Mirage is a public marker — exactly what ADR-0001 forbids — and the
//     smallest possible header set is the cheapest disguise.
//
// Invariants held here: I1 (the edge can never fail or stall a request —
// decision errors, deadline overruns, panics and render failures all pass
// to the origin), I3 (no locks, no I/O and no avoidable allocations on the
// hot path; every blocking concern belongs to the Service), I6 (identity
// only from the configured trusted proxies), I7 (attacker-controlled
// strings are sanitized before they reach a log line).
package edge

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/mirage-shield/mirage/internal/config"
	"github.com/mirage-shield/mirage/internal/decoy"
	"github.com/mirage-shield/mirage/internal/model"
	"github.com/mirage-shield/mirage/internal/service"
)

// The fixed action responses, byte-identical to the worker adapter so the
// two edges cannot be told apart by their denials.
const (
	// throttleBody and banBody are static bodies (I7): never a byte of
	// attacker input, so a denial can never reflect a probe back at its
	// sender. The ban body is deliberately plain — a generic one-liner any
	// server might emit, in the spirit of the stock 403 a deny-map hit
	// produces in the nginx topology (docs/deploy/nginx.md): no special
	// body, nothing that fingerprints Mirage (ADR-0001).
	throttleBody = "Too many requests. Please retry later."
	banBody      = "Request blocked."

	// throttleRetryAfter is the throttle answer's Retry-After, in seconds.
	// The value is the reference adapter's (worker.ts sends "30"; see also
	// docs/deploy/cloudflare-worker.md); spec/SIGNALS.md section 5 defines
	// when the throttle rung fires (request_score >= 40) and leaves the
	// wire shape to the adapter.
	throttleRetryAfter = "30"

	// textContentType names the two fixed bodies above; the worker declares
	// the same type on its throttle and ban answers.
	textContentType = "text/plain; charset=utf-8"
)

// decisionBudget is the wall-clock budget the edge defends on its own,
// independently of the Service's internal deadline checks: the protocol's
// recommended 5 ms (ADAPTER-PROTOCOL section 2), the same constant the
// default-configured Service measures itself against and the worker
// hardcodes as DECISION_DEADLINE_MS. The Service owns the authoritative
// check — this one exists for the case it cannot see: a Service whose
// injected clock is frozen or lies while real time burns (a broken test
// double, a wedged clock source). On overrun the request passes and one
// line is logged (I1); the decision is discarded rather than applied,
// matching the worker's recordFailOpen path.
const decisionBudget = time.Duration(service.DefaultDecideBudgetMs) * time.Millisecond

// Options tunes Edge construction. The zero value is production-shaped.
type Options struct {
	// Clock returns Unix ms; nil means time.Now. Tests inject a
	// deterministic clock.
	Clock func() int64
}

// Edge is the in-process HTTP adapter: it holds the validated config and
// the wired Service read-only and produces the middleware. An Edge is safe
// for concurrent use — it carries no mutable state, so one Edge may wrap
// every handler in the process.
type Edge struct {
	cfg   *config.Config // validated by the caller (Load/Validate); read-only here
	svc   *service.Service
	clock func() int64 // request timestamps (model.Request.TsMs), Unix ms
}

// New builds the edge middleware. cfg must have passed config.Validate;
// svc must be non-nil. Both are retained read-only: the Edge never mutates
// the config and never reaches past the Service's public surface.
func New(cfg *config.Config, svc *service.Service, opts Options) (*Edge, error) {
	if cfg == nil {
		return nil, errors.New("edge: config must not be nil")
	}
	if svc == nil {
		return nil, errors.New("edge: service must not be nil")
	}
	clock := opts.Clock
	if clock == nil {
		clock = func() int64 { return time.Now().UnixMilli() }
	}
	return &Edge{cfg: cfg, svc: svc, clock: clock}, nil
}

// Wrap returns the middleware. Per request: build model.Request, call
// Decide, apply the action:
//
//	pass        -> next.ServeHTTP
//	serve_decoy -> the decoy Rendered response (status, headers, body)
//	throttle    -> 429 with Retry-After per the action contract
//	ban         -> plain 403 (generic body, no marker)
//
// Decide NEVER fails the request: the Service already fails open (I1) on
// its own clock; the edge adds a defensive wall-time measurement around
// the Decide call, and the decision-phase guard also recovers a panicking
// Service — a panic is just an internal failure arriving loudly, and the
// worker's catch-all is its Go twin. The recover is scoped to Mirage's own
// code: next.ServeHTTP sits outside it, so an origin panic keeps the
// origin's semantics (the worker keeps its origin fetch outside the try
// for exactly this reason). An unknown or future action string passes to
// the origin too — passing is always the safe direction (I1) and the
// version handshake, not the hot path, is where protocol drift belongs.
func (e *Edge) Wrap(next http.Handler) http.Handler {
	if next == nil {
		// A nil upstream is a wiring bug. Wrap cannot return an error and a
		// first-request panic would break the never-panic contract, so the
		// middleware answers 404: there is no origin to fail open TO.
		next = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := e.buildRequest(r)

		d, ok := e.decide(req)
		if !ok {
			// Fail-open (I1): deadline overrun or a recovered panic. The
			// request reaches the origin unmodified, whatever the discarded
			// decision said.
			next.ServeHTTP(w, r)
			return
		}

		switch d.Action {
		case model.ActionServeDecoy:
			rendered, ok := e.renderDecoy(d)
			if !ok {
				// A decoy that cannot render fails open to the origin, like
				// the worker's act() throw landing in its catch (I1). The
				// decision stays recorded upstream (I10).
				next.ServeHTTP(w, r)
				return
			}
			writeDecoy(w, rendered)
		case model.ActionThrottle:
			writeThrottle(w)
		case model.ActionBan:
			writeBan(w)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// Dashboard returns the token-guarded dashboard handler (svc.Handler()).
// Loopback binding is the caller's (cmd/mirage) responsibility.
func (e *Edge) Dashboard() http.Handler {
	return e.svc.Handler()
}

// decide runs the decision path with the edge's defensive guards and
// reports whether the returned decision may be acted on. ok is false —
// and the request must pass to the origin — when the Decide call exceeded
// the wall-clock budget or panicked; both log exactly one line, with every
// attacker-influenced field sanitized (I1, I7 — a panic value is arbitrary
// and must never forge log lines either).
func (e *Edge) decide(req model.Request) (d model.Decision, ok bool) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("edge: decide panicked for %s %s from %s: %s (failing open, I1)",
				req.Method, model.Sanitize(req.Path, 0), model.Sanitize(req.ClientIP, 0),
				model.Sanitize(fmt.Sprint(rec), 0))
			d, ok = model.FailOpen(), false
		}
	}()
	start := time.Now()
	d = e.svc.Decide(req)
	if elapsed := time.Since(start); elapsed > decisionBudget {
		log.Printf("edge: decide over budget for %s %s from %s: %s > %s (failing open, I1)",
			req.Method, model.Sanitize(req.Path, 0), model.Sanitize(req.ClientIP, 0), elapsed, decisionBudget)
		return d, false
	}
	return d, true
}

// renderDecoy renders the decision's decoy with the same panic guard as
// the decision itself. An error (no catalog, unknown id, missing session
// key) or a panic hands the request back to the origin (I1); the worker's
// equivalent is a decoy-render throw landing in its catch-all.
func (e *Edge) renderDecoy(d model.Decision) (rd decoy.Rendered, ok bool) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("edge: render decoy %q panicked: %s (serving origin, I1)",
				d.DecoyID, model.Sanitize(fmt.Sprint(rec), 0))
			rd, ok = decoy.Rendered{}, false
		}
	}()
	rd, err := e.svc.ServeDecoy(d)
	if err != nil {
		log.Printf("edge: render decoy %q: %v (serving origin, I1)", d.DecoyID, err)
		return decoy.Rendered{}, false
	}
	return rd, true
}

// buildRequest translates an *http.Request into the model.Request the
// decision path scores, field by field after the worker's toEngineRequest
// (spec/SIGNALS.md section 1): raw path including dot segments and query,
// full header count including Host, cookie presence, user agent, the
// Authorization-plus-query credential hint, and client identity through
// the trusted-proxy walk (I6).
func (e *Edge) buildRequest(r *http.Request) model.Request {
	path := rawTarget(r)
	query := ""
	if i := strings.IndexByte(path, '?'); i != -1 {
		query = path[i+1:]
	}

	// auth_hint, exactly the worker's composition: the credential material
	// visible without reading the body — the Authorization header and the
	// raw query string, joined by one space when both are present, omitted
	// entirely when neither is (SIGNALS section 1). The body is not read on
	// this adapter either: the Go core scores request metadata only, the
	// same v1 reduction the worker documents.
	authHint := ""
	auth := r.Header.Get("Authorization")
	switch {
	case auth != "" && query != "":
		authHint = auth + " " + query
	case auth != "":
		authHint = auth
	case query != "":
		authHint = query
	}

	// header_count counts every header field the client sent. net/http
	// promotes Host out of r.Header into r.Host, so the promoted field is
	// counted back in — the worker's Headers iteration includes Host
	// (SIGNALS section 1: "including Host and User-Agent"), and a missing
	// +1 would undercount every request by exactly its Host.
	headerCount := len(r.Header)
	if r.Host != "" {
		headerCount++
	}

	xff := r.Header.Get("X-Forwarded-For")
	return model.Request{
		Method:       r.Method,
		Path:         path,
		ClientIP:     model.ClientIPFrom(r.RemoteAddr, xff, e.cfg.TrustedProxies()),
		UserAgent:    r.Header.Get("User-Agent"),
		HeaderCount:  headerCount,
		HasCookie:    r.Header.Get("Cookie") != "",
		AuthHint:     authHint,
		TsMs:         e.clock(),
		TrustedPeer:  trustedPeer(r.RemoteAddr, e.cfg.TrustedProxies()),
		ForwardedFor: xff,
	}
}

// rawTarget returns the request-target exactly as the client sent it —
// origin-form "/path?query", percent-escapes and dot segments intact. It
// is the Go counterpart of the worker's rawPathFromUrl, which exists
// because normalizing ".." would erase precisely the evidence dot_escape
// must see (SIGNALS section 3.2): r.URL.Path holds the DECODED path, so a
// "%2e%2e" probe read through it would look already resolved. r.RequestURI
// is the undecoded wire form and is used whenever it carries an
// origin-form target; the non-origin forms (OPTIONS "*", absolute-form
// proxy targets) fall back to the parsed URL's encoded form, which keeps
// the raw-bytes property for them too.
func rawTarget(r *http.Request) string {
	if uri := r.RequestURI; uri != "" && uri[0] == '/' {
		return uri
	}
	return r.URL.RequestURI()
}

// trustedPeer reports whether the immediate peer is one of the configured
// trusted proxies (ADAPTER-PROTOCOL section 2's trusted_peer). It answers
// with the same contains check model.ClientIPFrom applies to the same
// address, so the peer's TrustedPeer bit can never disagree with the walk
// that produced ClientIP (I6).
func trustedPeer(remoteAddr string, trusted []netip.Prefix) bool {
	ip, err := netip.ParseAddr(model.RequestIP(remoteAddr))
	if err != nil {
		// An unparseable peer is not a trusted one; ClientIPFrom treats the
		// same literal as an opaque identity, never as forwarded evidence.
		return false
	}
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// writeDecoy applies a rendered decoy verbatim: status, every header line,
// content type, body — the persona headers and the noindex set the renderer
// already decided (I12). A malformed header line (impossible through Load's
// validation, tolerated for a hand-built catalog) is skipped, never a 500:
// a decoy must always serve (I1's spirit).
func writeDecoy(w http.ResponseWriter, rd decoy.Rendered) {
	h := w.Header()
	for _, line := range rd.Headers {
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		h.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	if rd.ContentType != "" {
		h.Set("Content-Type", rd.ContentType)
	}
	w.WriteHeader(rd.Status)
	_, _ = w.Write(rd.Body)
}

// writeThrottle answers 429 with the fixed Retry-After and the static
// body. Retry-After is the ONE header the throttle action requires; the
// edge deliberately adds nothing else (ADR-0001: no marker, minimal
// surface — the worker's Cache-Control is its own choice, not the action
// contract's).
func writeThrottle(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", textContentType)
	h.Set("Retry-After", throttleRetryAfter)
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(throttleBody))
}

// writeBan answers a plain generic 403: fixed one-line body, content type,
// and nothing else. No TTL header (the worker's X-Mirage-Ban-Ttl names
// Mirage — a public marker ADR-0001 forbids), no cache header, no special
// body: indistinguishable from any server's stock denial, like the deny-map
// 403 of the nginx topology (docs/deploy/nginx.md).
func writeBan(w http.ResponseWriter) {
	w.Header().Set("Content-Type", textContentType)
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(banBody))
}
