package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mirage-shield/mirage/internal/config"
	"github.com/mirage-shield/mirage/internal/detect"
	"github.com/mirage-shield/mirage/internal/edge"
	"github.com/mirage-shield/mirage/internal/enforce"
	"github.com/mirage-shield/mirage/internal/model"
	"github.com/mirage-shield/mirage/internal/service"
)

// Default bind addresses. The proxy listens on the config's listen key
// (127.0.0.1:8080 by default); the dashboard defaults to its own loopback
// port so the two never collide on a default install.
const defaultDashboardAddr = "127.0.0.1:8090"

// shutdownTimeout bounds the graceful shutdown: in-flight requests and the
// queue flush each get at most this long, then the process exits anyway —
// an operator pressing Ctrl-C twice expects the second press to work.
const shutdownTimeout = 10 * time.Second

// cmdServe implements `mirage serve`: compose the full stack from the site
// configuration — store, engine, catalog, queue, gatekeeper (protect only,
// I9), connectors — start the service, wrap a reverse proxy to the upstream
// origin with the edge adapter, and serve the token-guarded dashboard on
// loopback. The proxy is the fail-open path incarnate (I1): Mirage sits in
// front of the origin and every failure mode degrades to passing traffic
// through.
func cmdServe(args []string) int {
	fs, help := newFlagSet("mirage serve",
		"mirage serve --config FILE --upstream URL [--listen ADDR] [--dashboard-addr ADDR]")
	cfgPath := fs.String("config", "", "site configuration file (required)")
	upstream := fs.String("upstream", "",
		"upstream origin URL the proxy forwards to (required; there is no upstream key in the config)")
	listen := fs.String("listen", "",
		"proxy listen address (default: the config's listen key, 127.0.0.1:8080)")
	dashAddr := fs.String("dashboard-addr", defaultDashboardAddr,
		"dashboard listen address (loopback only)")
	fs, code := parseFlags(fs, help, args)
	if fs == nil {
		return code
	}
	if code := extraArgs(fs); code != exitOK {
		return code
	}
	// Flag validation is complete before anything is opened or composed:
	// a usage error must not leave a half-built stack or a created store
	// file behind.
	if *cfgPath == "" {
		fmt.Fprintln(stderr, "mirage serve: --config is required")
		return exitUsage
	}
	if *upstream == "" {
		fmt.Fprintln(stderr, "mirage serve: --upstream is required (the config has no upstream key; name the origin explicitly)")
		return exitUsage
	}
	up, err := parseUpstream(*upstream)
	if err != nil {
		fmt.Fprintf(stderr, "mirage serve: %v\n", err)
		return exitUsage
	}
	if err := checkLoopback(*dashAddr); err != nil {
		fmt.Fprintf(stderr, "mirage serve: %v\n", err)
		return exitUsage
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "mirage serve: %v\n", err)
		return exitFail
	}
	effListen := *listen
	if effListen == "" {
		effListen = cfg.Listen
	}
	return runServe(cfg, up, effListen, *dashAddr)
}

// runServe composes the stack, runs both HTTP servers until SIGINT or
// SIGTERM, and shuts down gracefully. Every composition failure returns
// exitFail with the offending component named — serve fails closed at
// boot (the config twin of I1).
func runServe(cfg *config.Config, up *url.URL, listenAddr, dashAddr string) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, err := openServeStore(ctx, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "mirage serve: %v\n", err)
		return exitFail
	}
	rules, err := loadEngineRules(cfg)
	if err != nil {
		st.Close()
		fmt.Fprintf(stderr, "mirage serve: %v\n", err)
		return exitFail
	}
	cat, err := loadCatalog(cfg)
	if err != nil {
		st.Close()
		fmt.Fprintf(stderr, "mirage serve: %v\n", err)
		return exitFail
	}
	cs, err := buildConnectors(cfg)
	if err != nil {
		st.Close()
		fmt.Fprintf(stderr, "mirage serve: %v\n", err)
		return exitFail
	}
	// The gatekeeper exists only in protect mode (I9); every other mode
	// composes the service without one and service.New enforces that
	// shape. Connectors are built in every mode: they are inert outside
	// protect (no ban action ever reaches them) and their health stays
	// visible on the dashboard.
	var gk *enforce.Gatekeeper
	if cfg.Mode == config.ModeProtect {
		gk = newGatekeeper(cfg)
	}
	svc, err := service.New(cfg, detect.New(rules), cat, st, newQueue(cfg), gk, cs, service.Options{})
	if err != nil {
		st.Close()
		fmt.Fprintf(stderr, "mirage serve: %v\n", err)
		return exitFail
	}
	svc.Start(ctx)
	e, err := edge.New(cfg, svc, edge.Options{})
	if err != nil {
		svc.Stop(ctx)
		st.Close()
		fmt.Fprintf(stderr, "mirage serve: %v\n", err)
		return exitFail
	}

	proxy := httputil.NewSingleHostReverseProxy(up)
	// Upstream failures answer 502 with a plain body and no Mirage marker
	// (ADR 0001): the response must not reveal that a deception layer sits
	// in front of the origin. The error itself goes to stderr only.
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		fmt.Fprintf(stderr, "mirage serve: upstream %s: %s %s: %v\n", up.Host, r.Method, r.URL.Path, err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	// ReadHeaderTimeout bounds a slow client's header phase on both
	// servers; the body phase stays unbounded deliberately so slow
	// legitimate uploads keep working (the proxy's own timeouts govern
	// those).
	proxySrv := &http.Server{
		Addr:              listenAddr,
		Handler:           e.Wrap(proxy),
		ReadHeaderTimeout: 30 * time.Second,
	}
	dashSrv := &http.Server{
		Addr:              dashAddr,
		Handler:           e.Dashboard(),
		ReadHeaderTimeout: 30 * time.Second,
	}

	// Bind before the startup lines print, so "listen 127.0.0.1:8080" is
	// a promise the process has already kept (a bind failure exits 1 with
	// the address in the message instead of a goroutine log line).
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		svc.Stop(ctx)
		st.Close()
		fmt.Fprintf(stderr, "mirage serve: listen %s: %v\n", listenAddr, err)
		return exitFail
	}
	dln, err := net.Listen("tcp", dashAddr)
	if err != nil {
		ln.Close()
		svc.Stop(ctx)
		st.Close()
		fmt.Fprintf(stderr, "mirage serve: listen %s: %v\n", dashAddr, err)
		return exitFail
	}

	fmt.Fprintf(stdout, "mirage %s (spec %s, protocol %s)\n", version, model.SpecVersion, model.ProtocolVersion)
	fmt.Fprintf(stdout, "mode %s\n", cfg.Mode)
	fmt.Fprintf(stdout, "listen %s\n", listenAddr)
	fmt.Fprintf(stdout, "dashboard %s\n", dashAddr)
	fmt.Fprintf(stdout, "upstream %s\n", up)

	errCh := make(chan error, 2)
	go func() { errCh <- proxySrv.Serve(ln) }()
	go func() { errCh <- dashSrv.Serve(dln) }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	exitCode := exitOK
	select {
	case sig := <-sigCh:
		fmt.Fprintf(stderr, "mirage serve: %s: shutting down\n", sig)
	case err := <-errCh:
		// A server died outside shutdown (fatal accept error): tear the
		// rest down and fail — serve does not limp.
		fmt.Fprintf(stderr, "mirage serve: %v\n", err)
		exitCode = exitFail
	}

	// Graceful shutdown, in dependency order: stop accepting (both
	// servers drain in-flight requests), stop the service loops and flush
	// the event queue into the store (I10's evidence trail ends complete),
	// then close the store. Shutdown degrades, it does not error (the
	// spirit of I1): each step's failure is logged, the exit code stays 0.
	shCtx, shCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shCancel()
	if err := proxySrv.Shutdown(shCtx); err != nil {
		fmt.Fprintf(stderr, "mirage serve: proxy shutdown: %v\n", err)
	}
	if err := dashSrv.Shutdown(shCtx); err != nil {
		fmt.Fprintf(stderr, "mirage serve: dashboard shutdown: %v\n", err)
	}
	if err := svc.Stop(shCtx); err != nil {
		fmt.Fprintf(stderr, "mirage serve: service stop: %v\n", err)
	}
	if err := st.Close(); err != nil {
		fmt.Fprintf(stderr, "mirage serve: store close: %v\n", err)
	}
	return exitCode
}

// parseUpstream validates the origin URL: the reverse proxy rewrites
// requests against it, so it must be an absolute http(s) URL with a host.
// Anything less is a usage error at boot, not a runtime surprise.
func parseUpstream(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		// A bare host:port makes url.Parse itself fail ("first path segment
		// cannot contain colon"), which is just the missing scheme wearing
		// a different error; one message covers both.
		return nil, fmt.Errorf("invalid --upstream %q: scheme must be http or https (e.g. http://127.0.0.1:9000)", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid --upstream %q: host is required", raw)
	}
	return u, nil
}

// checkLoopback enforces the dashboard's loopback-only bind: the dashboard
// is reached through a local proxy or an SSH tunnel, never the network,
// and a token-gated public endpoint is still a public endpoint. Only IP
// literals are accepted (127.x.x.x, ::1) — a name would need a resolver
// lookup whose answer could drift.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("--dashboard-addr %q is not a host:port address (loopback required, e.g. %q)", addr, defaultDashboardAddr)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("--dashboard-addr must bind a loopback address (got %q; use 127.0.0.1 or ::1 and expose the dashboard through an SSH tunnel or local proxy)", host)
	}
	return nil
}
