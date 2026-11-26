package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mirage-shield/mirage/internal/config"
	"github.com/mirage-shield/mirage/internal/decoy"
	"github.com/mirage-shield/mirage/internal/detect"
	"github.com/mirage-shield/mirage/internal/enforce"
	"github.com/mirage-shield/mirage/internal/events"
	"github.com/mirage-shield/mirage/internal/model"
	"github.com/mirage-shield/mirage/internal/service"
	"github.com/mirage-shield/mirage/internal/store"
)

// replayClockMs is the frozen decision clock of the service parity gate
// (internal/service/vectors_test.go vectorClock): Decide's deadline
// arithmetic sees zero elapsed and ban bookkeeping gets a fixed now, so a
// replay is deterministic on any machine. Request timestamps themselves are
// absolute ts_ms values carried by the vector cases and feed the engine
// directly through model.Request.TsMs — no clock injection happens there,
// which is why the same case file reproduces byte-identical decisions in
// the Go tests, the TypeScript worker parity suite and this replay.
const replayClockMs int64 = 1_789_000_000_000

// replayToken is the dashboard token of the harness configuration. It
// exists only in memory for the replay run; service.New requires a
// non-empty token and the value is never an input to any decision.
const replayToken = "mirage-replay-harness-token"

// replayBudgets are the deliberately generous gatekeeper budgets of the
// parity gate: a vector's terminal ban must be judged on its evidence, not
// vetoed by a budget the vector never intended to exercise.
const replayMaxBansPerMinute = 100

// replayMaxConcurrentBans matches the parity gate's generous cap.
const replayMaxConcurrentBans = 100

// vectorFile mirrors the subset of spec/golden-vectors/vectors.json the
// replay harness consumes — the same shape internal/service/vectors_test.go
// decodes. The two optional request keys carry omitempty so a corrupted
// copy written back out round-trips the file's own shape.
type vectorFile struct {
	SpecVersion     string `json:"spec_version"`
	ProtocolVersion string `json:"protocol_version"`
	Policy          struct {
		ProtectedRoutes     []string `json:"protected_routes"`
		SessionTTLms        int64    `json:"session_ttl_ms"`
		UAWindowMs          int64    `json:"ua_window_ms"`
		EnumWindowMs        int64    `json:"enum_window_ms"`
		EnumThreshold       int      `json:"enum_threshold"`
		UARotationThreshold int      `json:"ua_rotation_threshold"`
		BanTTLms            int64    `json:"ban_ttl_ms"`
	} `json:"policy"`
	Cases []vectorCase `json:"cases"`
}

type vectorCase struct {
	ID             string           `json:"id"`
	ClientIP       string           `json:"client_ip"`
	AllowlistedIPs []string         `json:"allowlisted_ips"`
	Requests       []vectorRequest  `json:"requests"`
	Expected       []vectorExpected `json:"expected"`
}

type vectorRequest struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	TsMs         int64  `json:"ts_ms"`
	UserAgent    string `json:"user_agent"`
	HeaderCount  int    `json:"header_count"`
	HasCookie    bool   `json:"has_cookie"`
	AuthHint     string `json:"auth_hint,omitempty"`
	ForwardedFor string `json:"x_forwarded_for,omitempty"`
}

type vectorExpected struct {
	Signals    []string `json:"signals"`
	Verdict    string   `json:"verdict"`
	Score      int      `json:"score"`
	ReasonCode string   `json:"reason_code"`
}

// vectorWeights is the fixed signal table (SIGNALS.md section 4), duplicated
// from the parity gate so the request-score check derives its expectation
// independently of the engine's internal table: an engine weight bug must
// fail the replay, not hide behind the same constant.
var vectorWeights = map[string]int{
	"scanner_path":          25,
	"decoy_hit":             30,
	"decoy_lead_follow":     40,
	"honeytoken_use":        50,
	"path_enumeration":      25,
	"ua_suspicious":         15,
	"ua_rotation":           20,
	"no_cookie_persistence": 15,
	"headers_sparse":        10,
	"ua_missing":            10,
	"tooling_curl":          15,
}

// replayCaseResult is one case's outcome in the JSON report; Diff carries
// the first differing field of the first diverging request.
type replayCaseResult struct {
	ID   string `json:"id"`
	OK   bool   `json:"ok"`
	Diff string `json:"diff,omitempty"`
}

// replayReport is the --json shape: the overall verdict, the totals, and
// every case with its first divergence.
type replayReport struct {
	OK     bool               `json:"ok"`
	Total  int                `json:"total"`
	Passed int                `json:"passed"`
	Failed int                `json:"failed"`
	Cases  []replayCaseResult `json:"cases"`
}

// cmdReplay implements `mirage replay`: compose the full decision path in
// memory — exactly the composition of the service parity gate — and drive
// every golden vector case through Service.Decide, comparing the complete
// expected decision. The site configuration contributes its data files and
// decoy catalog (an operator whose catalog drifted from the canon vectors
// sees it here first); the harness itself fixes protect mode with
// enforcement enabled, the vectors' own protected routes, per-case
// allowlists, generous budgets and the frozen clock, because parity is
// measured against the full ladder, not the site's current rung.
func cmdReplay(args []string) int {
	fs, help := newFlagSet("mirage replay", "mirage replay --config FILE [--vectors PATH] [--json]")
	cfgPath := fs.String("config", "", "site configuration file (required)")
	vectorsPath := fs.String("vectors", defaultVectorsPath,
		fmt.Sprintf("golden vector file (default %s)", defaultVectorsPath))
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON instead of the per-case lines")
	fs, code := parseFlags(fs, help, args)
	if fs == nil {
		return code
	}
	if code := extraArgs(fs); code != exitOK {
		return code
	}
	if *cfgPath == "" {
		fmt.Fprintln(stderr, "mirage replay: --config is required")
		return exitUsage
	}
	return runReplay(*cfgPath, *vectorsPath, *jsonOut)
}

// runReplay loads config and vectors, replays every case, renders the
// report, and returns 0 only when every request of every case matched.
func runReplay(cfgPath, vectorsPath string, jsonOut bool) int {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "mirage replay: %v\n", err)
		return exitFail
	}
	vf, err := loadVectors(vectorsPath)
	if err != nil {
		fmt.Fprintf(stderr, "mirage replay: %v\n", err)
		return exitFail
	}
	// Version handshake: the vectors and this build must speak the same
	// protocol and spec, otherwise the replay compares against the wrong
	// contract.
	if vf.SpecVersion != model.SpecVersion || vf.ProtocolVersion != model.ProtocolVersion {
		fmt.Fprintf(stderr, "mirage replay: vectors speak spec %s/protocol %s, build speaks %s/%s: regenerate the vectors or update the engine\n",
			vf.SpecVersion, vf.ProtocolVersion, model.SpecVersion, model.ProtocolVersion)
		return exitFail
	}
	if err := checkVectorShape(vf); err != nil {
		fmt.Fprintf(stderr, "mirage replay: %v\n", err)
		return exitFail
	}

	rules, err := detect.LoadRules(dataDir, cfg.Decoys.CatalogPath, vf.Policy.ProtectedRoutes)
	if err != nil {
		fmt.Fprintf(stderr, "mirage replay: %v\n", err)
		return exitFail
	}
	cat, err := decoy.Load(cfg.Decoys.CatalogPath)
	if err != nil {
		fmt.Fprintf(stderr, "mirage replay: %v\n", err)
		return exitFail
	}

	rep := replayReport{OK: true, Total: len(vf.Cases)}
	requests := 0
	for _, c := range vf.Cases {
		requests += len(c.Requests)
		res := replayCase(c, vf, rules, cat)
		rep.Cases = append(rep.Cases, res)
		if res.OK {
			rep.Passed++
		} else {
			rep.Failed++
			rep.OK = false
		}
	}

	if jsonOut {
		if err := json.NewEncoder(stdout).Encode(rep); err != nil {
			fmt.Fprintf(stderr, "mirage replay: encode report: %v\n", err)
			return exitFail
		}
	} else {
		renderReplay(rep, requests)
	}
	if !rep.OK {
		return exitFail
	}
	return exitOK
}

// loadVectors reads and decodes the vector file.
func loadVectors(path string) (vectorFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return vectorFile{}, fmt.Errorf("read vectors: %w", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		return vectorFile{}, fmt.Errorf("parse vectors: %w", err)
	}
	return vf, nil
}

// checkVectorShape enforces the structural preconditions the replay's
// expectations rest on: request/expectation pairing, and every ban verdict
// being its case's last request — a ban followed by more requests would
// renew instead of scoring, and the vector's expectation would not apply.
func checkVectorShape(vf vectorFile) error {
	if len(vf.Cases) == 0 {
		return fmt.Errorf("vectors carry no cases")
	}
	for _, c := range vf.Cases {
		if len(c.Requests) != len(c.Expected) {
			return fmt.Errorf("case %s: %d requests but %d expectations", c.ID, len(c.Requests), len(c.Expected))
		}
		for i, exp := range c.Expected {
			if exp.Verdict == model.VerdictBan && i != len(c.Expected)-1 {
				return fmt.Errorf("case %s: ban verdict at request %d is not terminal; the renewal path would diverge", c.ID, i+1)
			}
		}
	}
	return nil
}

// replayCase composes a fresh full stack for one case — fresh engine,
// store, queue and gatekeeper, exactly like the parity gate: cases are
// independent sessions — and drives its requests through Service.Decide.
// The harness configuration is built per case because the case's
// allowlisted addresses travel through config.Validate exactly the way a
// site's owner_ips would.
func replayCase(c vectorCase, vf vectorFile, rules detect.Rules, cat *decoy.Catalog) replayCaseResult {
	cfg := config.Default()
	cfg.Mode = config.ModeProtect
	cfg.DashboardToken = replayToken
	cfg.Enforcement.Enabled = true
	cfg.OwnerIPCIDRs = c.AllowlistedIPs
	cfg.ProtectedRoutes = vf.Policy.ProtectedRoutes
	if err := cfg.Validate(); err != nil {
		return replayCaseResult{ID: c.ID, OK: false, Diff: fmt.Sprintf("harness config: %v", err)}
	}
	svc, err := service.New(cfg, detect.New(rules), cat, store.NewMemoryStore(),
		events.NewQueue(events.DefaultQueueCapacity),
		enforce.NewGatekeeper(enforce.Budgets{
			MaxBansPerMinute:  replayMaxBansPerMinute,
			MaxConcurrentBans: replayMaxConcurrentBans,
		}, nil),
		nil, service.Options{Clock: func() int64 { return replayClockMs }})
	if err != nil {
		return replayCaseResult{ID: c.ID, OK: false, Diff: fmt.Sprintf("compose service: %v", err)}
	}

	for i, vr := range c.Requests {
		got := svc.Decide(model.Request{
			Method:       vr.Method,
			Path:         vr.Path,
			ClientIP:     c.ClientIP,
			UserAgent:    vr.UserAgent,
			HeaderCount:  vr.HeaderCount,
			HasCookie:    vr.HasCookie,
			AuthHint:     vr.AuthHint,
			TsMs:         vr.TsMs,
			ForwardedFor: vr.ForwardedFor, // must be ignored (I6, v20)
		})
		if diff := decisionDiff(c.Expected[i], got, vf.Policy.BanTTLms); diff != "" {
			return replayCaseResult{ID: c.ID, OK: false,
				Diff: fmt.Sprintf("request %d: %s", i+1, diff)}
		}
	}
	return replayCaseResult{ID: c.ID, OK: true}
}

// decisionDiff compares one expected decision against the actual, field by
// field in a fixed order, and returns the first divergence (empty when
// they match). The action and request score are derived independently of
// the engine — wantAction from the verdict, wantReqScore from the expected
// signals' weights — so a mapping or weight bug cannot hide behind the
// engine agreeing with itself.
func decisionDiff(exp vectorExpected, got model.Decision, banTTLms int64) string {
	if got.Verdict != exp.Verdict {
		return fmt.Sprintf("verdict: want %s, got %s", exp.Verdict, got.Verdict)
	}
	if got.Action != wantAction(exp.Verdict) {
		return fmt.Sprintf("action: want %s, got %s", wantAction(exp.Verdict), got.Action)
	}
	if got.ReasonCode != exp.ReasonCode {
		return fmt.Sprintf("reason_code: want %s, got %s", exp.ReasonCode, got.ReasonCode)
	}
	if got.Score != exp.Score {
		return fmt.Sprintf("score: want %d, got %d", exp.Score, got.Score)
	}
	wantReqScore := 0
	for _, id := range exp.Signals {
		wantReqScore += vectorWeights[id]
	}
	if got.RequestScore != wantReqScore {
		return fmt.Sprintf("request_score: want %d (sum of signal weights), got %d", wantReqScore, got.RequestScore)
	}
	if !equalSignals(exp.Signals, got.Signals) {
		return fmt.Sprintf("signals: want %v, got %v", exp.Signals, got.Signals)
	}
	if exp.Verdict == model.VerdictDecoyRoute && got.DecoyID == "" {
		return "decoy_id: want non-empty on decoy_route, got empty"
	}
	if exp.Verdict != model.VerdictDecoyRoute && got.DecoyID != "" {
		return fmt.Sprintf("decoy_id: want empty (verdict %s), got %q", exp.Verdict, got.DecoyID)
	}
	if exp.Verdict == model.VerdictBan {
		if got.BanTTLms == nil {
			return fmt.Sprintf("ban_ttl_ms: want %d, got nil", banTTLms)
		}
		if *got.BanTTLms != banTTLms {
			return fmt.Sprintf("ban_ttl_ms: want %d, got %d", banTTLms, *got.BanTTLms)
		}
	} else if got.BanTTLms != nil {
		return fmt.Sprintf("ban_ttl_ms: want nil (verdict %s), got %d", exp.Verdict, *got.BanTTLms)
	}
	return ""
}

// wantAction re-derives the action from the verdict independently of the
// engine and the service (ADAPTER-PROTOCOL section 3), so a mapping bug
// cannot hide behind either.
func wantAction(verdict string) string {
	switch verdict {
	case model.VerdictDecoyRoute:
		return model.ActionServeDecoy
	case model.VerdictThrottle:
		return model.ActionThrottle
	case model.VerdictBan:
		return model.ActionBan
	default:
		return model.ActionPass
	}
}

// equalSignals compares two signal lists element-wise; nil and empty are
// equivalent, matching the vectors' encoding of "nothing fired".
func equalSignals(want, got []string) bool {
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if want[i] != got[i] {
			return false
		}
	}
	return true
}

// renderReplay prints the human report: one PASS/FAIL line per case with
// the first divergence on failure, then the summary line.
func renderReplay(rep replayReport, requests int) {
	for _, c := range rep.Cases {
		if c.OK {
			fmt.Fprintf(stdout, "PASS %s\n", c.ID)
			continue
		}
		fmt.Fprintf(stdout, "FAIL %s: %s\n", c.ID, c.Diff)
	}
	if rep.OK {
		fmt.Fprintf(stdout, "replay: %d/%d cases passed (%d requests)\n", rep.Passed, rep.Total, requests)
		return
	}
	fmt.Fprintf(stdout, "replay: %d/%d cases passed, %d failed (%d requests)\n",
		rep.Passed, rep.Total, rep.Failed, requests)
}
