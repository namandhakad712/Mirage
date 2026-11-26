package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mirage-shield/mirage/internal/config"
	"github.com/mirage-shield/mirage/internal/decoy"
	"github.com/mirage-shield/mirage/internal/detect"
	"github.com/mirage-shield/mirage/internal/enforce"
	"github.com/mirage-shield/mirage/internal/events"
	"github.com/mirage-shield/mirage/internal/model"
	"github.com/mirage-shield/mirage/internal/store"
)

// The parity gate, one layer up from internal/detect: the same golden
// vectors replayed THROUGH the service in protect mode — the full decision
// path (never-scored resolution, engine scoring, mode gating, gatekeeper
// wiring), not the engine alone. The service must not distort a single
// verdict, action, signal, score or reason code; CI fails on any divergence
// (spec/SIGNALS.md header). Every ban verdict in the vector set is a
// case's last request, so no renewal path can interpose a different
// decision midway (asserted by shape below).

// vectorFile mirrors the subset of vectors.json the gate consumes.
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
	AuthHint     string `json:"auth_hint"`
	ForwardedFor string `json:"x_forwarded_for"`
}

type vectorExpected struct {
	Signals    []string `json:"signals"`
	Verdict    string   `json:"verdict"`
	Score      int      `json:"score"`
	ReasonCode string   `json:"reason_code"`
}

// vectorWeights is the fixed signal table (SIGNALS.md section 4),
// duplicated here so the request-score check derives its expectation
// independently of the engine's internal table.
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

// repoPath resolves a path relative to the repository root from this test
// file's compile-time location, so the gate works no matter the working
// directory go test was launched from (the same approach as the decoy and
// detect suites).
func repoPath(t *testing.T, elems ...string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("service: cannot locate test source file")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(append([]string{root}, elems...)...)
}

// vectorClock is a frozen decision clock: the deadline arithmetic always
// sees zero elapsed, so vector parity is measured without any real-time
// flakiness from a loaded machine.
func vectorClock() func() int64 {
	return func() int64 { return 1_789_000_000_000 }
}

// wantAction re-derives the action from the verdict independently of the
// engine and the service, so a mapping bug cannot hide behind either.
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

func equalStrings(want, got []string) bool {
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

func TestServiceGoldenVectors(t *testing.T) {
	raw, err := os.ReadFile(repoPath(t, "spec", "golden-vectors", "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	// Version handshake: the vectors and this build must speak the same
	// protocol and spec, otherwise the gate is comparing against the wrong
	// contract.
	if vf.SpecVersion != model.SpecVersion {
		t.Fatalf("vectors spec_version %q != build %q: regenerate vectors or update the engine", vf.SpecVersion, model.SpecVersion)
	}
	if vf.ProtocolVersion != model.ProtocolVersion {
		t.Fatalf("vectors protocol_version %q != build %q", vf.ProtocolVersion, model.ProtocolVersion)
	}
	total := 0
	for _, c := range vf.Cases {
		total += len(c.Requests)
	}
	if len(vf.Cases) != 20 || total != 68 {
		t.Fatalf("vectors shape changed: %d cases / %d requests, want 20 / 68", len(vf.Cases), total)
	}
	// The replay assumes every ban verdict is its case's last request: a
	// ban followed by more requests would renew instead of scoring, and
	// the vector's expectation would not apply.
	for _, c := range vf.Cases {
		for i, exp := range c.Expected {
			if exp.Verdict == model.VerdictBan && i != len(c.Expected)-1 {
				t.Fatalf("case %s: ban verdict at request %d is not terminal; the renewal path would diverge", c.ID, i+1)
			}
		}
	}

	// The exact inputs the production loader reads: the repo's data
	// directory, the canon decoy catalog and the vectors' protected routes.
	rules, err := detect.LoadRules(
		repoPath(t, "data"),
		repoPath(t, "spec", "decoy-catalog", "catalog.yaml"),
		vf.Policy.ProtectedRoutes,
	)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	cat, err := decoy.Load(repoPath(t, "spec", "decoy-catalog", "catalog.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	for _, c := range vf.Cases {
		t.Run(c.ID, func(t *testing.T) {
			if len(c.Requests) != len(c.Expected) {
				t.Fatalf("case %s: %d requests but %d expectations", c.ID, len(c.Requests), len(c.Expected))
			}
			// The service resolves never-scored addresses itself from the
			// config's owner ranges, so the case's allowlist travels
			// through Validate exactly like a site's config would.
			cfg := config.Default()
			cfg.Mode = config.ModeProtect
			cfg.DashboardToken = testToken
			cfg.Enforcement.Enabled = true
			cfg.OwnerIPCIDRs = c.AllowlistedIPs
			cfg.ProtectedRoutes = vf.Policy.ProtectedRoutes
			if err := cfg.Validate(); err != nil {
				t.Fatalf("validate config: %v", err)
			}
			// Fresh engine, store, queue and gatekeeper per case: cases
			// are independent sessions, and generous budgets keep the
			// gatekeeper from vetoing any vector's terminal ban.
			svc, err := New(cfg, detect.New(rules), cat, store.NewMemoryStore(),
				events.NewQueue(events.DefaultQueueCapacity),
				enforce.NewGatekeeper(enforce.Budgets{MaxBansPerMinute: 100, MaxConcurrentBans: 100}, nil),
				nil, Options{Clock: vectorClock()})
			if err != nil {
				t.Fatalf("new service: %v", err)
			}

			for i, vr := range c.Requests {
				exp := c.Expected[i]
				t.Run(fmt.Sprintf("req%02d", i+1), func(t *testing.T) {
					req := model.Request{
						Method:       vr.Method,
						Path:         vr.Path,
						ClientIP:     c.ClientIP,
						UserAgent:    vr.UserAgent,
						HeaderCount:  vr.HeaderCount,
						HasCookie:    vr.HasCookie,
						AuthHint:     vr.AuthHint,
						TsMs:         vr.TsMs,
						ForwardedFor: vr.ForwardedFor, // must be ignored (I6, v20)
					}
					got := svc.Decide(req)

					var diffs []string
					if !equalStrings(exp.Signals, got.Signals) {
						diffs = append(diffs, fmt.Sprintf("signals:       want %v, got %v", exp.Signals, got.Signals))
					}
					if got.Verdict != exp.Verdict {
						diffs = append(diffs, fmt.Sprintf("verdict:       want %s, got %s", exp.Verdict, got.Verdict))
					}
					if got.Action != wantAction(exp.Verdict) {
						diffs = append(diffs, fmt.Sprintf("action:        want %s, got %s", wantAction(exp.Verdict), got.Action))
					}
					if got.Score != exp.Score {
						diffs = append(diffs, fmt.Sprintf("score:         want %d, got %d", exp.Score, got.Score))
					}
					if got.ReasonCode != exp.ReasonCode {
						diffs = append(diffs, fmt.Sprintf("reason_code:   want %s, got %s", exp.ReasonCode, got.ReasonCode))
					}
					wantReqScore := 0
					for _, id := range exp.Signals {
						wantReqScore += vectorWeights[id]
					}
					if got.RequestScore != wantReqScore {
						diffs = append(diffs, fmt.Sprintf("request_score: want %d (sum of signal weights), got %d", wantReqScore, got.RequestScore))
					}
					if wantKey := model.SessionKey(c.ClientIP); got.SessionKey != wantKey {
						diffs = append(diffs, fmt.Sprintf("session_key:   want %s, got %s", wantKey, got.SessionKey))
					}
					if exp.Verdict == model.VerdictBan {
						if got.BanTTLms == nil {
							diffs = append(diffs, fmt.Sprintf("ban_ttl_ms:    want %d, got nil", vf.Policy.BanTTLms))
						} else if *got.BanTTLms != vf.Policy.BanTTLms {
							diffs = append(diffs, fmt.Sprintf("ban_ttl_ms:    want %d, got %d", vf.Policy.BanTTLms, *got.BanTTLms))
						}
					} else if got.BanTTLms != nil {
						diffs = append(diffs, fmt.Sprintf("ban_ttl_ms:    want nil (verdict %s), got %d", exp.Verdict, *got.BanTTLms))
					}
					if exp.Verdict == model.VerdictDecoyRoute && got.DecoyID == "" {
						diffs = append(diffs, "decoy_id:      want non-empty on decoy_route, got empty")
					}
					if exp.Verdict != model.VerdictDecoyRoute && got.DecoyID != "" {
						diffs = append(diffs, fmt.Sprintf("decoy_id:      want empty (verdict %s), got %q", exp.Verdict, got.DecoyID))
					}
					if got.ProtocolVersion != model.ProtocolVersion || got.SpecVersion != model.SpecVersion {
						diffs = append(diffs, fmt.Sprintf("versions:      want %s/%s, got %s/%s",
							model.ProtocolVersion, model.SpecVersion, got.ProtocolVersion, got.SpecVersion))
					}

					if len(diffs) > 0 {
						t.Errorf("case %s request %d (%s %s, ua %q, headers %d, cookie %v, ts %d) diverges:\n  %s",
							c.ID, i+1, vr.Method, vr.Path, vr.UserAgent, vr.HeaderCount, vr.HasCookie, vr.TsMs,
							strings.Join(diffs, "\n  "))
					}
				})
			}
		})
	}
}
