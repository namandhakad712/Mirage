package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mirage-shield/mirage/internal/model"
)

// The parity gate: every request of every case in
// spec/golden-vectors/vectors.json must produce exactly the expected
// signals, verdict, score and reason code. This is the contract the Go core
// and the TypeScript worker port both live under; CI fails on any
// divergence (spec/SIGNALS.md header).

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

// repoPath resolves a path relative to the repository root from this test
// file's compile-time location, so the gate works no matter the working
// directory go test was launched from.
func repoPath(t *testing.T, elems ...string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("detect: cannot locate test source file")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(append([]string{root}, elems...)...)
}

// equalStrings compares two string slices element-wise; nil and empty are
// equal (the engine emits [] for "no signals").
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

// ipAllowlisted implements the harness rule: the case IP is allowlisted
// when it appears in allowlisted_ips, comparing the IP part of entries that
// carry a CIDR suffix (v08 uses "192.0.2.50/32"; a bare IP also matches).
func ipAllowlisted(ip string, list []string) bool {
	for _, entry := range list {
		if base, _, found := strings.Cut(entry, "/"); found {
			if base == ip {
				return true
			}
			continue
		}
		if entry == ip {
			return true
		}
	}
	return false
}

// wantAction re-derives the action from the verdict independently of the
// engine, so a mapping bug cannot hide behind the engine's own helper.
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

func TestGoldenVectors(t *testing.T) {
	raw, err := os.ReadFile(repoPath(t, "spec", "golden-vectors", "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	// Version handshake: the vectors and this build must speak the same
	// spec, otherwise the gate is comparing against the wrong contract.
	if vf.SpecVersion != model.SpecVersion {
		t.Fatalf("vectors spec_version %q != engine %q: regenerate vectors or update the engine", vf.SpecVersion, model.SpecVersion)
	}
	if vf.ProtocolVersion != model.ProtocolVersion {
		t.Fatalf("vectors protocol_version %q != engine %q", vf.ProtocolVersion, model.ProtocolVersion)
	}
	// The documented parity contract is 20 cases / 68 requests; a change
	// here means the spec bumped and the gate must be re-read.
	total := 0
	for _, c := range vf.Cases {
		total += len(c.Requests)
	}
	if len(vf.Cases) != 20 || total != 68 {
		t.Fatalf("vectors shape changed: %d cases / %d requests, want 20 / 68", len(vf.Cases), total)
	}

	rules, err := LoadRules(
		repoPath(t, "data"),
		repoPath(t, "spec", "decoy-catalog", "catalog.yaml"),
		vf.Policy.ProtectedRoutes,
	)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}

	// The vectors' policy block is the engine's contract: the shared
	// thresholds must match DefaultPolicy exactly, or the engine's defaults
	// have drifted from the spec.
	wantPolicy := Policy{
		SessionTTLms:        vf.Policy.SessionTTLms,
		UAWindowMs:          vf.Policy.UAWindowMs,
		EnumWindowMs:        vf.Policy.EnumWindowMs,
		EnumThreshold:       vf.Policy.EnumThreshold,
		UARotationThreshold: vf.Policy.UARotationThreshold,
		BanTTLms:            vf.Policy.BanTTLms,
	}
	got := rules.Policy
	if wantPolicy.SessionTTLms != got.SessionTTLms || wantPolicy.UAWindowMs != got.UAWindowMs ||
		wantPolicy.EnumWindowMs != got.EnumWindowMs || wantPolicy.EnumThreshold != got.EnumThreshold ||
		wantPolicy.UARotationThreshold != got.UARotationThreshold || wantPolicy.BanTTLms != got.BanTTLms {
		t.Fatalf("policy drift: vectors %+v, engine %+v", wantPolicy, got)
	}

	// Signal weights are fixed (SIGNALS section 4); the request-score check
	// below derives expectations from this table.
	weightByID := make(map[string]int, signalCount)
	for _, def := range signalTable {
		weightByID[def.ID] = def.Weight
	}

	for _, c := range vf.Cases {
		t.Run(c.ID, func(t *testing.T) {
			if len(c.Requests) != len(c.Expected) {
				t.Fatalf("case %s: %d requests but %d expectations", c.ID, len(c.Requests), len(c.Expected))
			}
			// Fresh engine per case: cases are independent sessions.
			engine := New(rules)
			allowlisted := ipAllowlisted(c.ClientIP, c.AllowlistedIPs)

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
					got := engine.Decide(req, allowlisted)

					var diffs []string
					if !equalStrings(exp.Signals, got.Signals) {
						diffs = append(diffs, fmt.Sprintf("signals:       want %v, got %v", exp.Signals, got.Signals))
					}
					if got.Verdict != exp.Verdict {
						diffs = append(diffs, fmt.Sprintf("verdict:       want %s, got %s", exp.Verdict, got.Verdict))
					}
					if got.Score != exp.Score {
						diffs = append(diffs, fmt.Sprintf("score:         want %d, got %d", exp.Score, got.Score))
					}
					if got.ReasonCode != exp.ReasonCode {
						diffs = append(diffs, fmt.Sprintf("reason_code:   want %s, got %s", exp.ReasonCode, got.ReasonCode))
					}
					wantReqScore := 0
					for _, id := range exp.Signals {
						wantReqScore += weightByID[id]
					}
					if got.RequestScore != wantReqScore {
						diffs = append(diffs, fmt.Sprintf("request_score: want %d (sum of signal weights), got %d", wantReqScore, got.RequestScore))
					}
					if wantKey := model.SessionKey(c.ClientIP); got.SessionKey != wantKey {
						diffs = append(diffs, fmt.Sprintf("session_key:   want %s, got %s", wantKey, got.SessionKey))
					}
					if wantAction := wantAction(exp.Verdict); got.Action != wantAction {
						diffs = append(diffs, fmt.Sprintf("action:        want %s, got %s", wantAction, got.Action))
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
