// Package model holds the types shared by every Mirage component: the
// request an adapter submits, the decision the engine returns, the event
// Core persists. Types follow spec/ADAPTER-PROTOCOL.md v1; wire consumers
// must treat every attacker-influenced field as untrusted input (I7).
package model

// Protocol and spec versions this build speaks.
const (
	ProtocolVersion = "1"
	SpecVersion     = "1.1.0"
)

// Verdict ladder rungs, lowest to highest (spec/SIGNALS.md section 5).
const (
	VerdictObserve    = "observe"
	VerdictTag        = "tag"
	VerdictDecoyRoute = "decoy_route"
	VerdictThrottle   = "throttle"
	VerdictBan        = "ban"
)

// Decision actions (spec/ADAPTER-PROTOCOL.md section 3).
const (
	ActionPass       = "pass"
	ActionServeDecoy = "serve_decoy"
	ActionThrottle   = "throttle"
	ActionBan        = "ban"
)

// Request is what an adapter submits per request. All fields except TsMs
// are attacker-influenced.
type Request struct {
	Method       string `json:"method"`
	Path         string `json:"path"` // raw, including dot segments and query
	ClientIP     string `json:"client_ip"`
	UserAgent    string `json:"user_agent"`
	HeaderCount  int    `json:"header_count"`
	HasCookie    bool   `json:"has_cookie"`
	AuthHint     string `json:"auth_hint,omitempty"` // credential material visible to the adapter
	TsMs         int64  `json:"ts_ms"`
	TrustedPeer  bool   `json:"trusted_peer"`              // immediate peer was a trusted proxy
	ForwardedFor string `json:"x_forwarded_for,omitempty"` // informational, never trusted alone (I6)
}

// Signal is one fired detection with its fixed weight, class and reason
// code (spec/SIGNALS.md section 4).
type Signal struct {
	ID     string `json:"id"`
	Weight int    `json:"weight"`
	Class  string `json:"class"` // "high" | "medium"
	Reason string `json:"reason"`
}

// Decision is the engine's answer to one Request. The zero value is never
// valid; use FailOpen for the reserved fail-open decision.
type Decision struct {
	ProtocolVersion string   `json:"protocol_version"`
	SpecVersion     string   `json:"spec_version"`
	Verdict         string   `json:"verdict"`
	Action          string   `json:"action"`
	DecoyID         string   `json:"decoy_id,omitempty"`
	SessionKey      string   `json:"session_key,omitempty"`
	ReasonCode      string   `json:"reason_code"`
	RequestScore    int      `json:"request_score"`
	Score           int      `json:"score"`
	Signals         []string `json:"signals"`
	BanTTLms        *int64   `json:"ban_ttl_ms"`
}

// Event is the asynchronous record of one decision (ADAPTER-PROTOCOL
// section 4). Emission is bounded and must never block the hot path.
type Event struct {
	ProtocolVersion string    `json:"protocol_version"`
	TsMs            int64     `json:"ts_ms"`
	SessionKey      string    `json:"session_key"`
	ClientIP        string    `json:"client_ip"`
	Method          string    `json:"method"`
	Path            string    `json:"path"`
	Decision        *Decision `json:"decision"`
}

// FailOpenReason is reserved for the fail-open decision and is never a ban
// input.
const FailOpenReason = "SIG-000"

// BanTTL is the fixed short ban duration (spec/SIGNALS.md section 5).
const BanTTL int64 = 1_800_000

// FailOpen returns the reserved decision used on any internal failure,
// unknown protocol version or deadline overrun: pass everything through,
// score nothing (I1).
func FailOpen() Decision {
	return Decision{
		ProtocolVersion: ProtocolVersion,
		SpecVersion:     SpecVersion,
		Verdict:         VerdictObserve,
		Action:          ActionPass,
		ReasonCode:      FailOpenReason,
	}
}
