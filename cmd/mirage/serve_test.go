package main

import (
	"strings"
	"testing"
)

// The serve tests cover the flag-validation layer only: upstream presence
// and shape, and the dashboard's loopback-only bind. The edge wiring behind
// it (internal/edge) is exercised once the adapter package lands; these
// tests make sure no wiring is ever reached with bad flags in the first
// place — validation is complete before anything is opened or composed.

func TestServeRequiresUpstream(t *testing.T) {
	runCmd := capture(t)
	cfgPath := writeSiteConfig(t)

	code, out, errOut := runCmd("serve", "--config", cfgPath)
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d (the config has no upstream key; the flag is the only source)", code, exitUsage)
	}
	if out != "" {
		t.Errorf("stdout %q, want empty (a usage error must not boot anything)", out)
	}
	if !strings.Contains(errOut, "--upstream is required") {
		t.Errorf("stderr %q, want the missing-upstream message", errOut)
	}
}

func TestServeRequiresConfig(t *testing.T) {
	runCmd := capture(t)
	code, _, errOut := runCmd("serve", "--upstream", "http://127.0.0.1:9000")
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut, "--config is required") {
		t.Errorf("stderr %q, want the missing-config message", errOut)
	}
}

func TestServeRejectsBadUpstream(t *testing.T) {
	runCmd := capture(t)
	cfgPath := writeSiteConfig(t)

	tests := []struct {
		raw  string
		want string
	}{
		// No scheme: the reverse proxy would rewrite against the empty
		// base and every request would 502 at runtime, not at boot.
		{"127.0.0.1:9000", "scheme must be http or https"},
		{"ftp://127.0.0.1:9000", "scheme must be http or https"},
		{"http://", "host is required"},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			code, _, errOut := runCmd("serve", "--config", cfgPath, "--upstream", tc.raw)
			if code != exitUsage {
				t.Errorf("exit code = %d, want %d", code, exitUsage)
			}
			if !strings.Contains(errOut, tc.want) {
				t.Errorf("stderr %q, want %q", errOut, tc.want)
			}
		})
	}
}

func TestServeRejectsNonLoopbackDashboard(t *testing.T) {
	runCmd := capture(t)
	cfgPath := writeSiteConfig(t)

	tests := []struct {
		name string
		addr string
	}{
		{"all interfaces", "0.0.0.0:8090"},
		{"public address", "192.0.2.1:8090"},
		{"a name, not an IP literal", "localhost:8090"},
		{"not host:port", "8090"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := runCmd("serve", "--config", cfgPath,
				"--upstream", "http://127.0.0.1:9000", "--dashboard-addr", tc.addr)
			if code != exitUsage {
				t.Errorf("exit code = %d, want %d (the dashboard never leaves loopback)", code, exitUsage)
			}
			if out != "" {
				t.Errorf("stdout %q, want empty", out)
			}
			if !strings.Contains(errOut, "loopback") {
				t.Errorf("stderr %q, want the loopback refusal", errOut)
			}
		})
	}
}

func TestCheckLoopbackTable(t *testing.T) {
	tests := []struct {
		addr    string
		wantErr bool
	}{
		{"127.0.0.1:8090", false},
		{"127.0.0.1:0", false},
		{"127.66.66.66:8090", false}, // the whole 127/8 block is loopback
		{"[::1]:8090", false},
		{"0.0.0.0:8090", true},   // wildcard: reachable from the network
		{"192.0.2.1:8090", true}, // public documentation address
		{"10.0.0.1:8090", true},  // private, still not loopback
		{"localhost:8090", true}, // a name, not an IP literal
		{"8090", true},           // no host:port shape
		{"127.0.0.1", true},      // no port
		{"", true},
	}
	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			err := checkLoopback(tc.addr)
			if tc.wantErr && err == nil {
				t.Errorf("checkLoopback(%q) = nil, want an error", tc.addr)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("checkLoopback(%q) = %v, want nil", tc.addr, err)
			}
		})
	}
}

func TestParseUpstreamTable(t *testing.T) {
	tests := []struct {
		raw     string
		wantErr string // empty means success
	}{
		{"http://127.0.0.1:9000", ""},
		{"https://origin.example.test", ""},
		{"http://unix-socket-host/", ""},
		{"127.0.0.1:9000", "scheme must be http or https"},
		{"ftp://127.0.0.1:9000", "scheme must be http or https"},
		{"http://", "host is required"},
		{"", "scheme must be http or https"},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			u, err := parseUpstream(tc.raw)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("parseUpstream(%q) = %v, want success", tc.raw, err)
				}
				if u.Host == "" {
					t.Errorf("parseUpstream(%q) produced an empty host", tc.raw)
				}
				return
			}
			if err == nil {
				t.Fatalf("parseUpstream(%q) succeeded, want %q", tc.raw, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("parseUpstream(%q) = %v, want it to contain %q", tc.raw, err, tc.wantErr)
			}
		})
	}
}
