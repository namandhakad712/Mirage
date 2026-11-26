package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirage-shield/mirage/internal/config"
)

// postureJSON is the decoded --json shape of the posture report.
type postureJSON struct {
	Mode     string `json:"mode"`
	Warnings []string
	Checks   []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"checks"`
}

func TestPostureReportsModeRoutesAndBudgets(t *testing.T) {
	runCmd := capture(t)
	cfgPath := writeSiteConfig(t, "mode: protect")

	code, out, errOut := runCmd("posture", "--config", cfgPath)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d (posture is informational); stderr: %s", code, exitOK, errOut)
	}
	for _, want := range []struct {
		name  string
		value string
	}{
		{"mode", "protect"},
		// The canon protected routes (I4) and the default budgets must be
		// visible so an operator can see what serve would actually do.
		{"protected routes", "/wp-login.php"},
		{"decision budget", "5 ms"},
		{"queue bounds", "10000"},
		{"ban budgets", "10 per minute"},
		{"ban ttl", "1800000 ms"},
		{"dashboard token", "present"},
		{"store", "sqlite at mirage.db"},
	} {
		if !strings.Contains(out, want.value) {
			t.Errorf("stdout missing %s %q:\n%s", want.name, want.value, out)
		}
	}
}

func TestPostureWarningProtectWithoutBlock(t *testing.T) {
	runCmd := capture(t)
	cfgPath := writeSiteConfig(t, "mode: protect")

	code, out, _ := runCmd("posture", "--config", cfgPath)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d (a warning is not a failure)", code, exitOK)
	}
	if !strings.Contains(out, "mode protect without enforcement.enabled") {
		t.Errorf("stdout %q, want the protect-without-block warning", out)
	}
}

func TestPostureWarningEmptyTrustedProxies(t *testing.T) {
	runCmd := capture(t)
	// The fixture sets no trusted_proxies, which is the warning's case.
	cfgPath := writeSiteConfig(t)

	code, out, _ := runCmd("posture", "--config", cfgPath)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	if !strings.Contains(out, "no trusted proxies") {
		t.Errorf("stdout %q, want the empty-trusted-proxies warning", out)
	}
}

func TestPostureNoProxyWarningWhenConfigured(t *testing.T) {
	runCmd := capture(t)
	cfgPath := writeSiteConfig(t,
		"trusted_proxies:",
		"  - \"127.0.0.1/32\"",
	)
	code, out, _ := runCmd("posture", "--config", cfgPath)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	if strings.Contains(out, "no trusted proxies") {
		t.Errorf("stdout warns about trusted proxies although one is configured:\n%s", out)
	}
}

func TestPostureWarningWorldReadableStore(t *testing.T) {
	runCmd := capture(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "site.db")
	// A world-readable database file: the event log holds
	// attacker-adjacent data (I7), so posture must name it.
	if err := os.WriteFile(db, []byte("x"), 0o644); err != nil {
		t.Fatalf("write db fixture: %v", err)
	}
	cfgPath := writeSiteConfig(t, "store:", "  path: "+db)

	code, out, _ := runCmd("posture", "--config", cfgPath)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	if !strings.Contains(out, "group/other accessible") {
		t.Errorf("stdout %q, want the store permission warning", out)
	}

	// Tightened to owner-only: the warning must disappear.
	if err := os.Chmod(db, 0o600); err != nil {
		t.Fatalf("chmod db: %v", err)
	}
	code, out, _ = runCmd("posture", "--config", cfgPath)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	if strings.Contains(out, "group/other accessible") {
		t.Errorf("stdout still warns after the permissions were fixed:\n%s", out)
	}
}

func TestPostureWarningKillSwitchEngaged(t *testing.T) {
	runCmd := capture(t)
	cfgPath := writeSiteConfig(t,
		"mode: protect",
		"enforcement:",
		"  enabled: true",
		"  kill_switch: true",
	)
	code, out, _ := runCmd("posture", "--config", cfgPath)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	if !strings.Contains(out, "kill switch engaged") {
		t.Errorf("stdout %q, want the kill-switch warning", out)
	}
}

func TestPostureJSONMirrorsReport(t *testing.T) {
	runCmd := capture(t)
	cfgPath := writeSiteConfig(t, "mode: tripwires")

	code, out, _ := runCmd("posture", "--config", cfgPath, "--json")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	var rep postureJSON
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("parse JSON report: %v\nreport: %s", err, out)
	}
	if rep.Mode != "tripwires" {
		t.Errorf("mode = %q, want tripwires", rep.Mode)
	}
	if rep.Warnings == nil {
		t.Error("warnings = null, want an array (empty is fine, null is not)")
	}
	var names []string
	for _, c := range rep.Checks {
		names = append(names, c.Name)
	}
	for _, want := range []string{"mode", "enforcement", "kill switch", "protected routes", "dashboard token", "store"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("checks = %v, want a %q line", names, want)
		}
	}
}

func TestPostureInvalidConfigExitsOne(t *testing.T) {
	runCmd := capture(t)
	path := filepath.Join(t.TempDir(), "mirage.yaml")
	// Enforcement outside protect mode is a hard validation error (I9);
	// posture exits 1 on exactly this class of failure.
	if err := os.WriteFile(path, []byte("dashboard_token: t\nmode: look\nenforcement:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	code, out, errOut := runCmd("posture", "--config", path)
	if code != exitFail {
		t.Fatalf("exit code = %d, want %d", code, exitFail)
	}
	if out != "" {
		t.Errorf("stdout %q, want empty (the error goes to stderr)", out)
	}
	if !strings.Contains(errOut, "enforcement.enabled") {
		t.Errorf("stderr %q, want the validation error", errOut)
	}
}

// TestPostureWarningsTable drives the pure warning computation directly
// with hand-built configurations — including the states config.Load can
// never produce, which is exactly why the computation is a function and
// not inline in the command.
func TestPostureWarningsTable(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*config.Config)
		want []string
	}{
		{
			name: "protect without block and without token",
			mut: func(c *config.Config) {
				c.Mode = config.ModeProtect
				c.DashboardToken = ""
			},
			want: []string{
				"mode protect without enforcement.enabled",
				"protect mode without a dashboard token",
				"no trusted proxies",
			},
		},
		{
			name: "look mode with trusted proxy is clean",
			mut: func(c *config.Config) {
				c.TrustedProxyCIDRs = []string{"127.0.0.1/32"}
			},
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.DashboardToken = "test-dashboard-token-0123456789abcdef"
			tc.mut(cfg)
			got := postureWarnings(cfg)
			if len(got) != len(tc.want) {
				t.Fatalf("warnings = %v, want %v", got, tc.want)
			}
			for i := range got {
				if !strings.Contains(got[i], tc.want[i]) {
					t.Errorf("warning[%d] = %q, want it to contain %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
