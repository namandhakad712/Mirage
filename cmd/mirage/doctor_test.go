package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// doctorJSON is the decoded --json shape of the doctor report.
type doctorJSON struct {
	OK     bool `json:"ok"`
	Checks []struct {
		Name   string `json:"name"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	} `json:"checks"`
	SpecVersion string `json:"spec_version"`
	Mode        string `json:"mode"`
}

func TestDoctorCleanConfigPasses(t *testing.T) {
	// doctor probes the engine's data files and the catalog relative to
	// the working directory; run from the repository root, as an
	// operator's site root would hold data/ and spec/.
	chdirRepoRoot(t)
	runCmd := capture(t)
	cfgPath := writeSiteConfig(t)

	code, out, errOut := runCmd("doctor", "--config", cfgPath)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, exitOK, errOut)
	}
	for _, want := range []string{"config", "engine data files", "decoy catalog", "store", "kill switch"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout %q, want a %q check", out, want)
		}
	}
	if strings.Contains(out, "FAIL") {
		t.Errorf("stdout %q, want no failing checks", out)
	}
}

func TestDoctorCleanConfigJSON(t *testing.T) {
	chdirRepoRoot(t)
	runCmd := capture(t)
	cfgPath := writeSiteConfig(t)

	code, out, _ := runCmd("doctor", "--config", cfgPath, "--json")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	var rep doctorJSON
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("parse JSON report: %v\nreport: %s", err, out)
	}
	if !rep.OK {
		t.Errorf("ok = false, want true; checks: %+v", rep.Checks)
	}
	if rep.Mode != "look" {
		t.Errorf("mode = %q, want look (the fixture sets no mode)", rep.Mode)
	}
	if rep.SpecVersion == "" {
		t.Error("spec_version is empty")
	}
	for _, c := range rep.Checks {
		if !c.OK {
			t.Errorf("check %q failed: %s", c.Name, c.Detail)
		}
	}
}

func TestDoctorMissingConfigFails(t *testing.T) {
	runCmd := capture(t)
	code, out, _ := runCmd("doctor", "--config", filepath.Join(t.TempDir(), "absent.yaml"), "--json")
	if code != exitFail {
		t.Fatalf("exit code = %d, want %d", code, exitFail)
	}
	var rep doctorJSON
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("parse JSON report: %v\nreport: %s", err, out)
	}
	if rep.OK {
		t.Error("ok = true for a missing config, want false")
	}
	if len(rep.Checks) != 1 || rep.Checks[0].Name != "config" || rep.Checks[0].OK {
		t.Errorf("checks = %+v, want exactly the failing config check", rep.Checks)
	}
}

func TestDoctorConnectorEnvResolution(t *testing.T) {
	chdirRepoRoot(t)
	runCmd := capture(t)
	// A crowdsec connector whose machine key variable is not exported: the
	// connector is fully configured (Validate accepts it), doctor's job is
	// to catch the missing secret before serve needs it.
	cfgPath := writeSiteConfig(t,
		"connectors:",
		"  crowdsec:",
		"    lapi_url: \"http://127.0.0.1:8081\"",
		"    api_key_env: \"MIRAGE_DOCTOR_TEST_UNSET_9F3A\"",
	)

	t.Run("human table", func(t *testing.T) {
		code, out, errOut := runCmd("doctor", "--config", cfgPath)
		if code != exitFail {
			t.Fatalf("exit code = %d, want %d", code, exitFail)
		}
		if !strings.Contains(out, "connector crowdsec") {
			t.Errorf("stdout %q, want the connector check named", out)
		}
		if !strings.Contains(out, "FAIL") {
			t.Errorf("stdout %q, want a FAIL row", out)
		}
		if !strings.Contains(errOut, "1 of") {
			t.Errorf("stderr %q, want the failed-check count", errOut)
		}
	})

	t.Run("json names the variable, never a value", func(t *testing.T) {
		code, out, _ := runCmd("doctor", "--config", cfgPath, "--json")
		if code != exitFail {
			t.Fatalf("exit code = %d, want %d", code, exitFail)
		}
		var rep doctorJSON
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("parse JSON report: %v\nreport: %s", err, out)
		}
		if rep.OK {
			t.Error("ok = true, want false (the secret does not resolve)")
		}
		var found *struct {
			Name   string `json:"name"`
			OK     bool   `json:"ok"`
			Detail string `json:"detail"`
		}
		for i := range rep.Checks {
			if rep.Checks[i].Name == "connector crowdsec" {
				found = &rep.Checks[i]
			}
		}
		if found == nil {
			t.Fatalf("checks = %+v, want a connector crowdsec check", rep.Checks)
		}
		if found.OK {
			t.Errorf("connector check ok = true, want false: %s", found.Detail)
		}
		if !strings.Contains(found.Detail, "MIRAGE_DOCTOR_TEST_UNSET_9F3A") {
			t.Errorf("detail %q, want the variable NAME", found.Detail)
		}
		if !strings.Contains(found.Detail, "not set") {
			t.Errorf("detail %q, want the unresolved verdict", found.Detail)
		}
	})
}

func TestDoctorConnectorEnvResolvesWhenSet(t *testing.T) {
	chdirRepoRoot(t)
	runCmd := capture(t)
	t.Setenv("MIRAGE_DOCTOR_TEST_SET_KEY", "a-resolved-secret-value")
	cfgPath := writeSiteConfig(t,
		"connectors:",
		"  crowdsec:",
		"    lapi_url: \"http://127.0.0.1:8081\"",
		"    api_key_env: \"MIRAGE_DOCTOR_TEST_SET_KEY\"",
	)
	code, out, _ := runCmd("doctor", "--config", cfgPath, "--json")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	// The resolved check must name the variable and say it resolves, and
	// must never carry the value (I11).
	if strings.Contains(out, "a-resolved-secret-value") {
		t.Errorf("report leaks the secret value: %s", out)
	}
	if !strings.Contains(out, "MIRAGE_DOCTOR_TEST_SET_KEY resolves") {
		t.Errorf("report %q, want the resolution named", out)
	}
}

func TestDoctorDoesNotTouchSqliteFile(t *testing.T) {
	chdirRepoRoot(t)
	runCmd := capture(t)
	dir := t.TempDir()
	cfgPath := writeSiteConfig(t, "store:", "  path: "+filepath.Join(dir, "site.db"))

	code, _, _ := runCmd("doctor", "--config", cfgPath)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	if _, err := os.Stat(filepath.Join(dir, "site.db")); !os.IsNotExist(err) {
		t.Errorf("doctor created or touched the sqlite file at %s (it must stay non-mutating)", dir)
	}
}

func TestDoctorRequiresConfigFlag(t *testing.T) {
	runCmd := capture(t)
	code, _, errOut := runCmd("doctor")
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut, "--config is required") {
		t.Errorf("stderr %q, want the missing-flag message", errOut)
	}
}
