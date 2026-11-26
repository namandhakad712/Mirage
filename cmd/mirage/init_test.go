package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mirage-shield/mirage/internal/model"
)

// tokenPattern matches the generated dashboard token line of the starter
// config: 64 lowercase hex characters, the crypto/rand shape.
var tokenPattern = regexp.MustCompile(`dashboard_token: "([0-9a-f]{64})"`)

func TestVersionPrintsBuildAndSpecVersions(t *testing.T) {
	runCmd := capture(t)
	code, out, errOut := runCmd("version")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, exitOK, errOut)
	}
	if !strings.Contains(out, "mirage "+version) {
		t.Errorf("output %q, want the version line naming %q", out, version)
	}
	// The spec version is the handshake every decision carries; reporting
	// anything else here would be a lie about the wire contract.
	if !strings.Contains(out, "spec "+model.SpecVersion) {
		t.Errorf("output %q, want spec %s", out, model.SpecVersion)
	}
	if !strings.Contains(out, "protocol "+model.ProtocolVersion) {
		t.Errorf("output %q, want protocol %s", out, model.ProtocolVersion)
	}
	if !strings.Contains(out, "commit "+commit) {
		t.Errorf("output %q, want the commit line naming %q", out, commit)
	}
}

func TestVersionRejectsArgumentsAndFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"unexpected argument", []string{"version", "extra"}, exitUsage},
		{"unknown flag", []string{"version", "--bogus"}, exitUsage},
		{"help flag", []string{"version", "-h"}, exitOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runCmd := capture(t)
			code, _, _ := runCmd(tc.args...)
			if code != tc.want {
				t.Errorf("exit code = %d, want %d", code, tc.want)
			}
		})
	}
}

func TestInitWritesValidConfig(t *testing.T) {
	runCmd := capture(t)
	path := filepath.Join(t.TempDir(), "mirage.yaml")
	code, out, errOut := runCmd("init", "--config", path)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, exitOK, errOut)
	}
	if !strings.Contains(out, "mirage init: wrote "+path) {
		t.Errorf("stdout %q, want the written path", out)
	}
	for _, next := range []string{"mirage doctor", "mirage posture", "mirage serve"} {
		if !strings.Contains(out, next) {
			t.Errorf("stdout %q, want next step %q", out, next)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	// The init contract is a config that PASSES validation, not merely a
	// file that was written; load it exactly like every subcommand does.
	if _, err := loadConfig(path); err != nil {
		t.Fatalf("generated config does not load: %v", err)
	}
	m := tokenPattern.FindSubmatch(raw)
	if m == nil {
		t.Fatalf("generated config has no 64-hex dashboard token:\n%s", raw)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat generated config: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("generated config mode = %04o, want 0600 (it carries the one inline secret)", perm)
	}
}

func TestInitRefusesOverwrite(t *testing.T) {
	runCmd := capture(t)
	path := filepath.Join(t.TempDir(), "mirage.yaml")
	if code, _, _ := runCmd("init", "--config", path); code != exitOK {
		t.Fatalf("first init exit code = %d, want %d", code, exitOK)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	code, out, errOut := runCmd("init", "--config", path)
	if code != exitFail {
		t.Errorf("second init exit code = %d, want %d", code, exitFail)
	}
	if !strings.Contains(errOut, "already exists") {
		t.Errorf("stderr %q, want the already-exists refusal", errOut)
	}
	if !strings.Contains(errOut, "--force") {
		t.Errorf("stderr %q, want --force mentioned", errOut)
	}
	if out != "" {
		t.Errorf("stdout %q, want empty on refusal", out)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("re-read config: %v", err)
	}
	if string(before) != string(after) {
		t.Error("refused init modified the existing file")
	}
}

func TestInitForceOverwritesWithFreshToken(t *testing.T) {
	runCmd := capture(t)
	path := filepath.Join(t.TempDir(), "mirage.yaml")
	if code, _, _ := runCmd("init", "--config", path); code != exitOK {
		t.Fatalf("first init exit code = %d, want %d", code, exitOK)
	}
	first := readToken(t, path)

	code, _, errOut := runCmd("init", "--config", path, "--force")
	if code != exitOK {
		t.Fatalf("forced init exit code = %d, want %d; stderr: %s", code, exitOK, errOut)
	}
	second := readToken(t, path)
	if first == second {
		// The token must be freshly generated: a repeated token would mean
		// init is minting predictable secrets, the exact opposite of its
		// job (the collision chance for two honest 32-byte draws is
		// negligible; equality here is a bug, not bad luck).
		t.Fatalf("forced init regenerated the same token %q", first)
	}
}

// readToken extracts the dashboard token from a generated config.
func readToken(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	m := tokenPattern.FindSubmatch(raw)
	if m == nil {
		t.Fatalf("no 64-hex dashboard token in %s:\n%s", path, raw)
	}
	return string(m[1])
}
