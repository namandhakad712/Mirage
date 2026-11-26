package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// capture swaps the command outputs for buffers and returns a function
// that runs args through run() and hands back the exit code plus both
// outputs. The suite never runs in parallel (no t.Parallel anywhere), so
// the package-level writer swap is safe.
func capture(t *testing.T) func(args ...string) (int, string, string) {
	t.Helper()
	oldOut, oldErr := stdout, stderr
	var out, err bytes.Buffer
	stdout, stderr = &out, &err
	t.Cleanup(func() { stdout, stderr = oldOut, oldErr })
	return func(args ...string) (int, string, string) {
		out.Reset()
		err.Reset()
		code := run(args)
		return code, out.String(), err.String()
	}
}

// repoPath resolves a path relative to the repository root from this test
// file's compile-time location, so tests work no matter the directory go
// test was launched from (the same approach as the internal suites).
func repoPath(t *testing.T, elems ...string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(append([]string{root}, elems...)...)
}

// chdirRepoRoot moves the test process to the repository root. The CLI
// resolves its engine inputs (data/ and the default catalog path) relative
// to the working directory, exactly as an operator's site root would, and
// go test starts in cmd/mirage.
func chdirRepoRoot(t *testing.T) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(repoPath(t)); err != nil {
		t.Fatalf("chdir repo root: %v", err)
	}
	t.Cleanup(func() { os.Chdir(wd) })
}

// writeSiteConfig writes a valid minimal site configuration using the
// repository's canon catalog, and returns its path. extra lines are
// appended verbatim so each test can add blocks (mode, connectors,
// budgets) the way a site file would.
func writeSiteConfig(t *testing.T, extra ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("site: https://example.test\n")
	b.WriteString("dashboard_token: test-dashboard-token-0123456789abcdef\n")
	for _, line := range extra {
		b.WriteString(line)
		b.WriteString("\n")
	}
	path := filepath.Join(t.TempDir(), "mirage.yaml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestNoArgsPrintsUsageToStderr(t *testing.T) {
	runCmd := capture(t)
	code, out, errOut := runCmd()
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d (usage)", code, exitUsage)
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty (usage goes to stderr)", out)
	}
	if !strings.Contains(errOut, "usage: mirage <subcommand>") {
		t.Errorf("stderr = %q, want the usage header", errOut)
	}
}

func TestUnknownSubcommandIsUsageError(t *testing.T) {
	runCmd := capture(t)
	code, out, errOut := runCmd("bogus")
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty", out)
	}
	if !strings.Contains(errOut, `unknown subcommand "bogus"`) {
		t.Errorf("stderr = %q, want the unknown subcommand named", errOut)
	}
	if !strings.Contains(errOut, "usage: mirage <subcommand>") {
		t.Errorf("stderr = %q, want usage printed after the error", errOut)
	}
}

func TestHelpVariantsPrintUsageToStdout(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		t.Run(arg, func(t *testing.T) {
			runCmd := capture(t)
			code, out, errOut := runCmd(arg)
			if code != exitOK {
				t.Errorf("exit code = %d, want %d", code, exitOK)
			}
			if !strings.Contains(out, "usage: mirage <subcommand>") {
				t.Errorf("stdout = %q, want usage", out)
			}
			if errOut != "" {
				t.Errorf("stderr = %q, want empty", errOut)
			}
		})
	}
}
