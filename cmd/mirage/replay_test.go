package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// replayJSON is the decoded --json shape of the replay report.
type replayJSON struct {
	OK     bool `json:"ok"`
	Total  int  `json:"total"`
	Passed int  `json:"passed"`
	Failed int  `json:"failed"`
	Cases  []struct {
		ID   string `json:"id"`
		OK   bool   `json:"ok"`
		Diff string `json:"diff"`
	} `json:"cases"`
}

func TestReplayGoldenVectorsAllPass(t *testing.T) {
	// The replay resolves the engine's data files (data/) and the default
	// catalog relative to the working directory; run from the repository
	// root, and let --vectors keep its shipped default.
	chdirRepoRoot(t)
	runCmd := capture(t)
	cfgPath := writeSiteConfig(t)

	code, out, errOut := runCmd("replay", "--config", cfgPath)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr: %s\nstdout:\n%s", code, exitOK, errOut, out)
	}
	if !strings.Contains(out, "20/20 cases passed (68 requests)") {
		t.Errorf("stdout %q, want all 20 cases and 68 requests passing", out)
	}
	if strings.Contains(out, "FAIL") {
		t.Errorf("stdout %q, want no failing cases", out)
	}
}

func TestReplayGoldenVectorsJSON(t *testing.T) {
	chdirRepoRoot(t)
	runCmd := capture(t)
	cfgPath := writeSiteConfig(t)

	code, out, _ := runCmd("replay", "--config", cfgPath, "--json")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	var rep replayJSON
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("parse JSON report: %v\nreport: %s", err, out)
	}
	if !rep.OK || rep.Total != 20 || rep.Passed != 20 || rep.Failed != 0 {
		t.Errorf("report = ok:%v total:%d passed:%d failed:%d, want ok:true 20/20/0", rep.OK, rep.Total, rep.Passed, rep.Failed)
	}
	if len(rep.Cases) != 20 {
		t.Errorf("cases = %d entries, want 20", len(rep.Cases))
	}
}

func TestReplayCorruptedExpectationFails(t *testing.T) {
	chdirRepoRoot(t)
	runCmd := capture(t)
	cfgPath := writeSiteConfig(t)

	// Corrupt one expected verdict in a copy of the shipped vectors: the
	// replay must fail, name the case, and point at the first differing
	// field. The corruption targets a case's LAST expectation, so the
	// harness's terminal-ban shape precondition stays satisfied and the
	// divergence is a pure decision mismatch. The copy is written through
	// the same structs the harness decodes, so the corruption is exactly
	// one expectation.
	raw, err := os.ReadFile(repoPath(t, "spec", "golden-vectors", "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	last := len(vf.Cases[0].Expected) - 1
	vf.Cases[0].Expected[last].Verdict = "ban"
	bad := filepath.Join(t.TempDir(), "vectors-bad.json")
	raw, err = json.Marshal(vf)
	if err != nil {
		t.Fatalf("re-encode vectors: %v", err)
	}
	if err := os.WriteFile(bad, raw, 0o600); err != nil {
		t.Fatalf("write corrupted vectors: %v", err)
	}

	t.Run("human output", func(t *testing.T) {
		code, out, _ := runCmd("replay", "--config", cfgPath, "--vectors", bad)
		if code != exitFail {
			t.Fatalf("exit code = %d, want %d on any mismatch", code, exitFail)
		}
		if !strings.Contains(out, "FAIL v01-clean-browsing") {
			t.Errorf("stdout %q, want the failing case id", out)
		}
		if !strings.Contains(out, fmt.Sprintf("request %d: verdict: want ban, got observe", last+1)) {
			t.Errorf("stdout %q, want the first differing field of the diverging request", out)
		}
		if !strings.Contains(out, "1 failed") {
			t.Errorf("stdout %q, want the failed count in the summary", out)
		}
	})

	t.Run("json output", func(t *testing.T) {
		code, out, _ := runCmd("replay", "--config", cfgPath, "--vectors", bad, "--json")
		if code != exitFail {
			t.Fatalf("exit code = %d, want %d", code, exitFail)
		}
		var rep replayJSON
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("parse JSON report: %v\nreport: %s", err, out)
		}
		if rep.OK || rep.Failed != 1 || rep.Passed != 19 {
			t.Errorf("report = ok:%v passed:%d failed:%d, want ok:false 19/1", rep.OK, rep.Passed, rep.Failed)
		}
		if len(rep.Cases) == 0 || rep.Cases[0].ID != "v01-clean-browsing" || rep.Cases[0].OK {
			t.Errorf("cases[0] = %+v, want v01-clean-browsing failing", rep.Cases)
		}
		if !strings.Contains(rep.Cases[0].Diff, "verdict") {
			t.Errorf("diff %q, want it to name the verdict field", rep.Cases[0].Diff)
		}
	})
}

func TestReplayVersionHandshake(t *testing.T) {
	chdirRepoRoot(t)
	runCmd := capture(t)
	cfgPath := writeSiteConfig(t)

	vectors := filepath.Join(t.TempDir(), "vectors-old-spec.json")
	if err := os.WriteFile(vectors, []byte(`{"spec_version":"0.0.1","protocol_version":"1","cases":[]}`), 0o600); err != nil {
		t.Fatalf("write vectors: %v", err)
	}
	code, _, errOut := runCmd("replay", "--config", cfgPath, "--vectors", vectors)
	if code != exitFail {
		t.Fatalf("exit code = %d, want %d", code, exitFail)
	}
	if !strings.Contains(errOut, "regenerate the vectors or update the engine") {
		t.Errorf("stderr %q, want the handshake error", errOut)
	}
}

func TestReplayMissingVectorsFile(t *testing.T) {
	chdirRepoRoot(t)
	runCmd := capture(t)
	cfgPath := writeSiteConfig(t)
	missing := filepath.Join(t.TempDir(), "absent.json")

	code, out, errOut := runCmd("replay", "--config", cfgPath, "--vectors", missing)
	if code != exitFail {
		t.Fatalf("exit code = %d, want %d", code, exitFail)
	}
	if out != "" {
		t.Errorf("stdout %q, want empty (the error goes to stderr)", out)
	}
	if !strings.Contains(errOut, "read vectors") {
		t.Errorf("stderr %q, want the read error", errOut)
	}
}

func TestReplayRequiresConfigFlag(t *testing.T) {
	runCmd := capture(t)
	code, _, errOut := runCmd("replay")
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut, "--config is required") {
		t.Errorf("stderr %q, want the missing-flag message", errOut)
	}
}
