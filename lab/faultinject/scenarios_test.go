package main

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The lab's own gate: every registered scenario runs as a subtest, and the
// registry itself is audited — unique names, at least one well-formed
// invariant citation per scenario, and a README whose matrix mentions every
// registered scenario and only invariants that exist in docs/invariants.md.
// The README check keeps the documentation honest forever: a scenario added
// without a README row fails CI.

func TestAllScenarios(t *testing.T) {
	for _, sc := range registry {
		t.Run(sc.Name, func(t *testing.T) {
			sc.Run(t)
		})
	}
}

// invariantRe is the shape of an invariant citation: I plus digits.
var invariantRe = regexp.MustCompile(`^I\d+$`)

// docPath resolves a path relative to the repository root from this test
// file's compile-time location, so the gate works no matter the working
// directory go test was launched from.
func docPath(t *testing.T, elems ...string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("faultinject: cannot locate test source file")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(append([]string{root}, elems...)...)
}

func TestRegistry(t *testing.T) {
	if len(registry) == 0 {
		t.Fatal("the fault matrix is empty: the lab proves nothing")
	}

	seen := make(map[string]bool, len(registry))
	for _, sc := range registry {
		if sc.Name == "" {
			t.Error("a scenario carries no name")
			continue
		}
		if seen[sc.Name] {
			t.Errorf("duplicate scenario name %q", sc.Name)
		}
		seen[sc.Name] = true
		if sc.Desc == "" {
			t.Errorf("scenario %s carries no description", sc.Name)
		}
		if sc.Run == nil {
			t.Errorf("scenario %s has no Run function", sc.Name)
			continue
		}
		if len(sc.Invariants) == 0 {
			t.Errorf("scenario %s cites no invariants: every fault must prove its invariants", sc.Name)
		}
		for _, inv := range sc.Invariants {
			if !invariantRe.MatchString(inv) {
				t.Errorf("scenario %s cites malformed invariant %q (want the I-numbered shape)", sc.Name, inv)
			}
		}
	}

	// Every citation must name a real invariant heading in the normative
	// copy — a citation to a deleted invariant is a stale doc.
	raw, err := os.ReadFile(docPath(t, "docs", "invariants.md"))
	if err != nil {
		t.Fatalf("read invariants doc: %v", err)
	}
	known := make(map[string]bool)
	for _, line := range strings.Split(string(raw), "\n") {
		if fields := strings.Fields(strings.TrimSpace(line)); len(fields) >= 2 && fields[0] == "##" && invariantRe.MatchString(fields[1]) {
			known[fields[1]] = true
		}
	}
	for _, sc := range registry {
		for _, inv := range sc.Invariants {
			if !known[inv] {
				t.Errorf("scenario %s cites %s, which has no heading in docs/invariants.md", sc.Name, inv)
			}
		}
	}

	// The README matrix must mention every registered scenario by name, so
	// the documented fault matrix cannot drift behind the code.
	raw, err = os.ReadFile(docPath(t, "lab", "faultinject", "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	readme := string(raw)
	for _, sc := range registry {
		if !strings.Contains(readme, sc.Name) {
			t.Errorf("README.md does not mention scenario %q: add it to the fault matrix table", sc.Name)
		}
	}
}
