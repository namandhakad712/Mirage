package decoy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Cross-engine render parity: spec/golden-vectors/renders.json pins the
// exact rendered body of every catalog entry for two fixed session keys.
// The Go renderer and the TypeScript worker renderer (packages/mirage-worker
// src/render.ts) must both reproduce these bytes byte-for-byte. CI fails on
// any divergence — the shared-catalog drift guard from the design doc
// (section 26, "several implementations, one spec").
//
// Regen: REGEN=1 go test ./internal/decoy/ -run TestRegenRenderGolden
// then re-run the TypeScript suite.

var goldenSessions = []string{
	"fec52565aa0cf18f57d7cf5b3ac72850", // sha256("203.0.113.7")[:32]
	"8959edf6884f2c2e223a9319e83a6982", // sha256("198.51.100.5")[:32]
}

const rendersPath = "../../spec/golden-vectors/renders.json"

type renderGoldenFile struct {
	SpecVersion         string                       `json:"spec_version"`
	DecoyCatalogVersion string                       `json:"decoy_catalog_version"`
	Sessions            []string                     `json:"sessions"`
	Entries             map[string]map[string]string `json:"entries"` // entry id -> session key -> body
}

func TestRenderGoldenVectors(t *testing.T) {
	c, _ := loadReal(t)
	raw, err := os.ReadFile(rendersPath)
	if err != nil {
		t.Fatalf("read renders.json: %v (run REGEN=1 to generate)", err)
	}
	var g renderGoldenFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("parse renders.json: %v", err)
	}
	if g.SpecVersion != "1.1.0" {
		t.Fatalf("renders.json spec_version = %q, want 1.1.0", g.SpecVersion)
	}
	if len(g.Sessions) != len(goldenSessions) {
		t.Fatalf("sessions = %v, want %v", g.Sessions, goldenSessions)
	}
	for _, entry := range c.Entries {
		bodies, ok := g.Entries[entry.ID]
		if !ok {
			t.Errorf("entry %q missing from renders.json", entry.ID)
			continue
		}
		for _, skey := range goldenSessions {
			want, ok := bodies[skey]
			if !ok {
				t.Errorf("entry %q session %s missing from renders.json", entry.ID, skey)
				continue
			}
			got, err := c.Render(entry, skey)
			if err != nil {
				t.Errorf("entry %q render: %v", entry.ID, err)
				continue
			}
			if string(got.Body) != want {
				t.Errorf("entry %q session %s: render drift\n got: %q\nwant: %q",
					entry.ID, skey, string(got.Body), want)
			}
			// The noindex invariant rides along on every golden body.
			foundNoindex := false
			for _, h := range got.Headers {
				if h == "X-Robots-Tag: noindex, nofollow, noarchive" {
					foundNoindex = true
				}
			}
			if !foundNoindex {
				t.Errorf("entry %q: noindex header missing", entry.ID)
			}
		}
	}
	// Both engines mint the same honeytoken: spot-check the golden v05
	// token inside the rendered env body (cross-anchor with vectors.json;
	// v05's attacker is 203.0.113.10 -> session 631f08140b24b7274d12df3c37a1a80c).
	env, ok := c.ByPath("/.env")
	if !ok {
		t.Fatal("env entry missing")
	}
	r, err := c.Render(env, "631f08140b24b7274d12df3c37a1a80c")
	if err != nil {
		t.Fatalf("render env: %v", err)
	}
	if !strings.Contains(string(r.Body), "mrg_live_63e36e2d68663c27f6841a68") {
		t.Errorf("env body does not carry the golden v05 honeytoken")
	}
}

func TestRegenRenderGolden(t *testing.T) {
	if os.Getenv("REGEN") != "1" {
		t.Skip("set REGEN=1 to regenerate renders.json")
	}
	c, _ := loadReal(t)
	g := renderGoldenFile{
		SpecVersion:         "1.1.0",
		DecoyCatalogVersion: c.CatalogVersion,
		Sessions:            goldenSessions,
		Entries:             map[string]map[string]string{},
	}
	for _, entry := range c.Entries {
		g.Entries[entry.ID] = map[string]string{}
		for _, skey := range goldenSessions {
			r, err := c.Render(entry, skey)
			if err != nil {
				t.Fatalf("entry %q render: %v", entry.ID, err)
			}
			g.Entries[entry.ID][skey] = string(r.Body)
		}
	}
	out, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Clean(rendersPath), append(out, '\n'), 0o644); err != nil {
		t.Fatalf("write renders.json: %v", err)
	}
	t.Logf("regenerated %s", rendersPath)
}
