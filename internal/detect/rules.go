package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DecoyEntry is one decoy catalog entry, keyed by its normalized path in
// Rules.DecoyPaths (spec/decoy-catalog/catalog.yaml). Leads are the trap
// paths the entry's body advertises; HoneytokenIDs name the per-session
// honeytokens the body embeds, minted when the decoy is served
// (spec/SIGNALS.md section 4.4).
type DecoyEntry struct {
	ID            string
	Leads         []string
	HoneytokenIDs []string
}

// Policy holds every threshold the engine consults. DefaultPolicy mirrors
// the policy block of spec/golden-vectors/vectors.json and the normative
// values of SIGNALS.md sections 5-7; changing either regenerates vectors.
type Policy struct {
	SessionTTLms        int64 // 30 min session expiry (SIGNALS section 7)
	UAWindowMs          int64 // 5 min trailing window for ua_rotation (section 4.7)
	EnumWindowMs        int64 // 60 s trailing window for path_enumeration (section 4.5)
	EnumThreshold       int   // >= 8 distinct unknown paths fires (section 4.5)
	UARotationThreshold int   // >= 4 distinct non-empty UAs fires (section 4.7)
	BanTTLms            int64 // 30 min ban TTL, set only on ban verdicts (section 5)

	TagScore        int // request score >= 15 -> tag (section 5.1)
	TagCumBefore    int // cumulative-before >= 25 -> tag via history (section 5.1)
	DecoyRouteScore int // request score >= 25 plus high class on a decoyable path (section 5.2)
	ThrottleScore   int // request score >= 40 -> throttle (section 5.3)
	BanScore        int // request score >= 60 with high class -> ban (section 5.4)
}

// DefaultPolicy returns the canonical thresholds. The verdict thresholds
// (TagScore..BanScore) are not part of the vectors.json policy block; they
// are fixed by SIGNALS.md section 5 and asserted by engine tests.
func DefaultPolicy() Policy {
	return Policy{
		SessionTTLms:        1_800_000,
		UAWindowMs:          300_000,
		EnumWindowMs:        60_000,
		EnumThreshold:       8,
		UARotationThreshold: 4,
		BanTTLms:            1_800_000,
		TagScore:            15,
		TagCumBefore:        25,
		DecoyRouteScore:     25,
		ThrottleScore:       40,
		BanScore:            60,
	}
}

// Rules is the immutable rule set the engine scores against: the data files
// from data/, the decoy catalog, and the site's protected routes. Build it
// with LoadRules. Hand-constructed Rules (tests) still work: New derives the
// internal lookups on the copy it retains.
type Rules struct {
	// ScannerPaths holds the raw entries of data/scanner-paths.txt. Matching
	// is trailing-slash-insensitive in both directions (SIGNALS section 3.3)
	// through the derived scannerLookup set.
	ScannerPaths []string

	// DecoyPaths maps a catalog decoy path to its entry. Keys are the
	// catalog paths verbatim; matching is exact on the normalized request
	// path (SIGNALS section 3.3).
	DecoyPaths map[string]DecoyEntry

	// AllLeads is the union of the leads of ALL catalog entries, including
	// entries never served to a session. Unknown-path counting for
	// path_enumeration excludes them: a lead is Mirage's territory
	// (HAND-COMPUTED canon decision 4).
	AllLeads map[string]bool

	// ProtectedRoutes lists routes never decoyed and never capped (I4). An
	// entry ending in "/" is a prefix, anything else matches exactly — the
	// same semantics as config.IsProtected.
	ProtectedRoutes []string

	// SuspiciousUA holds lowercased substrings from data/ua-suspicious.txt.
	SuspiciousUA []string

	// VerifiedBots holds lowercased substrings from data/ua-verified-bots.txt.
	VerifiedBots []string

	// Policy holds the scoring thresholds (DefaultPolicy unless overridden).
	Policy Policy

	// scannerLookup is the derived slash-stripped scanner set used for
	// O(1) trailing-slash-insensitive matching (SIGNALS section 3.3).
	scannerLookup map[string]bool
}

// LoadRules reads the engine's inputs:
//
//	dataDir/scanner-paths.txt     scanner path list (SIGNALS section 4.1)
//	dataDir/ua-suspicious.txt     suspicious UA substrings (section 4.6)
//	dataDir/ua-verified-bots.txt  verified-bot hints (section 2)
//	catalogPath                   decoy catalog YAML (entries: id, persona,
//	                              path, leads, honeytokens[].id)
//
// Blank lines and lines starting with "#" are skipped; list entries are
// trimmed. protectedRoutes is stored verbatim. Every error names the file it
// came from so a misconfigured deployment fails loudly at boot.
func LoadRules(dataDir, catalogPath string, protectedRoutes []string) (Rules, error) {
	scannerPaths, err := readList(filepath.Join(dataDir, "scanner-paths.txt"))
	if err != nil {
		return Rules{}, err
	}
	suspicious, err := readList(filepath.Join(dataDir, "ua-suspicious.txt"))
	if err != nil {
		return Rules{}, err
	}
	bots, err := readList(filepath.Join(dataDir, "ua-verified-bots.txt"))
	if err != nil {
		return Rules{}, err
	}
	decoys, allLeads, err := loadCatalog(catalogPath)
	if err != nil {
		return Rules{}, err
	}

	r := Rules{
		ScannerPaths:    scannerPaths,
		DecoyPaths:      decoys,
		AllLeads:        allLeads,
		ProtectedRoutes: protectedRoutes,
		SuspiciousUA:    lowerAll(suspicious),
		VerifiedBots:    lowerAll(bots),
		Policy:          DefaultPolicy(),
	}
	r.prepare()
	return r, nil
}

// prepare derives the lookup structures the engine needs. LoadRules calls
// it; New calls it again so hand-built Rules (tests, future embedders) also
// carry valid lookups. A zero Policy is defaulted so a Rules built without
// LoadRules cannot silently score with zero thresholds.
func (r *Rules) prepare() {
	if r.scannerLookup == nil {
		r.scannerLookup = make(map[string]bool, len(r.ScannerPaths))
		for _, p := range r.ScannerPaths {
			r.scannerLookup[stripTrailingSlash(p)] = true
		}
	}
	if r.DecoyPaths == nil {
		r.DecoyPaths = map[string]DecoyEntry{}
	}
	if r.AllLeads == nil {
		r.AllLeads = map[string]bool{}
	}
	if r.Policy == (Policy{}) {
		r.Policy = DefaultPolicy()
	}
}

// isScanner reports whether the normalized path matches a scanner-list
// entry. SIGNALS section 3.3: the comparison is trailing-slash-insensitive
// in both directions — the list entry "/phpmyadmin-old/" matches the request
// "/phpmyadmin-old", and the entry "/backup.tar.gz" matches the request
// "/backup.tar.gz/".
func (r Rules) isScanner(path string) bool {
	return r.scannerLookup[stripTrailingSlash(path)]
}

// isProtected reports whether the normalized path hits a protected route
// (I4): an entry ending in "/" is a prefix, anything else matches exactly.
// This mirrors config.IsProtected line for line. It is duplicated here —
// rather than importing internal/config — so the engine depends only on
// internal/model and the TypeScript worker port stays a standalone mirror.
func (r Rules) isProtected(path string) bool {
	for _, route := range r.ProtectedRoutes {
		if strings.HasSuffix(route, "/") {
			if strings.HasPrefix(path, route) {
				return true
			}
			continue
		}
		if path == route {
			return true
		}
	}
	return false
}

// decoyAt returns the catalog entry served at the normalized path, if any.
func (r Rules) decoyAt(path string) (DecoyEntry, bool) {
	entry, ok := r.DecoyPaths[path]
	return entry, ok
}

// isUnknown reports whether the path counts as an "unknown path" for
// path_enumeration (SIGNALS section 4.5): not "/", not a protected route,
// not a scanner path, not a decoy, and not a catalog lead (canon decision 4:
// unknown-path counting excludes ALL catalog lead paths, not only served
// ones).
func (r Rules) isUnknown(path string) bool {
	if path == "/" || r.isProtected(path) || r.isScanner(path) {
		return false
	}
	if _, isDecoy := r.DecoyPaths[path]; isDecoy {
		return false
	}
	return !r.AllLeads[path]
}

// isVerifiedBotUA reports whether the user agent carries a verified-bot
// hint (SIGNALS section 2): a case-insensitive substring match against
// data/ua-verified-bots.txt. Such requests are never scored and never meet
// a trap (I12).
func (r Rules) isVerifiedBotUA(ua string) bool {
	return containsAny(strings.ToLower(ua), r.VerifiedBots)
}

// isSuspiciousUA reports whether the user agent matches a suspicious
// substring (SIGNALS section 4.6), case-insensitive.
func (r Rules) isSuspiciousUA(ua string) bool {
	return containsAny(strings.ToLower(ua), r.SuspiciousUA)
}

// normalizePath implements SIGNALS section 3: strip the query string, then
// resolve "." and ".." segments left to right, popping the previous segment.
// ".." at the root pops nothing — the path is clamped at "/" — and sets
// dotEscape, because escaping above the root is scanner-style path fuzzing
// (section 4.1). Empty segments (double slashes) and "." are dropped.
func normalizePath(raw string) (path string, dotEscape bool) {
	p := raw
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	var stack []string
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			} else {
				dotEscape = true
			}
			continue
		}
		stack = append(stack, seg)
	}
	if len(stack) == 0 {
		return "/", dotEscape
	}
	return "/" + strings.Join(stack, "/"), dotEscape
}

// stripTrailingSlash removes every trailing "/" and maps an emptied result
// back to "/", the same normalization applied to both sides of scanner-list
// comparisons (SIGNALS section 3.3; mirrors tools/gen_vectors.py).
func stripTrailingSlash(p string) string {
	trimmed := strings.TrimRight(p, "/")
	if trimmed == "" {
		return "/"
	}
	return trimmed
}

// readList loads a one-entry-per-line data file. Blank lines and lines
// starting with "#" are skipped; everything else is trimmed. Errors carry
// the file path so operators see exactly which input is broken.
func readList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("detect: read %s: %w", path, err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

// catalogFile is the subset of the decoy catalog the engine consumes.
// Fields belonging to the decoy renderer (persona bodies, status codes,
// size caps, seed markers) are deliberately ignored: this loader wants only
// the graph of paths, leads and honeytoken ids.
type catalogFile struct {
	CatalogVersion string          `yaml:"catalog_version"`
	Entries        []catalogEntry  `yaml:"entries"`
	Personas       []catalogPerson `yaml:"personas"` // parsed for validation, unused by scoring
}

type catalogEntry struct {
	ID          string              `yaml:"id"`
	Persona     string              `yaml:"persona"`
	Path        string              `yaml:"path"`
	Leads       []string            `yaml:"leads"`
	Honeytokens []catalogHoneytoken `yaml:"honeytokens"`
}

type catalogHoneytoken struct {
	ID     string `yaml:"id"`
	Format string `yaml:"format"`
}

type catalogPerson struct {
	ID      string   `yaml:"id"`
	Story   string   `yaml:"story"`
	Headers []string `yaml:"headers"`
}

// loadCatalog parses the decoy catalog and returns the decoy map keyed by
// path plus the union of all lead paths. It validates just enough to fail
// closed at boot on an ambiguous catalog (duplicate paths, missing ids):
// a wrong decoy map silently corrupts every downstream decision.
func loadCatalog(path string) (map[string]DecoyEntry, map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("detect: read %s: %w", path, err)
	}
	var cf catalogFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, nil, fmt.Errorf("detect: parse %s: %w", path, err)
	}

	decoys := make(map[string]DecoyEntry, len(cf.Entries))
	allLeads := make(map[string]bool)
	for _, ent := range cf.Entries {
		if ent.ID == "" || ent.Path == "" {
			return nil, nil, fmt.Errorf("detect: %s: decoy entry with missing id or path (persona %q)", path, ent.Persona)
		}
		if _, dup := decoys[ent.Path]; dup {
			return nil, nil, fmt.Errorf("detect: %s: duplicate decoy path %q", path, ent.Path)
		}
		tokenIDs := make([]string, 0, len(ent.Honeytokens))
		for _, tok := range ent.Honeytokens {
			if tok.ID == "" {
				return nil, nil, fmt.Errorf("detect: %s: decoy %q has a honeytoken without id", path, ent.ID)
			}
			tokenIDs = append(tokenIDs, tok.ID)
		}
		decoys[ent.Path] = DecoyEntry{ID: ent.ID, Leads: ent.Leads, HoneytokenIDs: tokenIDs}
		// Canon decision 4: every catalog lead counts as known territory,
		// whether or not this entry was ever served.
		for _, lead := range ent.Leads {
			allLeads[lead] = true
		}
	}
	return decoys, allLeads, nil
}

// lowerAll lowercases a list in place for case-insensitive substring
// matching (the UA lists are matched against a lowercased UA).
func lowerAll(items []string) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = strings.ToLower(s)
	}
	return out
}

// containsAny reports whether s contains any of the substrings.
func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
