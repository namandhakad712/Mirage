// Package decoy implements the deception engine's data layer: loading the
// decoy catalog (spec/DECOY-CATALOG.md), validating it against the safety
// invariants (I8 inert, I12 no pollution, I13 no misinformation, I14 no
// third-party harm) and rendering deterministic per-session responses.
//
// The catalog is data, not code — it is shared verbatim with the TypeScript
// worker — so everything here reasons about bytes, never behaviour. Loading
// is strict: unknown YAML fields and semantic violations are rejected at
// boot (fail closed at load time) because a misparsed decoy must never
// reach the wire; at request time the engine fails open instead (I1).
package decoy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Semantic bounds for catalog entries, enforced by Load and mirrored by the
// worker's validator. Decoys answer with success or error statuses in
// 200..599; size caps outside these bounds would either truncate every
// body or break the bounded-footprint budget (I12).
const (
	minStatus = 200
	maxStatus = 599

	minSizeCapBytes = 64
	maxSizeCapBytes = 65536

	// wellKnownPrefix is reserved for site-wide metadata (ACME challenges,
	// security.txt). A decoy lead must never claim it (I4,
	// DECOY-CATALOG.md section 3 rule 1).
	wellKnownPrefix = "/.well-known/"
)

// knownHoneytokenFormats lists the honeytoken formats this engine can mint
// (data/token-formats.md). Every format lives in the mrg_ namespace that no
// real provider issues, so a decoy credential can never validate against a
// real service (I14). Admitting an unknown format here would let a catalog
// promise a credential shape a real service might accept.
var knownHoneytokenFormats = map[string]bool{
	"token_alnum_24": true,
}

// Catalog is the parsed decoy catalog (spec/decoy-catalog/catalog.yaml).
// A Catalog is immutable after Load; Render and the accessors are safe for
// concurrent use.
type Catalog struct {
	CatalogVersion string    `yaml:"catalog_version"`
	Personas       []Persona `yaml:"personas"`
	Entries        []Entry   `yaml:"entries"`
}

// Persona is one consistent fake identity shared by a group of entries:
// stack, headers and file layout all agree, because inconsistency is how an
// attacker spots a trap (DECOY-CATALOG.md section 2).
type Persona struct {
	ID      string   `yaml:"id"`
	Story   string   `yaml:"story"`
	Headers []string `yaml:"headers"`
}

// Entry is one decoy response template, mounted at Path.
type Entry struct {
	ID           string       `yaml:"id"`
	Persona      string       `yaml:"persona"`
	Path         string       `yaml:"path"`
	Status       int          `yaml:"status"`
	ContentType  string       `yaml:"content_type"`
	SizeCapBytes int          `yaml:"size_cap_bytes"`
	Body         string       `yaml:"body"`
	Leads        []string     `yaml:"leads"`
	Honeytokens  []Honeytoken `yaml:"honeytokens"`
}

// Honeytoken names one inert credential minted per session; the value is
// derived from (session key, entry id, token id) at render time.
type Honeytoken struct {
	ID     string `yaml:"id"`
	Format string `yaml:"format"`
}

// Load reads, strictly decodes and structurally validates the catalog at
// path. Unknown YAML fields are errors (a typo'd key must not silently
// produce a half-configured decoy), and every semantic violation is
// reported, joined with field context, so one load pass reveals the whole
// catalog's problems. The safety rules (I8/I12/I13/I14) live in Validate
// because they also apply to hand-built catalogs in tests.
func Load(path string) (*Catalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("decoy catalog %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var c Catalog
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decoy catalog %s: decode: %w", path, err)
	}
	if err := validateStructure(&c); err != nil {
		return nil, fmt.Errorf("decoy catalog %s: %w", path, err)
	}
	return &c, nil
}

// validateStructure enforces the structural rules of DECOY-CATALOG.md
// section 1: identity, references and ranges. It returns every violation
// joined, each carrying enough context (index, id, field) to locate the
// offending line in the YAML file.
func validateStructure(c *Catalog) error {
	var errs []error

	if strings.TrimSpace(c.CatalogVersion) == "" {
		errs = append(errs, fmt.Errorf("catalog_version: missing (v1 ships \"1\")"))
	}

	personas := make(map[string]bool, len(c.Personas))
	for i, p := range c.Personas {
		if p.ID == "" {
			errs = append(errs, fmt.Errorf("personas[%d]: empty id", i))
			continue
		}
		if personas[p.ID] {
			errs = append(errs, fmt.Errorf("personas[%d] (%q): duplicate persona id", i, p.ID))
			continue
		}
		personas[p.ID] = true
		// Header lines are copied verbatim onto responses; one without a
		// colon would corrupt the HTTP header block.
		for _, h := range p.Headers {
			if !strings.Contains(h, ":") {
				errs = append(errs, fmt.Errorf("persona %q: header %q is not a \"Name: value\" line", p.ID, h))
			}
		}
	}

	// Pass 1 collects every entry path before lead checks run: a lead may
	// collide with a path declared later in the file, so collision checks
	// must see the full path set.
	paths := make(map[string]string, len(c.Entries))
	for _, e := range c.Entries {
		if owner, dup := paths[e.Path]; dup {
			errs = append(errs, fmt.Errorf("entry %q: path %q already used by entry %q", e.ID, e.Path, owner))
			continue
		}
		paths[e.Path] = e.ID
	}

	// Pass 2 checks each entry and its leads against the full path set.
	entryIDs := make(map[string]bool, len(c.Entries))
	for i, e := range c.Entries {
		ctx := fmt.Sprintf("entries[%d]", i)
		if e.ID != "" {
			ctx = fmt.Sprintf("entries[%d] (%q)", i, e.ID)
		}
		if e.ID == "" {
			errs = append(errs, fmt.Errorf("%s: empty id", ctx))
		} else if entryIDs[e.ID] {
			errs = append(errs, fmt.Errorf("%s: duplicate entry id", ctx))
		} else {
			entryIDs[e.ID] = true
		}

		if !personas[e.Persona] {
			errs = append(errs, fmt.Errorf("%s: unknown persona %q", ctx, e.Persona))
		}
		if !strings.HasPrefix(e.Path, "/") {
			errs = append(errs, fmt.Errorf("%s: path %q must start with \"/\"", ctx, e.Path))
		}
		if strings.Contains(e.Path, "?") {
			errs = append(errs, fmt.Errorf("%s: path %q must not carry a query string", ctx, e.Path))
		}
		if e.Status < minStatus || e.Status > maxStatus {
			errs = append(errs, fmt.Errorf("%s: status %d outside %d..%d", ctx, e.Status, minStatus, maxStatus))
		}
		if e.SizeCapBytes < minSizeCapBytes || e.SizeCapBytes > maxSizeCapBytes {
			errs = append(errs, fmt.Errorf("%s: size_cap_bytes %d outside %d..%d", ctx, e.SizeCapBytes, minSizeCapBytes, maxSizeCapBytes))
		}
		if e.ContentType == "" {
			errs = append(errs, fmt.Errorf("%s: empty content_type", ctx))
		}

		for j, lead := range e.Leads {
			if !strings.HasPrefix(lead, "/") {
				errs = append(errs, fmt.Errorf("%s: leads[%d] %q must be an absolute path", ctx, j, lead))
				continue
			}
			if strings.HasPrefix(lead, wellKnownPrefix) {
				errs = append(errs, fmt.Errorf("%s: leads[%d] %q must not claim the reserved namespace %s (I4)", ctx, j, lead, wellKnownPrefix))
			}
			if owner, clash := paths[lead]; clash {
				errs = append(errs, fmt.Errorf("%s: leads[%d] %q collides with the path of entry %q", ctx, j, lead, owner))
			}
		}

		tokenIDs := make(map[string]bool, len(e.Honeytokens))
		for j, h := range e.Honeytokens {
			if h.ID == "" {
				errs = append(errs, fmt.Errorf("%s: honeytokens[%d]: empty id", ctx, j))
				continue
			}
			if tokenIDs[h.ID] {
				// Two tokens with one id would mint identical values and
				// make leak attribution ambiguous.
				errs = append(errs, fmt.Errorf("%s: honeytokens[%d]: duplicate id %q", ctx, j, h.ID))
				continue
			}
			tokenIDs[h.ID] = true
			if !knownHoneytokenFormats[h.Format] {
				errs = append(errs, fmt.Errorf("%s: honeytoken %q has unknown format %q", ctx, h.ID, h.Format))
			}
		}
	}

	return errors.Join(errs...)
}

// ByPath returns the entry mounted at path. Catalogs are small (v1 ships
// six entries), so a linear scan beats maintaining a map copy that could
// drift from the slice.
func (c *Catalog) ByPath(path string) (Entry, bool) {
	for _, e := range c.Entries {
		if e.Path == path {
			return e, true
		}
	}
	return Entry{}, false
}

// Leads returns a copy of entry's lead paths — the paths that exist only
// inside that decoy's story. The copy protects the catalog from callers
// mutating the returned slice.
func (c *Catalog) Leads(entry Entry) []string {
	leads := make([]string, len(entry.Leads))
	copy(leads, entry.Leads)
	return leads
}

// AllLeads returns every lead path in the catalog, deduplicated and in
// catalog order, so callers can register lure routes once per path.
func (c *Catalog) AllLeads() []string {
	var out []string
	seen := make(map[string]bool)
	for _, e := range c.Entries {
		for _, l := range e.Leads {
			if seen[l] {
				continue
			}
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

// personaByID resolves a persona reference; ok is false for catalogs built
// by hand without the referenced persona (Render then serves the entry with
// the engine's own headers only, so a decoy still renders).
func (c *Catalog) personaByID(id string) (Persona, bool) {
	for _, p := range c.Personas {
		if p.ID == id {
			return p, true
		}
	}
	return Persona{}, false
}
