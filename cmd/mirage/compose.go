package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mirage-shield/mirage/internal/config"
	"github.com/mirage-shield/mirage/internal/connectors"
	"github.com/mirage-shield/mirage/internal/decoy"
	"github.com/mirage-shield/mirage/internal/detect"
	"github.com/mirage-shield/mirage/internal/enforce"
	"github.com/mirage-shield/mirage/internal/events"
	"github.com/mirage-shield/mirage/internal/store"
)

// dataDir is where the engine's rule lists live, resolved relative to the
// working directory — the same convention as the default decoy catalog
// path in mirage.example.yaml. Operators run mirage from their site root,
// which holds data/ and spec/.
const dataDir = "data"

// defaultVectorsPath is the shipped golden-vector set, used when `mirage
// replay` gets no --vectors flag.
const defaultVectorsPath = "spec/golden-vectors/vectors.json"

// loadConfig loads and validates the site configuration. Every subcommand
// goes through here so the fail-closed-at-boot behavior (strict decoding,
// every violation listed) is identical across the CLI.
func loadConfig(path string) (*config.Config, error) {
	return config.Load(path)
}

// loadEngineRules loads the detect engine's inputs for a site: the data
// lists from dataDir and the decoy graph from the site's catalog. Errors
// name the offending file, so doctor and serve can surface them verbatim.
func loadEngineRules(cfg *config.Config) (detect.Rules, error) {
	return detect.LoadRules(dataDir, cfg.Decoys.CatalogPath, cfg.ProtectedRoutes)
}

// buildConnectors instantiates every connector the configuration lists.
// Secrets are resolved from their *_env variables HERE, at boot — a missing
// variable is a boot-time failure (fail closed), never a connector that
// silently no-ops mid-incident. Errors come from the config package and
// name the variable, never its value (I11).
//
// The "is it configured" tests mirror internal/config's anySet semantics:
// a block with any key set counts as configured, and Validate has already
// required its siblings by the time a config reaches this function.
func buildConnectors(cfg *config.Config) ([]connectors.Connector, error) {
	var cs []connectors.Connector
	if csCfg := cfg.Connectors.CrowdSec; csCfg.LAPIURL != "" || csCfg.APIKeyEnv != "" {
		key, err := cfg.CrowdSecKey()
		if err != nil {
			return nil, err
		}
		cs = append(cs, connectors.NewCrowdSec(csCfg.LAPIURL, key, nil))
	}
	if cfCfg := cfg.Connectors.Cloudflare; cfCfg.AccountID != "" || cfCfg.ZoneID != "" || cfCfg.APITokenEnv != "" {
		token, err := cfg.CloudflareToken()
		if err != nil {
			return nil, err
		}
		// Empty apiBase selects the pinned production API; tests and
		// private installs would carry their own base URL in config.
		cs = append(cs, connectors.NewCloudflare("", cfCfg.ZoneID, token))
	}
	if whCfg := cfg.Connectors.Webhook; whCfg.URL != "" || whCfg.SecretEnv != "" {
		secret, err := cfg.WebhookSecret()
		if err != nil {
			return nil, err
		}
		cs = append(cs, connectors.NewWebhook(whCfg.URL, []byte(secret)))
	}
	if cfg.Connectors.Denyfile.Path != "" {
		cs = append(cs, connectors.NewDenyFile(cfg.Connectors.Denyfile.Path))
	}
	return cs, nil
}

// connectorNames lists the configured connector names, in construction
// order, for reports that must never leak configuration detail (posture).
func connectorNames(cfg *config.Config) []string {
	var names []string
	if c := cfg.Connectors.CrowdSec; c.LAPIURL != "" || c.APIKeyEnv != "" {
		names = append(names, "crowdsec")
	}
	if c := cfg.Connectors.Cloudflare; c.AccountID != "" || c.ZoneID != "" || c.APITokenEnv != "" {
		names = append(names, "cloudflare")
	}
	if c := cfg.Connectors.Webhook; c.URL != "" || c.SecretEnv != "" {
		names = append(names, "webhook")
	}
	if cfg.Connectors.Denyfile.Path != "" {
		names = append(names, "denyfile")
	}
	return names
}

// newGatekeeper arms the enforcement gatekeeper with the site's budgets and
// owner ranges. A gatekeeper exists only in protect mode (I9) — every other
// mode composes the service without one, and service.New enforces exactly
// that shape.
func newGatekeeper(cfg *config.Config) *enforce.Gatekeeper {
	b := cfg.Enforcement.Budgets
	return enforce.NewGatekeeper(enforce.Budgets{
		MaxBansPerMinute:  b.MaxBansPerMinute,
		MaxConcurrentBans: b.MaxConcurrentBans,
		MaxSharePct:       b.MaxSharePct,
	}, cfg.OwnerRanges())
}

// openServeStore opens the durable store for serve. The config schema
// offers SQLite only — there is deliberately no store-kind key, because an
// in-memory store loses every ban and event on restart and exists solely
// as a library facility for tests and the replay harness. The parent
// directory of store.path is created so a fresh install can boot without a
// manual mkdir; the database file itself is created by OpenSQLite.
func openServeStore(ctx context.Context, cfg *config.Config) (*store.SQLiteStore, error) {
	if dir := filepath.Dir(cfg.Store.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create store directory %s: %w", dir, err)
		}
	}
	return store.OpenSQLite(ctx, cfg.Store.Path)
}

// newQueue builds the bounded event queue at the site's configured
// capacity. The queue constructor clamps to the protocol bounds on its own
// (events.NewQueue), the same bounds posture reports.
func newQueue(cfg *config.Config) *events.Queue {
	return events.NewQueue(cfg.Events.QueueCapacity)
}

// loadCatalog loads the decoy catalog for rendering. It is needed in
// tripwires and protect (service.New rejects a nil catalog there); in look
// mode loading it anyway keeps doctor's catalog check meaningful for every
// mode.
func loadCatalog(cfg *config.Config) (*decoy.Catalog, error) {
	return decoy.Load(cfg.Decoys.CatalogPath)
}
