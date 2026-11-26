// Package config loads and validates Mirage's YAML site configuration.
//
// Mirage fails open at request time (I1) but fails closed at boot time: a
// config that cannot be strictly decoded and fully validated is rejected
// with every violation listed, never silently repaired or guessed.
//
// Two invariants shape the schema:
//
//   - I9 (observe by default): enforcement is opt-in and only possible in
//     mode "protect"; Validate rejects enforcement.enabled anywhere else,
//     and EnforcementAllowed additionally honours the kill switch.
//   - I11 (least privilege): no connector credential may live in the file.
//     Connector structs carry only *_env fields naming environment
//     variables; values are resolved at call time (CrowdSecKey,
//     CloudflareToken, WebhookSecret), never stored on the Config. The
//     dashboard token is the one secret carried inline and must go through
//     Redacted before any log or debug dump.
package config

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/mirage-shield/mirage/internal/model"
)

// Operating modes. Enforcement (bans, throttling) exists only in
// ModeProtect (I9); the other modes observe and record.
const (
	ModeLook      = "look"
	ModeTripwires = "tripwires"
	ModeProtect   = "protect"
)

// Defaults applied by Default and by Load for zero values, and the bounds
// enforced by Validate.
const (
	defaultListen                  = "127.0.0.1:8080"
	defaultStorePath               = "mirage.db"
	defaultRetentionDays           = 30
	defaultQueueCapacity           = 10000
	defaultDecoyCatalogPath        = "spec/decoy-catalog/catalog.yaml"
	defaultBanTTLms          int64 = 1_800_000
	defaultMaxBansPerMin           = 10
	defaultMaxConcurrentBans       = 100
	defaultMaxSharePct             = 5

	minRetentionDays = 1
	maxRetentionDays = 3650
	minQueueCapacity = 100
	maxQueueCapacity = 1_000_000
	minSharePct      = 1
	maxSharePct      = 100
)

// defaultProtectedRoutes is the canon protected-route list (spec/SIGNALS.md
// section 2, I4): paths a default install must never decoy or cap. Entries
// ending in "/" are prefixes (IsProtected).
var defaultProtectedRoutes = []string{"/wp-login.php", "/wp-admin/", "/checkout", "/cart", "/api/"}

// Config is a decoded site configuration. Load returns a Config only after
// strict decoding, defaulting and validation; hand-constructed values must
// be passed through Validate before use.
type Config struct {
	// Mode selects the operating mode: "look" (observe only, default),
	// "tripwires" (observe plus decoys) or "protect" (enforcement possible).
	Mode string `yaml:"mode"`

	// Site is the site name or origin URL, used in dashboards and reports.
	Site string `yaml:"site"`

	// Listen is the core API/dashboard address. Loopback by default; the
	// dashboard requires a token even on loopback (DashboardToken).
	Listen string `yaml:"listen"`

	// TrustedProxyCIDRs lists proxy CIDRs whose X-Forwarded-For may be
	// trusted when walking the chain (I6). Parsed into TrustedProxies by
	// a successful Validate.
	TrustedProxyCIDRs []string `yaml:"trusted_proxies"`

	// DashboardToken guards the dashboard. REQUIRED: loopback access
	// without a token is rejected by design (auth itself lives in
	// internal/service; config only carries the token). Never log this
	// value — hand the Config to Redacted first (I11).
	DashboardToken string `yaml:"dashboard_token"`

	// OwnerIPCIDRs lists owner and CDN ranges that are never scored (I6).
	// Parsed into OwnerRanges by a successful Validate.
	OwnerIPCIDRs []string `yaml:"owner_ips"`

	// ProtectedRoutes lists routes never decoyed or throttle-capped (I4).
	// Absent means the canon default list; an explicitly empty list means
	// no protected routes. A route ending in "/" is a prefix, anything
	// else matches exactly (IsProtected).
	ProtectedRoutes []string `yaml:"protected_routes"`

	Store       StoreConfig       `yaml:"store"`
	Events      EventsConfig      `yaml:"events"`
	Decoys      DecoysConfig      `yaml:"decoys"`
	Enforcement EnforcementConfig `yaml:"enforcement"`
	Connectors  ConnectorsConfig  `yaml:"connectors"`

	// Parsed forms of TrustedProxyCIDRs and OwnerIPCIDRs, committed by a
	// successful Validate so accessors never expose half-validated state.
	trustedProxies []netip.Prefix
	ownerRanges    []netip.Prefix
}

// StoreConfig controls the event store.
type StoreConfig struct {
	// Path is the store file location.
	Path string `yaml:"path"`
	// RetentionDays bounds how long events are kept (1..3650).
	RetentionDays int `yaml:"retention_days"`
	// HashIPs salts-and-hashes stored IPs when true. Default true; an
	// explicit false survives loading because decoding happens on top of
	// Default.
	HashIPs bool `yaml:"hash_ips"`
}

// EventsConfig bounds the asynchronous event queue so emission can never
// block the hot path (I3).
type EventsConfig struct {
	// QueueCapacity is the bounded queue size (100..1000000).
	QueueCapacity int `yaml:"queue_capacity"`
}

// DecoysConfig controls decoy serving.
type DecoysConfig struct {
	// CatalogPath locates the decoy catalog YAML.
	CatalogPath string `yaml:"catalog_path"`
	// Enabled turns decoy serving on. Default true; an explicit false
	// survives loading because decoding happens on top of Default.
	Enabled bool `yaml:"enabled"`
}

// EnforcementConfig is the opt-in enforcement block (I9). Enabled may only
// be true in ModeProtect; KillSwitch drops the whole system to observe.
type EnforcementConfig struct {
	Enabled    bool          `yaml:"enabled"`
	KillSwitch bool          `yaml:"kill_switch"`
	BanTTLms   int64         `yaml:"ban_ttl_ms"`
	Budgets    BudgetsConfig `yaml:"budgets"`
}

// BudgetsConfig caps enforcement so Mirage can never ban its way through a
// site's legitimate traffic (I5, I15).
type BudgetsConfig struct {
	MaxBansPerMinute  int `yaml:"max_bans_per_minute"`
	MaxConcurrentBans int `yaml:"max_concurrent_bans"`
	// MaxSharePct caps the share of sessions that may be banned (1..100).
	MaxSharePct int `yaml:"max_share_pct"`
}

// ConnectorsConfig groups the optional outbound integrations. A connector
// with every field empty counts as not configured.
//
// I11: none of these structs carries an inline credential — there is
// deliberately no api_key, api_token or secret field, only the *_env
// variants naming environment variables. Values are resolved at call time
// (CrowdSecKey, CloudflareToken, WebhookSecret) and never stored. Do not
// add inline secret fields; a secret grep gate enforces this repo-wide.
type ConnectorsConfig struct {
	CrowdSec   CrowdSecConfig   `yaml:"crowdsec"`
	Cloudflare CloudflareConfig `yaml:"cloudflare"`
	Webhook    WebhookConfig    `yaml:"webhook"`
	Denyfile   DenyfileConfig   `yaml:"denyfile"`
}

// CrowdSecConfig connects Mirage to a local CrowdSec LAPI. The machine
// key never appears here; only the name of the variable holding it.
type CrowdSecConfig struct {
	LAPIURL   string `yaml:"lapi_url"`
	APIKeyEnv string `yaml:"api_key_env"`
}

// CloudflareConfig pushes bans as Cloudflare firewall rules. The API token
// never appears here; only the name of the variable holding it.
type CloudflareConfig struct {
	AccountID   string `yaml:"account_id"`
	ZoneID      string `yaml:"zone_id"`
	APITokenEnv string `yaml:"api_token_env"`
}

// WebhookConfig receives enforcement notifications. The signing secret
// never appears here; only the name of the variable holding it.
type WebhookConfig struct {
	URL       string `yaml:"url"`
	SecretEnv string `yaml:"secret_env"`
}

// DenyfileConfig writes bans to a plain deny file (e.g. for nginx). Single
// field, nothing to resolve from the environment.
type DenyfileConfig struct {
	Path string `yaml:"path"`
}

// anySet reports whether any field is configured; an all-empty connector
// block is treated as absent and skipped by validation.
func (cs CrowdSecConfig) anySet() bool {
	return cs.LAPIURL != "" || cs.APIKeyEnv != ""
}

func (cf CloudflareConfig) anySet() bool {
	return cf.AccountID != "" || cf.ZoneID != "" || cf.APITokenEnv != ""
}

func (wh WebhookConfig) anySet() bool {
	return wh.URL != "" || wh.SecretEnv != ""
}

// Default returns a Config with every default applied. It is the base Load
// decodes onto (absent keys inherit defaults while explicit values,
// including explicit false booleans, win) and a template for starter files.
// Default is not valid as-is: DashboardToken is empty because no default
// secret exists, and Validate rejects it.
func Default() *Config {
	return &Config{
		Mode:            ModeLook,
		Listen:          defaultListen,
		ProtectedRoutes: slices.Clone(defaultProtectedRoutes),
		Store: StoreConfig{
			Path:          defaultStorePath,
			RetentionDays: defaultRetentionDays,
			HashIPs:       true,
		},
		Events: EventsConfig{QueueCapacity: defaultQueueCapacity},
		Decoys: DecoysConfig{CatalogPath: defaultDecoyCatalogPath, Enabled: true},
		Enforcement: EnforcementConfig{
			BanTTLms: defaultBanTTLms,
			Budgets: BudgetsConfig{
				MaxBansPerMinute:  defaultMaxBansPerMin,
				MaxConcurrentBans: defaultMaxConcurrentBans,
				MaxSharePct:       defaultMaxSharePct,
			},
		},
	}
}

// Load reads, strictly decodes, defaults and validates the YAML file at
// path. Unknown fields are errors (KnownFields) so a typo can never
// silently disable a security control. Any failure returns nil and an
// error that includes the file path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer f.Close()

	// Decode onto the defaults rather than a zero Config: with plain bool
	// fields a zero-value pass cannot tell "hash_ips absent" apart from
	// "hash_ips: false", and the default is true. Absent keys keep the
	// value from Default; present keys overwrite it.
	cfg := Default()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	err = dec.Decode(cfg)
	switch {
	case err == nil:
		// Decoded exactly one document; check for a trailing one below.
	case errors.Is(err, io.EOF):
		// Empty (or comment-only) file: keep the defaults and let
		// Validate report the real problem — the missing dashboard
		// token — instead of a bare EOF.
	default:
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err == nil {
		var extra any
		if derr := dec.Decode(&extra); !errors.Is(derr, io.EOF) {
			// A second document would silently discard half a
			// mis-pasted config; reject it loudly instead.
			return nil, fmt.Errorf("config: parse %s: expected exactly one YAML document", path)
		}
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validate %s: %w", path, err)
	}
	return cfg, nil
}

// applyDefaults replaces zero values with defaults. It deliberately never
// touches bool fields: false is a meaningful explicit choice, and the
// default-true booleans (store.hash_ips, decoys.enabled) are already
// supplied by decoding onto Default in Load. Explicit nil ("null") slices
// are treated as absent and re-defaulted.
func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeLook
	}
	if c.Listen == "" {
		c.Listen = defaultListen
	}
	if c.ProtectedRoutes == nil {
		c.ProtectedRoutes = slices.Clone(defaultProtectedRoutes)
	}
	if c.Store.Path == "" {
		c.Store.Path = defaultStorePath
	}
	if c.Store.RetentionDays == 0 {
		c.Store.RetentionDays = defaultRetentionDays
	}
	if c.Events.QueueCapacity == 0 {
		c.Events.QueueCapacity = defaultQueueCapacity
	}
	if c.Decoys.CatalogPath == "" {
		c.Decoys.CatalogPath = defaultDecoyCatalogPath
	}
	if c.Enforcement.BanTTLms == 0 {
		c.Enforcement.BanTTLms = defaultBanTTLms
	}
	if c.Enforcement.Budgets.MaxBansPerMinute == 0 {
		c.Enforcement.Budgets.MaxBansPerMinute = defaultMaxBansPerMin
	}
	if c.Enforcement.Budgets.MaxConcurrentBans == 0 {
		c.Enforcement.Budgets.MaxConcurrentBans = defaultMaxConcurrentBans
	}
	if c.Enforcement.Budgets.MaxSharePct == 0 {
		c.Enforcement.Budgets.MaxSharePct = defaultMaxSharePct
	}
}

// Validate checks every rule and returns all violations joined with
// errors.Join, each message prefixed by its field path (e.g.
// "store.retention_days: must be 1..3650"). On success it also commits the
// parsed CIDR lists so TrustedProxies and OwnerRanges return data; on
// failure the Config must be treated as rejected and accessors stay empty.
func (c *Config) Validate() error {
	var errs []error

	switch c.Mode {
	case ModeLook, ModeTripwires, ModeProtect:
	default:
		errs = append(errs, fmt.Errorf("mode: must be one of %q, %q or %q (got %q)",
			ModeLook, ModeTripwires, ModeProtect, c.Mode))
	}

	// The dashboard requires a token even on loopback: an unauthenticated
	// local endpoint is one curl away from a full takeover.
	if strings.TrimSpace(c.DashboardToken) == "" {
		errs = append(errs, errors.New("dashboard_token: must not be empty (the dashboard requires a token even on loopback)"))
	}

	trustedProxies, err := model.ParsePrefixes(c.TrustedProxyCIDRs)
	if err != nil {
		errs = append(errs, fmt.Errorf("trusted_proxies: %w", err))
	}
	ownerRanges, err := model.ParsePrefixes(c.OwnerIPCIDRs)
	if err != nil {
		errs = append(errs, fmt.Errorf("owner_ips: %w", err))
	}

	if c.Store.RetentionDays < minRetentionDays || c.Store.RetentionDays > maxRetentionDays {
		errs = append(errs, fmt.Errorf("store.retention_days: must be %d..%d (got %d)",
			minRetentionDays, maxRetentionDays, c.Store.RetentionDays))
	}
	if c.Events.QueueCapacity < minQueueCapacity || c.Events.QueueCapacity > maxQueueCapacity {
		errs = append(errs, fmt.Errorf("events.queue_capacity: must be >=%d and <=%d (got %d)",
			minQueueCapacity, maxQueueCapacity, c.Events.QueueCapacity))
	}
	share := c.Enforcement.Budgets.MaxSharePct
	if share < minSharePct || share > maxSharePct {
		errs = append(errs, fmt.Errorf("enforcement.budgets.max_share_pct: must be %d..%d (got %d)",
			minSharePct, maxSharePct, share))
	}

	// I9: enforcement is opt-in per site and only exists in protect mode.
	if c.Enforcement.Enabled && c.Mode != ModeProtect {
		errs = append(errs, fmt.Errorf("enforcement.enabled: cannot be enabled in mode %q (enforcement requires mode %q, I9)",
			c.Mode, ModeProtect))
	}

	if cs := c.Connectors.CrowdSec; cs.anySet() {
		if cs.LAPIURL == "" {
			errs = append(errs, errors.New("connectors.crowdsec.lapi_url: required when the crowdsec connector is configured"))
		}
		if cs.APIKeyEnv == "" {
			errs = append(errs, errors.New("connectors.crowdsec.api_key_env: required when the crowdsec connector is configured"))
		}
	}
	if cf := c.Connectors.Cloudflare; cf.anySet() {
		if cf.AccountID == "" {
			errs = append(errs, errors.New("connectors.cloudflare.account_id: required when the cloudflare connector is configured"))
		}
		if cf.ZoneID == "" {
			errs = append(errs, errors.New("connectors.cloudflare.zone_id: required when the cloudflare connector is configured"))
		}
		if cf.APITokenEnv == "" {
			errs = append(errs, errors.New("connectors.cloudflare.api_token_env: required when the cloudflare connector is configured"))
		}
	}
	if wh := c.Connectors.Webhook; wh.anySet() {
		if wh.URL == "" {
			errs = append(errs, errors.New("connectors.webhook.url: required when the webhook connector is configured"))
		}
		if wh.SecretEnv == "" {
			errs = append(errs, errors.New("connectors.webhook.secret_env: required when the webhook connector is configured"))
		}
	}
	// Denyfile has a single field (path), so an all-empty block is simply
	// not configured and there is nothing further to require.

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	// Commit parsed state only for a fully valid config: accessors must
	// never hand out half-validated data.
	c.trustedProxies = trustedProxies
	c.ownerRanges = ownerRanges
	return nil
}

// TrustedProxies returns the parsed trusted-proxy prefixes (I6). Populated
// by a successful Validate (Load performs it); nil before that.
func (c *Config) TrustedProxies() []netip.Prefix {
	return c.trustedProxies
}

// OwnerRanges returns the parsed owner ranges: addresses never scored (I6).
// Populated by a successful Validate (Load performs it); nil before that.
func (c *Config) OwnerRanges() []netip.Prefix {
	return c.ownerRanges
}

// IsProtected reports whether path hits a protected route (I4): a route
// ending in "/" is a prefix, anything else matches exactly. Callers pass
// the normalized request path (query stripped, dot segments resolved —
// spec/SIGNALS.md section 3); this method does not normalize.
func (c *Config) IsProtected(path string) bool {
	for _, route := range c.ProtectedRoutes {
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

// EnforcementAllowed reports whether enforcement may act at all: opted in,
// protect mode, kill switch off (I9). Enforcement paths re-check this on
// every decision so flipping the kill switch takes effect immediately.
func (c *Config) EnforcementAllowed() bool {
	return c.Enforcement.Enabled && c.Mode == ModeProtect && !c.Enforcement.KillSwitch
}

// Redacted returns a deep copy with the dashboard token replaced by
// "REDACTED" (I11: secrets never reach logs or debug dumps). The copy is
// independent — mutating its slices never affects the original — and
// remains fully usable, including the parsed accessors.
func (c *Config) Redacted() *Config {
	out := *c
	out.DashboardToken = "REDACTED"
	out.TrustedProxyCIDRs = slices.Clone(c.TrustedProxyCIDRs)
	out.OwnerIPCIDRs = slices.Clone(c.OwnerIPCIDRs)
	out.ProtectedRoutes = slices.Clone(c.ProtectedRoutes)
	out.trustedProxies = slices.Clone(c.trustedProxies)
	out.ownerRanges = slices.Clone(c.ownerRanges)
	return &out
}

// CrowdSecKey resolves the CrowdSec LAPI key from the environment variable
// named by connectors.crowdsec.api_key_env (I11: the key never lives in the
// config file and is never stored on the Config).
func (c *Config) CrowdSecKey() (string, error) {
	return resolveEnv("connectors.crowdsec.api_key_env", c.Connectors.CrowdSec.APIKeyEnv)
}

// CloudflareToken resolves the Cloudflare API token from the environment
// variable named by connectors.cloudflare.api_token_env (I11).
func (c *Config) CloudflareToken() (string, error) {
	return resolveEnv("connectors.cloudflare.api_token_env", c.Connectors.Cloudflare.APITokenEnv)
}

// WebhookSecret resolves the webhook signing secret from the environment
// variable named by connectors.webhook.secret_env (I11).
func (c *Config) WebhookSecret() (string, error) {
	return resolveEnv("connectors.webhook.secret_env", c.Connectors.Webhook.SecretEnv)
}

// resolveEnv reads an environment variable referenced by name. An empty
// name means the connector was never configured; an unset or empty
// variable is an operator error, never a reason to fall back to an inline
// secret (I11).
func resolveEnv(field, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("config: %s is empty: connector not configured", field)
	}
	if v := os.Getenv(name); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("config: environment variable %s not set", name)
}
