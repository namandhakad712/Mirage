package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeYAML writes content to a fresh temp file and returns its path, so
// every case exercises the real file-reading path of Load.
func writeYAML(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mirage.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string // empty means Load must succeed
		check   func(*testing.T, *Config)
	}{
		{
			name: "minimal file gets every default",
			yaml: "site: https://example.test\ndashboard_token: tok-minimal\n",
			check: func(t *testing.T, cfg *Config) {
				if cfg.Mode != ModeLook {
					t.Errorf("Mode = %q, want %q", cfg.Mode, ModeLook)
				}
				if cfg.Listen != "127.0.0.1:8080" {
					t.Errorf("Listen = %q, want default 127.0.0.1:8080", cfg.Listen)
				}
				wantRoutes := []string{"/wp-login.php", "/wp-admin/", "/checkout", "/cart", "/api/"}
				if !slices.Equal(cfg.ProtectedRoutes, wantRoutes) {
					t.Errorf("ProtectedRoutes = %v, want canon default %v", cfg.ProtectedRoutes, wantRoutes)
				}
				if cfg.Store.Path != "mirage.db" || cfg.Store.RetentionDays != 30 || !cfg.Store.HashIPs {
					t.Errorf("Store = %+v, want defaults mirage.db/30/true", cfg.Store)
				}
				if cfg.Events.QueueCapacity != 10000 {
					t.Errorf("QueueCapacity = %d, want 10000", cfg.Events.QueueCapacity)
				}
				if cfg.Decoys.CatalogPath != "spec/decoy-catalog/catalog.yaml" || !cfg.Decoys.Enabled {
					t.Errorf("Decoys = %+v, want defaults catalog/enabled", cfg.Decoys)
				}
				if cfg.Enforcement.Enabled || cfg.Enforcement.KillSwitch {
					t.Errorf("Enforcement flags = enabled:%v kill:%v, want both false", cfg.Enforcement.Enabled, cfg.Enforcement.KillSwitch)
				}
				if cfg.Enforcement.BanTTLms != 1_800_000 {
					t.Errorf("BanTTLms = %d, want 1800000", cfg.Enforcement.BanTTLms)
				}
				b := cfg.Enforcement.Budgets
				if b.MaxBansPerMinute != 10 || b.MaxConcurrentBans != 100 || b.MaxSharePct != 5 {
					t.Errorf("Budgets = %+v, want 10/100/5", b)
				}
				if cfg.EnforcementAllowed() {
					t.Error("EnforcementAllowed() = true, want false in look mode")
				}
				if len(cfg.TrustedProxies()) != 0 || len(cfg.OwnerRanges()) != 0 {
					t.Error("parsed ranges should be empty when none are configured")
				}
			},
		},
		{
			name:    "empty file reports missing dashboard token",
			yaml:    "",
			wantErr: "dashboard_token:",
		},
		{
			name:    "missing dashboard token",
			yaml:    "site: https://example.test\n",
			wantErr: "dashboard_token:",
		},
		{
			name:    "whitespace-only dashboard token",
			yaml:    "dashboard_token: \"   \"\n",
			wantErr: "dashboard_token:",
		},
		{
			name:    "unknown top-level field rejected",
			yaml:    "dashboard_token: t\nnot_a_field: 1\n",
			wantErr: "field not_a_field not found",
		},
		{
			name:    "unknown nested field rejected",
			yaml:    "dashboard_token: t\nstore:\n  not_a_store_field: 1\n",
			wantErr: "field not_a_store_field not found",
		},
		{
			name:    "wrong scalar type rejected",
			yaml:    "dashboard_token: t\nlisten: [not, a, string]\n",
			wantErr: "cannot unmarshal",
		},
		{
			name:    "second yaml document rejected",
			yaml:    "dashboard_token: t\n---\ndashboard_token: t2\n",
			wantErr: "expected exactly one YAML document",
		},
		{
			name:    "invalid mode rejected",
			yaml:    "dashboard_token: t\nmode: observe\n",
			wantErr: "mode: must be one of",
		},
		{
			name: "explicit empty mode falls back to look",
			yaml: "dashboard_token: t\nmode: \"\"\n",
			check: func(t *testing.T, cfg *Config) {
				if cfg.Mode != ModeLook {
					t.Errorf("Mode = %q, want %q", cfg.Mode, ModeLook)
				}
			},
		},
		{
			name:    "retention days above range rejected",
			yaml:    "dashboard_token: t\nstore:\n  retention_days: 4000\n",
			wantErr: "store.retention_days:",
		},
		{
			name:    "retention days negative rejected",
			yaml:    "dashboard_token: t\nstore:\n  retention_days: -1\n",
			wantErr: "store.retention_days:",
		},
		{
			name: "retention days zero uses default",
			yaml: "dashboard_token: t\nstore:\n  retention_days: 0\n",
			check: func(t *testing.T, cfg *Config) {
				if cfg.Store.RetentionDays != 30 {
					t.Errorf("RetentionDays = %d, want default 30", cfg.Store.RetentionDays)
				}
			},
		},
		{
			name:    "queue capacity below minimum rejected",
			yaml:    "dashboard_token: t\nevents:\n  queue_capacity: 50\n",
			wantErr: "events.queue_capacity:",
		},
		{
			name:    "queue capacity above maximum rejected",
			yaml:    "dashboard_token: t\nevents:\n  queue_capacity: 1000001\n",
			wantErr: "events.queue_capacity:",
		},
		{
			name:    "max share percent above 100 rejected",
			yaml:    "dashboard_token: t\nenforcement:\n  budgets:\n    max_share_pct: 150\n",
			wantErr: "enforcement.budgets.max_share_pct:",
		},
		{
			name: "max share percent zero uses default",
			yaml: "dashboard_token: t\nenforcement:\n  budgets:\n    max_share_pct: 0\n",
			check: func(t *testing.T, cfg *Config) {
				if cfg.Enforcement.Budgets.MaxSharePct != 5 {
					t.Errorf("MaxSharePct = %d, want default 5", cfg.Enforcement.Budgets.MaxSharePct)
				}
			},
		},
		{
			name:    "enforcement enabled in look mode rejected",
			yaml:    "dashboard_token: t\nenforcement:\n  enabled: true\n",
			wantErr: "enforcement.enabled:",
		},
		{
			name:    "enforcement enabled in tripwires mode rejected",
			yaml:    "dashboard_token: t\nmode: tripwires\nenforcement:\n  enabled: true\n",
			wantErr: "enforcement.enabled:",
		},
		{
			name: "enforcement enabled in protect mode accepted",
			yaml: "dashboard_token: t\nmode: protect\nenforcement:\n  enabled: true\n",
			check: func(t *testing.T, cfg *Config) {
				if !cfg.EnforcementAllowed() {
					t.Error("EnforcementAllowed() = false, want true in protect mode with enforcement on")
				}
			},
		},
		{
			name: "kill switch blocks enforcement even in protect mode",
			yaml: "dashboard_token: t\nmode: protect\nenforcement:\n  enabled: true\n  kill_switch: true\n",
			check: func(t *testing.T, cfg *Config) {
				if cfg.EnforcementAllowed() {
					t.Error("EnforcementAllowed() = true, want false with kill switch on")
				}
			},
		},
		{
			name:    "invalid trusted proxy cidr rejected",
			yaml:    "dashboard_token: t\ntrusted_proxies: [\"not-a-cidr\"]\n",
			wantErr: "trusted_proxies:",
		},
		{
			name:    "invalid owner ip cidr rejected",
			yaml:    "dashboard_token: t\nowner_ips: [\"300.0.0.0/8\"]\n",
			wantErr: "owner_ips:",
		},
		{
			name:    "crowdsec missing api_key_env rejected",
			yaml:    "dashboard_token: t\nconnectors:\n  crowdsec:\n    lapi_url: http://127.0.0.1:8080/v1\n",
			wantErr: "connectors.crowdsec.api_key_env:",
		},
		{
			name:    "cloudflare missing zone_id rejected",
			yaml:    "dashboard_token: t\nconnectors:\n  cloudflare:\n    account_id: acct\n    api_token_env: CF_TOKEN\n",
			wantErr: "connectors.cloudflare.zone_id:",
		},
		{
			name:    "webhook missing url rejected",
			yaml:    "dashboard_token: t\nconnectors:\n  webhook:\n    secret_env: HOOK_SECRET\n",
			wantErr: "connectors.webhook.url:",
		},
		{
			name: "empty connector blocks are accepted",
			yaml: "dashboard_token: t\nconnectors:\n  crowdsec: {}\n  cloudflare: {}\n  webhook: {}\n  denyfile: {}\n",
		},
		{
			name: "explicit hash_ips false survives the true default",
			yaml: "dashboard_token: t\nstore:\n  hash_ips: false\n",
			check: func(t *testing.T, cfg *Config) {
				if cfg.Store.HashIPs {
					t.Error("HashIPs = true, want the explicit false")
				}
			},
		},
		{
			name: "explicit decoys disabled survives the true default",
			yaml: "dashboard_token: t\ndecoys:\n  enabled: false\n",
			check: func(t *testing.T, cfg *Config) {
				if cfg.Decoys.Enabled {
					t.Error("Decoys.Enabled = true, want the explicit false")
				}
			},
		},
		{
			name: "explicit empty protected routes list is honored",
			yaml: "dashboard_token: t\nprotected_routes: []\n",
			check: func(t *testing.T, cfg *Config) {
				if len(cfg.ProtectedRoutes) != 0 {
					t.Errorf("ProtectedRoutes = %v, want empty (explicit owner choice)", cfg.ProtectedRoutes)
				}
				if cfg.IsProtected("/wp-admin/") {
					t.Error("IsProtected(/wp-admin/) = true, want false with an empty route list")
				}
			},
		},
		{
			name: "custom protected routes replace the defaults",
			yaml: "dashboard_token: t\nprotected_routes:\n  - /admin/\n  - /exact\n",
			check: func(t *testing.T, cfg *Config) {
				want := []string{"/admin/", "/exact"}
				if !slices.Equal(cfg.ProtectedRoutes, want) {
					t.Errorf("ProtectedRoutes = %v, want %v", cfg.ProtectedRoutes, want)
				}
				if cfg.IsProtected("/wp-login.php") {
					t.Error("IsProtected(/wp-login.php) = true, want false: defaults were replaced")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(writeYAML(t, tt.yaml))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Load succeeded, want error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Load error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestValidateCollectsAllViolations(t *testing.T) {
	cfg := &Config{
		Mode:           "observe",
		DashboardToken: "   ",
		Store:          StoreConfig{RetentionDays: 9999},
		Events:         EventsConfig{QueueCapacity: 1},
		Enforcement:    EnforcementConfig{Enabled: true, Budgets: BudgetsConfig{MaxSharePct: 200}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate succeeded, want joined violations")
	}
	for _, want := range []string{
		"mode:",
		"dashboard_token:",
		"store.retention_days:",
		"events.queue_capacity:",
		"enforcement.budgets.max_share_pct:",
		"enforcement.enabled:",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Validate error %q does not contain %q", err, want)
		}
	}
	// A failed Validate must not commit half-parsed state.
	if cfg.TrustedProxies() != nil || cfg.OwnerRanges() != nil {
		t.Error("accessors must stay empty when Validate fails")
	}
}

func TestValidateCommitsParsedRanges(t *testing.T) {
	cfg := Default()
	cfg.DashboardToken = "tok"
	cfg.TrustedProxyCIDRs = []string{"10.0.0.0/8", "192.0.2.1"}
	cfg.OwnerIPCIDRs = []string{"198.51.100.0/24"}
	if cfg.TrustedProxies() != nil || cfg.OwnerRanges() != nil {
		t.Fatal("accessors must be empty before Validate")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := cfg.TrustedProxies(); len(got) != 2 {
		t.Errorf("TrustedProxies() = %v, want 2 prefixes", got)
	} else if !slices.Contains(got, netip.MustParsePrefix("192.0.2.1/32")) {
		t.Errorf("TrustedProxies() = %v, want a bare IP normalized to 192.0.2.1/32", got)
	}
	if got := cfg.OwnerRanges(); len(got) != 1 || got[0] != netip.MustParsePrefix("198.51.100.0/24") {
		t.Errorf("OwnerRanges() = %v, want [198.51.100.0/24]", got)
	}
}

func TestIsProtected(t *testing.T) {
	defaultCfg := Default()
	customCfg := Default()
	customCfg.ProtectedRoutes = []string{"/admin/", "/exact"}

	tests := []struct {
		name string
		cfg  *Config
		path string
		want bool
	}{
		// Default canon list: exact entries and "/"-terminated prefixes.
		{"default exact wp-login", defaultCfg, "/wp-login.php", true},
		{"default wp-login is not a prefix", defaultCfg, "/wp-login.php/x", false},
		{"default wp-admin prefix self", defaultCfg, "/wp-admin/", true},
		{"default wp-admin prefix child", defaultCfg, "/wp-admin/options-general.php", true},
		{"default wp-admin lookalike", defaultCfg, "/wp-adminish", false},
		{"default exact checkout", defaultCfg, "/checkout", true},
		{"default checkout has no children", defaultCfg, "/checkout/step2", false},
		{"default exact cart", defaultCfg, "/cart", true},
		{"default api prefix child", defaultCfg, "/api/v1/orders", true},
		{"default api prefix needs the slash", defaultCfg, "/api", false},
		{"default root", defaultCfg, "/", false},
		{"default blog", defaultCfg, "/blog/post", false},
		// The caller normalizes the path (spec section 3): a query string
		// is not stripped here and breaks the exact match on purpose.
		{"default query is not stripped", defaultCfg, "/wp-login.php?redirect=/", false},
		// Custom list replaces the defaults entirely.
		{"custom prefix child", customCfg, "/admin/users", true},
		{"custom prefix self", customCfg, "/admin/", true},
		{"custom prefix misses bare path", customCfg, "/admin", false},
		{"custom exact", customCfg, "/exact", true},
		{"custom exact has no children", customCfg, "/exact/sub", false},
		{"custom replaced default", customCfg, "/wp-login.php", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsProtected(tt.path); got != tt.want {
				t.Errorf("IsProtected(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestEnforcementAllowed(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		enabled    bool
		killSwitch bool
		want       bool
	}{
		{"protect enabled", ModeProtect, true, false, true},
		{"protect enabled kill switch", ModeProtect, true, true, false},
		{"protect disabled", ModeProtect, false, false, false},
		{"look enabled", ModeLook, true, false, false},
		{"tripwires enabled", ModeTripwires, true, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Mode: tt.mode, Enforcement: EnforcementConfig{Enabled: tt.enabled, KillSwitch: tt.killSwitch}}
			if got := cfg.EnforcementAllowed(); got != tt.want {
				t.Errorf("EnforcementAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnvResolution(t *testing.T) {
	cfg := Default()
	cfg.DashboardToken = "tok"
	cfg.Connectors = ConnectorsConfig{
		CrowdSec:   CrowdSecConfig{LAPIURL: "http://127.0.0.1:8080/v1", APIKeyEnv: "MIRAGE_TEST_LAPI_KEY"},
		Cloudflare: CloudflareConfig{AccountID: "acct", ZoneID: "zone", APITokenEnv: "MIRAGE_TEST_CF_TOKEN"},
		Webhook:    WebhookConfig{URL: "https://example.test/hook", SecretEnv: "MIRAGE_TEST_HOOK_SECRET"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	t.Setenv("MIRAGE_TEST_LAPI_KEY", "lapi-secret-value")
	t.Setenv("MIRAGE_TEST_HOOK_SECRET", "hook-secret-value")
	// MIRAGE_TEST_CF_TOKEN deliberately left unset.

	if got, err := cfg.CrowdSecKey(); err != nil || got != "lapi-secret-value" {
		t.Errorf("CrowdSecKey() = %q, %v; want lapi-secret-value, nil", got, err)
	}
	if got, err := cfg.WebhookSecret(); err != nil || got != "hook-secret-value" {
		t.Errorf("WebhookSecret() = %q, %v; want hook-secret-value, nil", got, err)
	}
	if _, err := cfg.CloudflareToken(); err == nil || !strings.Contains(err.Error(), "environment variable MIRAGE_TEST_CF_TOKEN not set") {
		t.Errorf("CloudflareToken() error = %v, want missing-environment error naming MIRAGE_TEST_CF_TOKEN", err)
	}

	// A connector that was never configured fails with its field path so
	// the operator learns which block is incomplete.
	empty := Default()
	empty.DashboardToken = "tok"
	if err := empty.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, err := empty.CrowdSecKey(); err == nil || !strings.Contains(err.Error(), "connectors.crowdsec.api_key_env") {
		t.Errorf("CrowdSecKey() on unconfigured connector error = %v, want field-path error", err)
	}
}

func TestRedacted(t *testing.T) {
	cfg := Default()
	cfg.DashboardToken = "super-secret-token"
	cfg.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
	cfg.ProtectedRoutes = []string{"/admin/"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	red := cfg.Redacted()
	if red.DashboardToken != "REDACTED" {
		t.Errorf("Redacted().DashboardToken = %q, want REDACTED", red.DashboardToken)
	}
	if cfg.DashboardToken != "super-secret-token" {
		t.Errorf("original DashboardToken = %q, want unchanged", cfg.DashboardToken)
	}
	// Deep copy: mutating the copy's slices must never leak into the
	// original, and parsed accessors survive redaction.
	red.ProtectedRoutes[0] = "/mutated/"
	red.TrustedProxyCIDRs[0] = "192.0.2.0/24"
	if cfg.ProtectedRoutes[0] != "/admin/" || cfg.TrustedProxyCIDRs[0] != "10.0.0.0/8" {
		t.Error("mutating the redacted copy changed the original")
	}
	if len(red.TrustedProxies()) != 1 {
		t.Errorf("Redacted().TrustedProxies() = %v, want the parsed range preserved", red.TrustedProxies())
	}
}

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.Mode != ModeLook || cfg.Listen != "127.0.0.1:8080" {
		t.Errorf("Mode/Listen = %q/%q, want look/127.0.0.1:8080", cfg.Mode, cfg.Listen)
	}
	if !cfg.Store.HashIPs || !cfg.Decoys.Enabled {
		t.Error("default-true booleans must default to true")
	}
	// Default must be valid except for the missing token, which cannot
	// have a default because no default secret exists.
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "dashboard_token") {
		t.Fatalf("Validate(Default) = %v, want exactly the dashboard_token violation", err)
	}
	cfg.DashboardToken = "tok"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default plus a token must validate cleanly: %v", err)
	}
	// Each Default() call must own its slices: mutating one result may
	// never poison later ones.
	first := Default()
	first.ProtectedRoutes[0] = "/mutated/"
	if second := Default(); second.ProtectedRoutes[0] != "/wp-login.php" {
		t.Error("Default() results share slice backing arrays")
	}
}

func TestLoadErrorsIncludePath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	if _, err := Load(missing); err == nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("Load(missing) error = %v, want it to include %q", err, missing)
	}

	invalid := writeYAML(t, "dashboard_token: \"\"\n")
	if _, err := Load(invalid); err == nil || !strings.Contains(err.Error(), invalid) {
		t.Errorf("Load(invalid) error = %v, want it to include %q", err, invalid)
	} else if !strings.Contains(err.Error(), "dashboard_token") {
		t.Errorf("Load(invalid) error = %v, want it to also name the violation", err)
	}
}

func TestValidFullExample(t *testing.T) {
	path := writeYAML(t, `mode: protect
site: https://example.test
listen: 127.0.0.1:9090
trusted_proxies:
  - 173.245.48.0/20
  - 10.0.0.7
dashboard_token: tok-full-example
owner_ips:
  - 192.0.2.10
  - 198.51.100.0/24
protected_routes:
  - /wp-login.php
  - /wp-admin/
  - /shop/checkout
store:
  path: /var/lib/mirage/mirage.db
  retention_days: 90
  hash_ips: false
events:
  queue_capacity: 5000
decoys:
  catalog_path: spec/decoy-catalog/catalog.yaml
  enabled: true
enforcement:
  enabled: true
  kill_switch: false
  ban_ttl_ms: 900000
  budgets:
    max_bans_per_minute: 5
    max_concurrent_bans: 50
    max_share_pct: 3
connectors:
  crowdsec:
    lapi_url: http://127.0.0.1:8080/v1
    api_key_env: MIRAGE_TEST_LAPI_KEY
  cloudflare:
    account_id: acct-example
    zone_id: zone-example
    api_token_env: MIRAGE_TEST_CF_TOKEN
  webhook:
    url: https://example.test/hook
    secret_env: MIRAGE_TEST_HOOK_SECRET
  denyfile:
    path: /etc/mirage/deny.txt
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Mode != ModeProtect || cfg.Site != "https://example.test" || cfg.Listen != "127.0.0.1:9090" {
		t.Errorf("header fields = %q/%q/%q", cfg.Mode, cfg.Site, cfg.Listen)
	}
	wantProxies := []netip.Prefix{netip.MustParsePrefix("173.245.48.0/20"), netip.MustParsePrefix("10.0.0.7/32")}
	if got := cfg.TrustedProxies(); !slices.Equal(got, wantProxies) {
		t.Errorf("TrustedProxies() = %v, want %v (bare IP normalized to /32)", got, wantProxies)
	}
	wantOwners := []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32"), netip.MustParsePrefix("198.51.100.0/24")}
	if got := cfg.OwnerRanges(); !slices.Equal(got, wantOwners) {
		t.Errorf("OwnerRanges() = %v, want %v", got, wantOwners)
	}
	if !cfg.IsProtected("/shop/checkout") || !cfg.IsProtected("/wp-admin/x") || cfg.IsProtected("/cart") {
		t.Error("IsProtected disagrees with the custom route list")
	}
	if cfg.Store.Path != "/var/lib/mirage/mirage.db" || cfg.Store.RetentionDays != 90 || cfg.Store.HashIPs {
		t.Errorf("Store = %+v, want explicit values with hash_ips false", cfg.Store)
	}
	if cfg.Events.QueueCapacity != 5000 {
		t.Errorf("QueueCapacity = %d, want 5000", cfg.Events.QueueCapacity)
	}
	if !cfg.Decoys.Enabled || cfg.Decoys.CatalogPath != "spec/decoy-catalog/catalog.yaml" {
		t.Errorf("Decoys = %+v", cfg.Decoys)
	}
	if !cfg.EnforcementAllowed() {
		t.Error("EnforcementAllowed() = false, want true (protect, enabled, no kill switch)")
	}
	if cfg.Enforcement.BanTTLms != 900000 {
		t.Errorf("BanTTLms = %d, want 900000", cfg.Enforcement.BanTTLms)
	}
	b := cfg.Enforcement.Budgets
	if b.MaxBansPerMinute != 5 || b.MaxConcurrentBans != 50 || b.MaxSharePct != 3 {
		t.Errorf("Budgets = %+v, want 5/50/3", b)
	}
	if cfg.Connectors.Denyfile.Path != "/etc/mirage/deny.txt" {
		t.Errorf("Denyfile.Path = %q", cfg.Connectors.Denyfile.Path)
	}

	// Environment resolution works end to end on the loaded config; the
	// secret values themselves must not exist anywhere on it (I11).
	t.Setenv("MIRAGE_TEST_LAPI_KEY", "lapi-key-value")
	if got, err := cfg.CrowdSecKey(); err != nil || got != "lapi-key-value" {
		t.Errorf("CrowdSecKey() = %q, %v; want lapi-key-value, nil", got, err)
	}
}
