package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/mirage-shield/mirage/internal/config"
	"github.com/mirage-shield/mirage/internal/events"
	"github.com/mirage-shield/mirage/internal/service"
)

// postureCheck is one line of the posture report: a named aspect of the
// configuration and its effective value. Values are strings so the human
// table and the JSON mirror each other exactly.
type postureCheck struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// postureReport is the --json shape: the mode, every warning, and the check
// lines. Warnings are advisory — posture exits 0 for any configuration
// that loads and validates; only a load/validate failure exits 1.
type postureReport struct {
	Mode     string         `json:"mode"`
	Warnings []string       `json:"warnings"`
	Checks   []postureCheck `json:"checks"`
}

// cmdPosture implements `mirage posture`: a non-mutating, informational
// report of the site's security posture — what the configuration actually
// grants, as opposed to what it might be assumed to grant. It is the
// operator's answer to "what would this config do" before `serve` does it:
// mode and opt-in state (I9), budgets (I5), protected routes (I4), trust
// boundaries (I6), and the leak-shaped mistakes posture can see.
func cmdPosture(args []string) int {
	fs, help := newFlagSet("mirage posture", "mirage posture --config FILE [--json]")
	cfgPath := fs.String("config", "", "site configuration file (required)")
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON instead of the report")
	fs, code := parseFlags(fs, help, args)
	if fs == nil {
		return code
	}
	if code := extraArgs(fs); code != exitOK {
		return code
	}
	if *cfgPath == "" {
		fmt.Fprintln(stderr, "mirage posture: --config is required")
		return exitUsage
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "mirage posture: %v\n", err)
		return exitFail
	}

	rep := buildPostureReport(cfg)
	if *jsonOut {
		if err := json.NewEncoder(stdout).Encode(rep); err != nil {
			fmt.Fprintf(stderr, "mirage posture: encode report: %v\n", err)
			return exitFail
		}
		return exitOK
	}
	renderPosture(rep, *cfgPath)
	return exitOK
}

// buildPostureReport assembles the check lines and warnings from a loaded
// configuration. Warnings never affect the exit code: posture reports the
// posture, doctor judges the health.
func buildPostureReport(cfg *config.Config) postureReport {
	enforcement := "not opted in (observe only, I9)"
	if cfg.Enforcement.Enabled {
		enforcement = "opted in (enabled)"
	}
	killSwitch := "disarmed"
	if cfg.Enforcement.KillSwitch {
		killSwitch = "ENGAGED (enforcement drops to observe)"
	}
	token := "present"
	if strings.TrimSpace(cfg.DashboardToken) == "" {
		token = "MISSING"
	}

	// The decision budget is a service-level constant, not a config key
	// (service.Options.DecideBudgetMs); every deployment runs the
	// recommended budget unless code says otherwise, so the report states
	// the effective value.
	checks := []postureCheck{
		{"mode", cfg.Mode},
		{"enforcement", enforcement},
		{"kill switch", killSwitch},
		{"decision budget", fmt.Sprintf("%d ms", service.DefaultDecideBudgetMs)},
		{"queue bounds", fmt.Sprintf("capacity %d (min %d, max %d)",
			cfg.Events.QueueCapacity, events.MinQueueCapacity, events.MaxQueueCapacity)},
		{"ban budgets", fmt.Sprintf("%d per minute, %d concurrent, %d%% share cap",
			cfg.Enforcement.Budgets.MaxBansPerMinute,
			cfg.Enforcement.Budgets.MaxConcurrentBans,
			cfg.Enforcement.Budgets.MaxSharePct)},
		{"ban ttl", fmt.Sprintf("%d ms", cfg.Enforcement.BanTTLms)},
		{"protected routes", strings.Join(cfg.ProtectedRoutes, " ")},
		{"trusted proxies", fmt.Sprintf("%d range(s)", len(cfg.TrustedProxyCIDRs))},
		{"never-scored ranges", fmt.Sprintf("%d range(s)", len(cfg.OwnerIPCIDRs))},
		{"connectors", strings.Join(connectorNames(cfg), ", ")},
		{"dashboard token", token},
		{"store", fmt.Sprintf("sqlite at %s (retention %d d, ip hashing %v)",
			cfg.Store.Path, cfg.Store.RetentionDays, cfg.Store.HashIPs)},
	}
	warnings := postureWarnings(cfg)
	if warnings == nil {
		warnings = []string{} // JSON: [] rather than null when clean
	}
	return postureReport{Mode: cfg.Mode, Warnings: warnings, Checks: checks}
}

// postureWarnings lists the advisory findings. Each one names a gap between
// what the mode implies and what the configuration actually grants, or a
// permission shape that leaks.
func postureWarnings(cfg *config.Config) []string {
	var warnings []string
	if cfg.Mode == config.ModeProtect && !cfg.Enforcement.Enabled {
		warnings = append(warnings,
			"mode protect without enforcement.enabled: the site observes only — the opt-in block is missing (I9)")
	}
	if cfg.Mode == config.ModeProtect && strings.TrimSpace(cfg.DashboardToken) == "" {
		// Unreachable through Load — Validate rejects an empty token — and
		// kept anyway: posture is also the checklist a hand-built
		// configuration is inspected against, and protect mode without the
		// one required secret is exactly the mistake it must name.
		warnings = append(warnings,
			"protect mode without a dashboard token: the dashboard requires a token even on loopback")
	}
	if len(cfg.TrustedProxyCIDRs) == 0 {
		warnings = append(warnings,
			"no trusted proxies: X-Forwarded-For is ignored and every session maps to the peer address — behind a proxy all traffic shares one session (I6)")
	}
	warnings = append(warnings, storePermWarnings(cfg.Store.Path)...)
	if cfg.Mode == config.ModeProtect && cfg.Enforcement.Enabled && cfg.Enforcement.KillSwitch {
		warnings = append(warnings,
			"kill switch engaged: enforcement is armed but disarmed at the switch — every ban degrades to observe (I9)")
	}
	return warnings
}

// storePermWarnings inspects the sqlite store path's permissions. The event
// log holds attacker-adjacent data and plain ban IPs (I7, I10), so a
// group/other-accessible database file is a leak; a world-writable store
// directory lets any local user replace the database wholesale. Only the
// file is checked when it exists — a fresh install has no file yet, and
// the directory the file will be created in is the only thing on disk to
// judge.
func storePermWarnings(path string) []string {
	var warnings []string
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		if perm := st.Mode().Perm(); perm&0o077 != 0 {
			warnings = append(warnings, fmt.Sprintf(
				"store file %s is group/other accessible (mode %04o) — the event log holds attacker-adjacent data (I7)",
				path, perm))
		}
		return warnings
	}
	if st, err := os.Stat(filepath.Dir(path)); err == nil && st.IsDir() {
		if perm := st.Mode().Perm(); perm&0o002 != 0 {
			warnings = append(warnings, fmt.Sprintf(
				"store directory %s is world-writable (mode %04o) — any local user can replace the database",
				filepath.Dir(path), perm))
		}
	}
	return warnings
}

// renderPosture prints the human report: an aligned check/value table, the
// warnings under their own heading so they cannot be skimmed past, and a
// closing summary that names the warning count even when the list is long.
func renderPosture(rep postureReport, cfgPath string) {
	fmt.Fprintf(stdout, "mirage posture — %s (informational)\n\n", cfgPath)
	w := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	for _, c := range rep.Checks {
		fmt.Fprintf(w, "%s\t%s\n", c.Name, c.Value)
	}
	w.Flush()
	fmt.Fprintln(stdout)
	if len(rep.Warnings) == 0 {
		fmt.Fprintln(stdout, "warnings: none")
		return
	}
	fmt.Fprintf(stdout, "WARNINGS (%d)\n", len(rep.Warnings))
	for _, warn := range rep.Warnings {
		fmt.Fprintf(stdout, "- %s\n", warn)
	}
}
