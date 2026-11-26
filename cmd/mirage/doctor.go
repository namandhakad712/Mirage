package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/mirage-shield/mirage/internal/config"
	"github.com/mirage-shield/mirage/internal/model"
	"github.com/mirage-shield/mirage/internal/store"
)

// check is one doctor finding: a named probe, its outcome, and a detail
// line that is safe to print. Safety here is a hard rule inherited from the
// connector surface (I11): env-var probes report the variable NAME and a
// yes/no resolution, never a resolved value.
type check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// doctorReport is the --json shape of the health check: the overall verdict,
// every check, and the spec/mode identity of the configuration examined so
// a log of past doctor runs stays interpretable after spec bumps.
type doctorReport struct {
	OK          bool    `json:"ok"`
	Checks      []check `json:"checks"`
	SpecVersion string  `json:"spec_version"`
	Mode        string  `json:"mode"`
}

// cmdDoctor implements `mirage doctor`: a non-mutating pre-flight check of
// everything `mirage serve` will need — the config itself, the engine's
// data files, the decoy catalog, a store that opens and answers (memory
// only: doctor must never create or touch the site's real sqlite file),
// every configured connector's secret resolution, and the kill-switch
// state. Exit 1 when any check fails, so install docs can say "run doctor"
// and scripts can trust the exit code.
func cmdDoctor(args []string) int {
	fs, help := newFlagSet("mirage doctor", "mirage doctor --config FILE [--json]")
	cfgPath := fs.String("config", "", "site configuration file (required)")
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON instead of the check table")
	fs, code := parseFlags(fs, help, args)
	if fs == nil {
		return code
	}
	if code := extraArgs(fs); code != exitOK {
		return code
	}
	if *cfgPath == "" {
		fmt.Fprintln(stderr, "mirage doctor: --config is required")
		return exitUsage
	}
	return runDoctor(*cfgPath, *jsonOut)
}

// runDoctor performs the checks and renders the report. A config that
// cannot load is reported as its own failing check and short-circuits the
// rest: every later probe reads paths from the config, and probing against
// silent defaults would produce confident nonsense.
func runDoctor(cfgPath string, jsonOut bool) int {
	var checks []check
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		checks = append(checks, check{Name: "config", OK: false, Detail: err.Error()})
	} else {
		checks = append(checks, check{Name: "config", OK: true,
			Detail: fmt.Sprintf("%s (mode %s)", cfgPath, cfg.Mode)})
		checks = append(checks, engineRulesCheck(cfg)...)
		checks = append(checks, catalogCheck(cfg)...)
		checks = append(checks, storeCheck())
		checks = append(checks, connectorChecks(cfg)...)
		checks = append(checks, killSwitchCheck(cfg))
	}

	rep := doctorReport{OK: true, Checks: checks, SpecVersion: model.SpecVersion}
	if cfg != nil {
		rep.Mode = cfg.Mode
	}
	for _, c := range checks {
		if !c.OK {
			rep.OK = false
		}
	}
	if jsonOut {
		if err := json.NewEncoder(stdout).Encode(rep); err != nil {
			fmt.Fprintf(stderr, "mirage doctor: encode report: %v\n", err)
			return exitFail
		}
	} else {
		renderChecks(checks)
	}
	if rep.OK {
		return exitOK
	}
	fmt.Fprintf(stderr, "mirage doctor: %d of %d checks failed\n", countFailed(checks), len(checks))
	return exitFail
}

// engineRulesCheck loads the engine's inputs (the data lists and the decoy
// graph). One failing file fails the check with the loader's own message,
// which names the file — a missing data/scanner-paths.txt reads as such,
// not as a generic load error.
func engineRulesCheck(cfg *config.Config) []check {
	rules, err := loadEngineRules(cfg)
	if err != nil {
		return []check{{Name: "engine data files", OK: false, Detail: err.Error()}}
	}
	return []check{{Name: "engine data files", OK: true, Detail: fmt.Sprintf(
		"%d scanner paths, %d suspicious UA substrings, %d verified-bot hints, %d decoys (%s)",
		len(rules.ScannerPaths), len(rules.SuspiciousUA), len(rules.VerifiedBots), len(rules.DecoyPaths),
		cfg.Decoys.CatalogPath)}}
}

// catalogCheck loads the catalog through the renderer's loader, which
// validates the full entry surface (personas, statuses, size caps, lead
// hygiene) beyond the graph the engine reads.
func catalogCheck(cfg *config.Config) []check {
	cat, err := loadCatalog(cfg)
	if err != nil {
		return []check{{Name: "decoy catalog", OK: false, Detail: err.Error()}}
	}
	return []check{{Name: "decoy catalog", OK: true,
		Detail: fmt.Sprintf("%d entries, %d personas (%s)", len(cat.Entries), len(cat.Personas), cfg.Decoys.CatalogPath)}}
}

// storeCheck proves a store opens, answers and closes — through the memory
// implementation, deliberately: doctor is non-mutating and must never
// create or migrate the site's real sqlite file just by being run.
func storeCheck() check {
	ms := store.NewMemoryStore()
	ctx := context.Background()
	ev := model.Event{
		ProtocolVersion: model.ProtocolVersion,
		TsMs:            0,
		SessionKey:      "mirage-doctor-probe",
		ClientIP:        "203.0.113.1", // RFC 5737 documentation range (I14)
		Method:          "GET",
		Path:            "/",
	}
	if err := ms.AppendEvent(ctx, ev); err != nil {
		return check{Name: "store", OK: false, Detail: fmt.Sprintf("memory store append: %v", err)}
	}
	got, err := ms.RecentEvents(ctx, 1)
	if err != nil || len(got) != 1 {
		return check{Name: "store", OK: false, Detail: fmt.Sprintf("memory store read back: %v (got %d events)", err, len(got))}
	}
	if err := ms.Close(); err != nil {
		return check{Name: "store", OK: false, Detail: fmt.Sprintf("memory store close: %v", err)}
	}
	return check{Name: "store", OK: true, Detail: "memory store round-trip ok (sqlite file untouched)"}
}

// connectorChecks verifies every configured connector's *_env variable
// resolves. The check prints the variable NAME and whether it resolves —
// never the value (I11). The denyfile connector carries no secret; its
// probe is that the directory it rewrites into exists.
func connectorChecks(cfg *config.Config) []check {
	c := cfg.Connectors
	var checks []check
	if cs := c.CrowdSec; cs.LAPIURL != "" || cs.APIKeyEnv != "" {
		checks = append(checks, envCheck("connector crowdsec", cs.APIKeyEnv))
	}
	if cf := c.Cloudflare; cf.AccountID != "" || cf.ZoneID != "" || cf.APITokenEnv != "" {
		checks = append(checks, envCheck("connector cloudflare", cf.APITokenEnv))
	}
	if wh := c.Webhook; wh.URL != "" || wh.SecretEnv != "" {
		checks = append(checks, envCheck("connector webhook", wh.SecretEnv))
	}
	if c.Denyfile.Path != "" {
		checks = append(checks, denyfileCheck(c.Denyfile.Path))
	}
	if len(checks) == 0 {
		checks = append(checks, check{Name: "connectors", OK: true, Detail: "none configured"})
	}
	return checks
}

// envCheck resolves one *_env variable by name. Unset and empty are the
// same failure, matching internal/config's resolveEnv: an empty variable
// is an operator error, never a reason to fall back to an inline secret.
func envCheck(name, varName string) check {
	if v, ok := os.LookupEnv(varName); ok && v != "" {
		return check{Name: name, OK: true, Detail: fmt.Sprintf("%s resolves", varName)}
	}
	return check{Name: name, OK: false, Detail: fmt.Sprintf("%s is not set (or empty)", varName)}
}

// denyfileCheck verifies the directory the deny map rewrites into exists.
// The file itself is created lazily on the first ban; its absence is
// normal, a missing directory is not.
func denyfileCheck(path string) check {
	dir := filepath.Dir(path)
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return check{Name: "connector denyfile", OK: true, Detail: fmt.Sprintf("directory %s present", dir)}
	}
	return check{Name: "connector denyfile", OK: false, Detail: fmt.Sprintf("directory %s missing", dir)}
}

// killSwitchCheck reports the enforcement kill switch (I9): a boolean in
// the config, engaged or disarmed. Engaged is a deliberate operator state,
// not a failed check — doctor reports it loudly in the detail so it cannot
// be missed, but the exit code stays driven by real failures.
func killSwitchCheck(cfg *config.Config) check {
	if cfg.Enforcement.KillSwitch {
		return check{Name: "kill switch", OK: true,
			Detail: "ENGAGED: enforcement drops to observe until it is flipped back (I9)"}
	}
	return check{Name: "kill switch", OK: true, Detail: "disarmed"}
}

// renderChecks prints the human table: aligned check, result and detail
// columns (tabwriter, two spaces of padding — the same layout discipline
// as the fault-injection lab's results table).
func renderChecks(checks []check) {
	w := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "CHECK\tRESULT\tDETAIL")
	for _, c := range checks {
		result := "ok"
		if !c.OK {
			result = "FAIL"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", c.Name, result, c.Detail)
	}
	w.Flush()
	fmt.Fprintf(stdout, "doctor: %d checks, %d failed\n", len(checks), countFailed(checks))
}

// countFailed totals the failing checks for the summary lines.
func countFailed(checks []check) int {
	n := 0
	for _, c := range checks {
		if !c.OK {
			n++
		}
	}
	return n
}
