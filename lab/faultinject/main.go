// Command faultinject runs the Mirage fault-injection lab from the
// terminal. It executes the same scenario registry `go test` executes
// (scenarios.go / scenarios_test.go) and prints a results table: name,
// invariants asserted, PASS/FAIL and duration. The exit code is 0 only
// when every selected scenario passed; a non-zero exit names the failing
// scenarios so CI output stays actionable.
//
// Flags:
//
//	-only <names>  run only these scenarios (repeatable, comma-separated)
//	-list         print the scenario matrix and exit
//	-v            print per-scenario progress logs
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

// onlyFlag collects the -only scenario filter. It is both repeatable and
// comma-separated, so "-only a,b -only c" selects a, b and c.
type onlyFlag []string

func (f *onlyFlag) String() string { return strings.Join(*f, ",") }

func (f *onlyFlag) Set(v string) error {
	for _, name := range strings.Split(v, ",") {
		if name = strings.TrimSpace(name); name != "" {
			*f = append(*f, name)
		}
	}
	return nil
}

// fatalSentinel is the panic cliT.Fatalf raises to bail out of a scenario
// early, mirroring how *testing.T's Fatalf ends a test. The runner recovers
// it, records the failure (already reported by Errorf) and moves on.
type fatalSentinel struct{}

// cliT adapts the scenario runner to the terminal: the same surface as
// *testing.T over the TestingT interface. Failures are collected under a
// mutex because scenarios report from worker goroutines (dashboard-storm).
type cliT struct {
	name    string
	verbose bool
	mu      sync.Mutex
	failed  bool
}

func (c *cliT) Helper() {}

func (c *cliT) Logf(format string, args ...any) {
	c.mu.Lock()
	v := c.verbose
	c.mu.Unlock()
	if v {
		fmt.Printf("[%s] %s\n", c.name, fmt.Sprintf(format, args...))
	}
}

func (c *cliT) Errorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	c.mu.Lock()
	c.failed = true
	c.mu.Unlock()
	fmt.Fprintf(os.Stderr, "FAIL %s: %s\n", c.name, msg)
}

// Error reports a pre-formatted failure.
func (c *cliT) Error(args ...any) { c.Errorf("%s", fmt.Sprint(args...)) }

// Fatal reports a pre-formatted failure and bails out like Fatalf.
func (c *cliT) Fatal(args ...any) { c.Fatalf("%s", fmt.Sprint(args...)) }

// Fatalf reports the failure and raises the sentinel; the deferred
// cleanups inside the scenario still run as the panic unwinds.
func (c *cliT) Fatalf(format string, args ...any) {
	c.Errorf(format, args...)
	panic(fatalSentinel{})
}

// selectScenarios resolves the requested names against the registry,
// preserving registry order. An unknown name is a usage error: the message
// lists the valid names so the fix is mechanical.
func selectScenarios(only []string) ([]Scenario, error) {
	if len(only) == 0 {
		return registry, nil
	}
	want := make(map[string]bool, len(only))
	for _, name := range only {
		want[name] = true
	}
	var out []Scenario
	for _, sc := range registry {
		if want[sc.Name] {
			out = append(out, sc)
		}
	}
	if len(out) != len(want) {
		var unknown []string
		for _, name := range only {
			found := false
			for _, sc := range registry {
				if sc.Name == name {
					found = true
				}
			}
			if !found {
				unknown = append(unknown, name)
			}
		}
		return nil, fmt.Errorf("unknown scenario(s): %s (known: %s)",
			strings.Join(unknown, ", "), strings.Join(scenarioNames(", "), ", "))
	}
	return out, nil
}

// scenarioNames lists the registry names joined by sep.
func scenarioNames(sep string) []string {
	names := make([]string, 0, len(registry))
	for _, sc := range registry {
		names = append(names, sc.Name)
	}
	return names
}

// runScenarios executes the selected scenarios in order, printing the
// results table as scenarios finish, and returns the failed names.
func runScenarios(selected []Scenario, verbose bool) []string {
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "SCENARIO\tINVARIANTS\tRESULT\tDURATION")
	var failed []string
	for _, sc := range selected {
		ct := &cliT{name: sc.Name, verbose: verbose}
		start := time.Now()
		func() {
			defer func() {
				if r := recover(); r != nil {
					if _, ok := r.(fatalSentinel); ok {
						return // already reported via Errorf
					}
					// A raw panic is a lab bug: fail the scenario, keep the
					// run going.
					ct.Errorf("scenario panicked: %v", r)
				}
			}()
			sc.Run(ct)
		}()
		result := "PASS"
		ct.mu.Lock()
		bad := ct.failed
		ct.mu.Unlock()
		if bad {
			result = "FAIL"
			failed = append(failed, sc.Name)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", sc.Name, strings.Join(sc.Invariants, " "), result, time.Since(start).Round(time.Millisecond))
		w.Flush()
	}
	return failed
}

// printMatrix prints the scenario matrix: name, invariants, description.
func printMatrix() {
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "SCENARIO\tINVARIANTS\tDESCRIPTION")
	for _, sc := range registry {
		fmt.Fprintf(w, "%s\t%s\t%s\n", sc.Name, strings.Join(sc.Invariants, " "), sc.Desc)
	}
	w.Flush()
}

func main() {
	var only onlyFlag
	list := flag.Bool("list", false, "print the scenario matrix and exit")
	verbose := flag.Bool("v", false, "print per-scenario progress logs")
	flag.Var(&only, "only", "run only these scenarios (repeatable, comma-separated)")
	flag.Parse()

	if *list {
		printMatrix()
		return
	}
	selected, err := selectScenarios([]string(only))
	if err != nil {
		fmt.Fprintf(os.Stderr, "faultinject: %v\n", err)
		os.Exit(2)
	}
	failed := runScenarios(selected, *verbose)
	if len(failed) > 0 {
		fmt.Fprintf(os.Stderr, "faultinject: %d/%d scenarios failed: %s\n",
			len(failed), len(selected), strings.Join(failed, ", "))
		os.Exit(1)
	}
	fmt.Printf("%d/%d scenarios passed\n", len(selected), len(selected))
}
