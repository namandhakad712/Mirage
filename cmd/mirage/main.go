// Command mirage is Mirage Core's operator surface: one binary, six
// subcommands covering the deployment lifecycle —
//
//	mirage init      write a minimal validated starter configuration
//	mirage doctor    pre-flight health check (non-mutating)
//	mirage posture   configuration posture report (non-mutating)
//	mirage replay    replay the golden vectors through the full decision path
//	mirage serve     run the edge adapter: reverse proxy + dashboard
//	mirage version   print build, spec and protocol versions
//
// The CLI is the operator's window onto the boot-time half of the
// invariants: configuration fails closed at boot (internal/config rejects
// what it cannot strictly decode) while requests fail open at runtime (I1),
// enforcement is opt-in per site (I9), and the dashboard never leaves
// loopback unauthenticated. Every subcommand shares the same exit contract
// — 0 success, 1 failure or mismatch, 2 usage error — and the same output
// discipline: reports on stdout, errors on stderr, plain text only, no
// colors, no decorations (machine-friendly by default).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// Exit codes, identical for every subcommand so scripts can branch on them
// without per-command tables.
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

// stdout and stderr are the command outputs. They are package variables
// solely so tests can capture them; the test suite runs sequentially, so
// the swap is never raced.
var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run dispatches a subcommand and returns its exit code. It is the seam the
// tests drive: swapping the writer variables exercises any subcommand
// without spawning processes.
func run(args []string) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version":
		return cmdVersion(rest)
	case "init":
		return cmdInit(rest)
	case "doctor":
		return cmdDoctor(rest)
	case "posture":
		return cmdPosture(rest)
	case "replay":
		return cmdReplay(rest)
	case "serve":
		return cmdServe(rest)
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "mirage: unknown subcommand %q\n\n", cmd)
		usage(stderr)
		return exitUsage
	}
}

// usage prints the top-level help. Each subcommand prints its own help via
// its flag set; this lists only the dispatch surface.
func usage(w io.Writer) {
	fmt.Fprint(w, `usage: mirage <subcommand> [flags]

Mirage deception-layer defense — operator CLI.

Subcommands:
  init      write a minimal validated starter configuration
  doctor    pre-flight health check (non-mutating)
  posture   configuration posture report (non-mutating)
  replay    replay golden vectors through the full decision path
  serve     run the edge adapter (reverse proxy + dashboard)
  version   print build, spec and protocol versions

Run "mirage <subcommand> -h" for flags.
Exit codes: 0 success, 1 failure or mismatch, 2 usage error.
`)
}

// newFlagSet builds a subcommand's flag set. Parse errors print to stderr
// (flag's own message plus the usage text) and the caller returns exitUsage;
// an explicit -h returns flag.ErrHelp, which the caller answers with the
// same usage text on stdout and exit 0 — help the operator asked for is a
// success, not an error.
func newFlagSet(name, line string) (fs *flag.FlagSet, help func(io.Writer)) {
	fs = flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	help = func(w io.Writer) {
		fs.SetOutput(w)
		fmt.Fprintf(w, "usage: %s\n\n", line)
		fs.PrintDefaults()
		fs.SetOutput(stderr)
	}
	fs.Usage = func() { help(stderr) }
	return fs, help
}

// parseFlags is the shared parse step: it returns the flag set on success,
// (nil, exitOK) for -h (help already printed to stdout), and (nil,
// exitUsage) for a parse error (flag has already printed both the error and
// the usage text to stderr). Every subcommand starts with it so the -h and
// usage-error behavior cannot drift between them.
func parseFlags(fs *flag.FlagSet, help func(io.Writer), args []string) (*flag.FlagSet, int) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			help(stdout)
			return nil, exitOK
		}
		return nil, exitUsage
	}
	return fs, exitOK
}

// extraArgs rejects leftover positional arguments; no subcommand accepts
// any, so this is a uniform usage error with the offending value named.
func extraArgs(fs *flag.FlagSet) int {
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "mirage %s: unexpected argument %q\n", fs.Name(), fs.Arg(0))
		return exitUsage
	}
	return exitOK
}
