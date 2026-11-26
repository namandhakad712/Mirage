package main

import (
	"fmt"

	"github.com/mirage-shield/mirage/internal/model"
)

// version and commit are stamped at build time by the Makefile's build
// target (-ldflags -X main.version=... -X main.commit=...). The defaults
// identify a bare `go build` of the package, so an unstamped binary still
// answers honestly instead of pretending to be a release.
var (
	version = "dev"
	commit  = "none"
)

// cmdVersion implements `mirage version`: two lines — the binary identity
// together with the spec and protocol versions this build speaks (the same
// model.SpecVersion / model.ProtocolVersion constants every decision
// carries on the wire, so an adapter can compare against its own handshake
// without running a request), then the commit it was built from.
func cmdVersion(args []string) int {
	fs, help := newFlagSet("mirage version", "mirage version")
	fs, code := parseFlags(fs, help, args)
	if fs == nil {
		return code
	}
	if code := extraArgs(fs); code != exitOK {
		return code
	}
	fmt.Fprintf(stdout, "mirage %s (spec %s, protocol %s)\ncommit %s\n",
		version, model.SpecVersion, model.ProtocolVersion, commit)
	return exitOK
}
