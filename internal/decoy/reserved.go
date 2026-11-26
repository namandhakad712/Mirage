package decoy

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
)

// hostishRe is a deliberately permissive hostname shape (dot-separated
// labels of letters, digits and hyphens). The reserved-hosts file ships
// with the project, so this only needs to catch typos and wrong files, not
// to validate arbitrary DNS names.
var hostishRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$`)

// Reserved is the parsed form of data/reserved-hosts.txt (I14): the RFC
// 2606 hostnames and RFC 5737 documentation networks that every decoy host
// and address must come from, so a decoy can never name, link or point at
// a real third party.
type Reserved struct {
	// ReservedHosts holds every hostname entry of the file in one map.
	// Bare names (example.com, example.net, example.org) are exact names
	// and also cover their subdomains; wildcard lines (*.test, *.invalid,
	// *.example) are stored with the leading dot (".test") and match any
	// host ending in that suffix. One map because the file lists them as
	// one list; IsReservedHost applies the right rule by key shape.
	ReservedHosts map[string]struct{}

	// ReservedCIDRs are the RFC 5737 documentation networks
	// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
	ReservedCIDRs []netip.Prefix
}

// LoadReserved reads and parses a reserved-hosts file. Lines are "#"
// comments, hostnames, "*.suffix" wildcards or CIDRs; anything else is an
// error rather than a silent skip, because a mis-parsed reserved list
// would let real hosts into decoy bodies (I14). A file without hostnames
// or without networks is rejected: the shipped file always carries both,
// so their absence means the wrong file was loaded.
func LoadReserved(path string) (Reserved, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Reserved{}, fmt.Errorf("reserved hosts %s: %w", path, err)
	}
	r := Reserved{ReservedHosts: make(map[string]struct{})}
	for i, line := range strings.Split(string(raw), "\n") {
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "*."):
			// "*.test" -> suffix ".test": matches db.test, a.b.test, …
			suffix := strings.ToLower(line[1:])
			if !hostishRe.MatchString(suffix[1:]) {
				return Reserved{}, fmt.Errorf("reserved hosts %s:%d: bad wildcard %q", path, i+1, line)
			}
			r.ReservedHosts[suffix] = struct{}{}
		case strings.Contains(line, "/"):
			p, err := netip.ParsePrefix(line)
			if err != nil {
				return Reserved{}, fmt.Errorf("reserved hosts %s:%d: %w", path, i+1, err)
			}
			r.ReservedCIDRs = append(r.ReservedCIDRs, p)
		default:
			host := strings.ToLower(line)
			if !hostishRe.MatchString(host) {
				return Reserved{}, fmt.Errorf("reserved hosts %s:%d: bad hostname %q", path, i+1, line)
			}
			r.ReservedHosts[host] = struct{}{}
		}
	}
	if len(r.ReservedHosts) == 0 || len(r.ReservedCIDRs) == 0 {
		return Reserved{}, fmt.Errorf("reserved hosts %s: no hostnames or no networks found", path)
	}
	return r, nil
}

// IsReservedHost reports whether host is safe to name in a decoy (I14).
// The host may carry a trailing ":port" and any case; matching is
// case-insensitive. A host is reserved when it
//
//   - equals a reserved name (example.com), or is a subdomain of one
//     (staging.example.com — the catalog's APP_URL, still inside IANA's
//     example domain), or
//   - ends with a reserved wildcard suffix (db.test, a.b.invalid).
//
// A reserved label in the middle of a name is NOT a reservation:
// foo.test.evil.com is a subdomain of evil.com, not a .test host, and
// must fail this check.
func (r Reserved) IsReservedHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".") // tolerate an FQDN root dot
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = strings.TrimSuffix(h, ".")
	}
	if host == "" {
		return false
	}
	if _, ok := r.ReservedHosts[host]; ok {
		return true
	}
	for name := range r.ReservedHosts {
		if strings.HasPrefix(name, ".") {
			// Wildcard entry (".test"): any host under the suffix.
			if strings.HasSuffix(host, name) {
				return true
			}
			continue
		}
		// Exact name (example.com): its subdomains are reserved too.
		if strings.HasSuffix(host, "."+name) {
			return true
		}
	}
	return false
}

// IsReservedIP reports whether addr falls inside one of the RFC 5737
// documentation networks (I14). IPv4-mapped IPv6 addresses are unmapped
// first so ::ffff:192.0.2.1 is recognised as 192.0.2.1.
func (r Reserved) IsReservedIP(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range r.ReservedCIDRs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
