package model

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ClientIPFrom resolves the real client IP (I6, spec/SIGNALS.md section 2).
//
// Rules:
//   - The immediate peer (remoteAddr) is the client unless it is a trusted
//     proxy.
//   - For trusted peers, X-Forwarded-For is walked right-to-left: trusted
//     proxy addresses are skipped, and the first non-trusted address is the
//     client.
//   - If every hop is trusted, the peer itself is the client.
//   - Malformed entries are skipped; if no valid non-trusted address
//     remains in the chain, the peer is the client.
//
// Callers must pass the result of net/http's RemoteAddr host part (strip
// the port with net.SplitHostPort or RequestIP) and the forwarding header
// only from the immediate peer.
func ClientIPFrom(remoteAddr, xForwardedFor string, trustedProxies []netip.Prefix) string {
	peer := hostOnly(remoteAddr)
	if peer == "" {
		return ""
	}
	peerIP, err := netip.ParseAddr(peer)
	if err != nil {
		return peer // unparseable: treat the literal as opaque identity
	}
	if !containsIP(trustedProxies, peerIP) {
		return peer
	}

	hops := splitForwarded(xForwardedFor)
	// Walk right-to-left: the first valid non-trusted address is the client.
	for i := len(hops) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(hops[i])
		if err != nil {
			continue // skip malformed entries
		}
		if !containsIP(trustedProxies, ip) {
			return hops[i]
		}
	}
	// Only trusted proxies (or garbage) in the chain: the peer is the client.
	return peer
}

// RequestIP extracts the host part of an http.Request RemoteAddr.
func RequestIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return hostOnly(remoteAddr)
	}
	return host
}

// ParsePrefixes parses CIDR strings, ignoring invalid entries and
// normalizing bare IPs to /32 or /128.
func ParsePrefixes(items []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range items {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("invalid address %q: %w", s, err)
			}
			out = append(out, netip.PrefixFrom(ip.Unmap(), ip.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %q: %w", s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// NeverScored reports whether an IP must never be scored or banned (I6,
// I15): loopback, link-local, the never-scored ranges from config, and
// shared/CGNAT ranges. Private ranges are never BANNED by default but may
// still be scored; use IsNeverBanned for the ban check.
func NeverScored(ip string, ownerRanges []netip.Prefix) bool {
	a, err := netip.ParseAddr(hostOnly(ip))
	if err != nil {
		return false
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return true
	}
	return containsIP(ownerRanges, a)
}

// IsNeverBanned reports whether an IP is excluded from bans (I15):
// private and shared (CGNAT 100.64.0.0/10) ranges, plus everything
// NeverScored covers.
func IsNeverBanned(ip string, ownerRanges []netip.Prefix) bool {
	a, err := netip.ParseAddr(hostOnly(ip))
	if err != nil {
		return false
	}
	a = a.Unmap()
	if NeverScored(ip, ownerRanges) {
		return true
	}
	if a.IsPrivate() {
		return true
	}
	if a.Is4() {
		if cgnat.Contains(a) {
			return true
		}
	}
	return false
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func containsIP(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return strings.TrimSpace(addr)
}

func splitForwarded(header string) []string {
	if header == "" {
		return nil
	}
	parts := strings.Split(header, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// Strip any port appended to an address (non-standard but seen).
		if i := strings.LastIndexByte(p, ':'); i > 0 && !strings.Contains(p[i:], "]") {
			if _, err := netip.ParseAddr(p[:i]); err == nil {
				p = p[:i]
			}
		}
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
