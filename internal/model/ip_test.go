package model

import (
	"net/netip"
	"testing"
)

func mustPrefixes(t *testing.T, items ...string) []netip.Prefix {
	t.Helper()
	p, err := ParsePrefixes(items)
	if err != nil {
		t.Fatalf("ParsePrefixes: %v", err)
	}
	return p
}

func TestClientIPUntrustedPeerIgnoresHeader(t *testing.T) {
	// I6: a spoofed X-Forwarded-For from an untrusted peer must be ignored.
	trusted := mustPrefixes(t, "10.0.0.0/8")
	got := ClientIPFrom("203.0.113.99:44321", "1.2.3.4, 5.6.7.8", trusted)
	if got != "203.0.113.99" {
		t.Fatalf("got %q, want socket IP 203.0.113.99", got)
	}
}

func TestClientIPTrustedWalk(t *testing.T) {
	trusted := mustPrefixes(t, "10.0.0.0/8", "10.1.2.3")
	cases := []struct {
		name, remote, xff, want string
	}{
		{"single trusted hop", "10.0.0.9:1000", "203.0.113.7", "203.0.113.7"},
		{"chain two trusted", "10.1.2.3:80", "203.0.113.7, 10.0.0.9", "203.0.113.7"},
		{"untrusted in middle", "10.0.0.9:80", "198.51.100.5, 10.1.2.3", "198.51.100.5"},
		{"all trusted falls back to peer", "10.0.0.9:80", "10.9.9.9, 10.1.2.3", "10.0.0.9"},
		{"empty header", "10.0.0.9:80", "", "10.0.0.9"},
		{"garbage right wins", "10.0.0.9:80", "203.0.113.7, not-an-ip", "203.0.113.7"},
		{"garbage only falls back to peer", "10.0.0.9:80", "bogus, junk", "10.0.0.9"},
		{"spoof attempt blocked", "10.0.0.9:80", "8.8.8.8, 6.6.6.6", "6.6.6.6"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClientIPFrom(c.remote, c.xff, trusted); got != c.want {
				t.Fatalf("ClientIPFrom(%q, %q) = %q, want %q", c.remote, c.xff, got, c.want)
			}
		})
	}
}

func TestClientIPv6(t *testing.T) {
	trusted := mustPrefixes(t, "2001:db8::/32")
	got := ClientIPFrom("[2001:db8::1]:9999", "2001:1::42", trusted)
	if got != "2001:1::42" {
		t.Fatalf("got %q, want 2001:1::42", got)
	}
}

func TestParsePrefixes(t *testing.T) {
	if _, err := ParsePrefixes([]string{"10.0.0.0/8", "bogus"}); err == nil {
		t.Fatal("want error for bogus entry")
	}
	p, err := ParsePrefixes([]string{"192.0.2.10", "198.51.100.0/24"})
	if err != nil {
		t.Fatalf("ParsePrefixes: %v", err)
	}
	if len(p) != 2 {
		t.Fatalf("len = %d, want 2", len(p))
	}
	if p[0].Bits() != 32 || p[0].Addr().String() != "192.0.2.10" {
		t.Fatalf("bare IP not normalized: %v", p[0])
	}
}

func TestNeverScoredAndNeverBanned(t *testing.T) {
	owner := mustPrefixes(t, "192.0.2.50/32")
	if !NeverScored("127.0.0.1", nil) {
		t.Fatal("loopback must be never-scored")
	}
	if !NeverScored("192.0.2.50", owner) {
		t.Fatal("owner IP must be never-scored")
	}
	if NeverScored("203.0.113.7", owner) {
		t.Fatal("attacker IP must be scorable")
	}
	if !IsNeverBanned("10.1.2.3", nil) {
		t.Fatal("private range must be never-banned")
	}
	if !IsNeverBanned("100.64.0.7", nil) {
		t.Fatal("CGNAT range must be never-banned")
	}
	if IsNeverBanned("203.0.113.7", nil) {
		t.Fatal("attacker IP must be bannable")
	}
	// The owner's ranges apply to bans too.
	if !IsNeverBanned("192.0.2.50", owner) {
		t.Fatal("owner IP must be never-banned")
	}
}
