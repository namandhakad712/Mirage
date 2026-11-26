package model

import "testing"

func TestSessionKeyAnchor(t *testing.T) {
	// Anchor from spec/SIGNALS.md section 2 and the golden vectors.
	if got, want := SessionKey("203.0.113.7"), "fec52565aa0cf18f57d7cf5b3ac72850"; got != want {
		t.Fatalf("SessionKey(203.0.113.7) = %q, want %q", got, want)
	}
	if got, want := SessionKey("198.51.100.5"), "8959edf6884f2c2e223a9319e83a6982"; got != want {
		t.Fatalf("SessionKey(198.51.100.5) = %q, want %q", got, want)
	}
}

func TestSessionKeyLength(t *testing.T) {
	for _, ip := range []string{"1.2.3.4", "::1", "", "not-an-ip"} {
		k := SessionKey(ip)
		if len(k) != 32 {
			t.Fatalf("SessionKey(%q) length = %d, want 32", ip, len(k))
		}
	}
}
