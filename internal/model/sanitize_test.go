package model

import (
	"strings"
	"testing"
)

func TestSanitizeStripsLogInjection(t *testing.T) {
	in := "clean\r\n2026-11-26 INJECTED fake log line"
	got := Sanitize(in, 0)
	if strings.ContainsAny(got, "\n\r") {
		t.Fatalf("newlines survived: %q", got)
	}
	// \r and \n each collapse to one space.
	if got != "clean  2026-11-26 INJECTED fake log line" {
		t.Fatalf("collapse mismatch: %q", got)
	}
}

func TestSanitizeNeutralizesAngleBrackets(t *testing.T) {
	got := Sanitize("<script>alert(1)</script>", 0)
	if strings.Contains(got, "<") || strings.Contains(got, ">") {
		t.Fatalf("raw angle brackets survived: %q", got)
	}
}

func TestSanitizeControlChars(t *testing.T) {
	got := Sanitize("a\x00\x1bb\tc", 0)
	if strings.ContainsRune(got, 0) || strings.ContainsRune(got, 0x1b) {
		t.Fatalf("control characters survived: %q", got)
	}
	// Control chars are dropped; tab becomes a space.
	if got != "ab c" {
		t.Fatalf("got %q", got)
	}
}

func TestSanitizeLengthCap(t *testing.T) {
	long := strings.Repeat("x", 5000)
	if got := Sanitize(long, 100); len(got) != 100 {
		t.Fatalf("capped length = %d, want 100", len(got))
	}
	if got := Sanitize(long, 0); len(got) != MaxSanitizedLen {
		t.Fatalf("default cap = %d, want %d", len(got), MaxSanitizedLen)
	}
}

func TestFailOpenShape(t *testing.T) {
	d := FailOpen()
	if d.Verdict != VerdictObserve || d.Action != ActionPass ||
		d.ReasonCode != FailOpenReason || d.RequestScore != 0 ||
		d.SessionKey != "" || d.BanTTLms != nil {
		t.Fatalf("fail-open decision malformed: %+v", d)
	}
	if d.ProtocolVersion != ProtocolVersion {
		t.Fatalf("protocol version %q", d.ProtocolVersion)
	}
}
