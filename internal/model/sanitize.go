package model

import (
	"strings"
	"unicode"
)

// MaxSanitizedLen is the length cap applied to attacker-controlled strings
// before they reach logs, the dashboard or exports (I7).
const MaxSanitizedLen = 512

// Sanitize makes an attacker-controlled string safe for logs and HTML-ish
// contexts: strips control characters (including newlines, so log injection
// cannot forge entries), neutralizes angle brackets, collapses to a single
// line and caps the length. It does NOT make the string safe for raw SQL
// or shell interpolation — those must use parameter binding and exec
// respectively.
func Sanitize(s string, max int) string {
	if max <= 0 || max > MaxSanitizedLen {
		max = MaxSanitizedLen
	}
	var b strings.Builder
	b.Grow(min(len(s), max))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case unicode.IsControl(r):
			// dropped entirely
		case r == '<':
			b.WriteString("&lt;")
		case r == '>':
			b.WriteString("&gt;")
		default:
			b.WriteRune(r)
		}
		if b.Len() >= max {
			break
		}
	}
	out := b.String()
	if len(out) > max {
		out = out[:max]
	}
	return strings.TrimSpace(out)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
