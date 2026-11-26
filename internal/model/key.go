package model

import (
	"crypto/sha256"
	"encoding/hex"
)

// SessionKey derives the session key from the client IP: the first 32 hex
// characters of sha256(ip) (spec/SIGNALS.md section 2).
func SessionKey(ip string) string {
	sum := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(sum[:])[:32]
}
