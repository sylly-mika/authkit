package authkit

import (
	"strings"

	"golang.org/x/text/unicode/norm"

	"github.com/sylly-mika/authkit/internal/token"
)

// Normalize is the form a login is looked up and throttled under: without
// invalid UTF-8 or NUL, trimmed, Unicode NFC, lower case. NFC runs
// again after lower-casing, so the result is NFC and Normalize is idempotent.
func Normalize(login string) string {
	return norm.NFC.String(strings.ToLower(norm.NFC.String(strings.TrimSpace(clean(login)))))
}

// WHY: Postgres text cannot hold invalid UTF-8 or NUL, so clean drops both.
func clean(s string) string { return strings.ReplaceAll(strings.ToValidUTF8(s, ""), "\x00", "") }

// WHY: auth_sessions and auth_events can store the request metadata only once cleaned.
func (m Meta) clean() Meta {
	m.IP, m.UserAgent = clean(m.IP), clean(m.UserAgent)
	return m
}

// HashToken is the stored form of a raw refresh or one-time token.
func HashToken(raw string) []byte { return token.Hash(raw) }

const maxLoginRunes = 254

func typedLogin(login string) string {
	s := clean(login)
	if r := []rune(s); len(r) > maxLoginRunes {
		return string(r[:maxLoginRunes])
	}
	return s
}
