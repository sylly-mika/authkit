package authkit

import (
	"strings"

	"golang.org/x/text/unicode/norm"

	"github.com/sylly-mika/authkit/internal/token"
)

// Normalize is the form a login is looked up and throttled under: without
// invalid UTF-8 or NUL, trimmed, Unicode NFC, lower case (spec §5.1). NFC runs
// again after lower-casing, so the result is NFC and Normalize is idempotent.
func Normalize(login string) string {
	return norm.NFC.String(strings.ToLower(norm.NFC.String(strings.TrimSpace(clean(login)))))
}

// clean drops what Postgres text cannot hold: invalid UTF-8 and NUL.
func clean(s string) string { return strings.ReplaceAll(strings.ToValidUTF8(s, ""), "\x00", "") }

// clean is the request metadata as auth_sessions and auth_events can store it.
func (m Meta) clean() Meta {
	m.IP, m.UserAgent = clean(m.IP), clean(m.UserAgent)
	return m
}

// HashToken is the stored form of a raw refresh or one-time token.
func HashToken(raw string) []byte { return token.Hash(raw) }

// maxLoginRunes bounds the login the sign-in log keeps and the throttle keys.
const maxLoginRunes = 254

// typedLogin is the login as the user typed it, as the sign-in log keeps it:
// valid UTF-8 without NUL, at most maxLoginRunes characters.
func typedLogin(login string) string {
	s := clean(login)
	if r := []rune(s); len(r) > maxLoginRunes {
		return string(r[:maxLoginRunes])
	}
	return s
}
