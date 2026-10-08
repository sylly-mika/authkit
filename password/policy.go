package password

import (
	"fmt"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Policy bounds a new password by its length in characters (spec §8.7).
type Policy struct {
	MinRunes int
	MaxRunes int
}

// DefaultPolicy is the spec's 10 to 256 characters.
var DefaultPolicy = Policy{MinRunes: 10, MaxRunes: 256}

// PolicyError is the refusal of a password the policy does not admit.
type PolicyError struct {
	MinRunes int
	MaxRunes int
	TooLong  bool
}

func (e PolicyError) Error() string {
	if e.TooLong {
		return fmt.Sprintf("authkit: a password has at most %d characters", e.MaxRunes)
	}
	return fmt.Sprintf("authkit: a password has at least %d characters", e.MinRunes)
}

// Check refuses, as a PolicyError, a password whose NFC form is shorter or
// longer than the policy allows.
func (p Policy) Check(pw string) error {
	switch n := utf8.RuneCountInString(norm.NFC.String(pw)); {
	case n < p.MinRunes:
		return PolicyError{MinRunes: p.MinRunes, MaxRunes: p.MaxRunes}
	case n > p.MaxRunes:
		return PolicyError{MinRunes: p.MinRunes, MaxRunes: p.MaxRunes, TooLong: true}
	}
	return nil
}
