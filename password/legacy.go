package password

import (
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Legacy verifies a stored hash that is not argon2id, such as one imported from an older system.
type Legacy interface {
	// Owns reports whether encoded is in this verifier's format.
	Owns(encoded string) bool
	// Verify reports whether pw matches encoded: false and nil on a mismatch, ErrMalformed for a hash it will not check.
	Verify(encoded, pw string) (bool, error)
}

// WHY: a tampered row must not stall sign-in, so a stored bcrypt cost above this is malformed.
const maxBcryptCost = 14

type bcryptLegacy struct{}

// Bcrypt verifies $2a$, $2b$ and $2y$ hashes of cost 14 or less; a password over 72 bytes never matches.
func Bcrypt() Legacy { return bcryptLegacy{} }

func (bcryptLegacy) Owns(encoded string) bool {
	return strings.HasPrefix(encoded, "$2a$") || strings.HasPrefix(encoded, "$2b$") || strings.HasPrefix(encoded, "$2y$")
}

func (bcryptLegacy) Verify(encoded, pw string) (bool, error) {
	cost, err := bcrypt.Cost([]byte(encoded))
	if err != nil || cost > maxBcryptCost {
		return false, ErrMalformed
	}
	if len(pw) > 72 {
		return false, nil
	}
	err = bcrypt.CompareHashAndPassword([]byte(encoded), []byte(pw))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	if err != nil {
		return false, ErrMalformed
	}
	return true, nil
}
