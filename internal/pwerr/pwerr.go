// Package pwerr holds the password errors that authkit and authkit/password share.
package pwerr

import (
	"errors"
	"fmt"
)

// ErrBusy refuses a password hash when every slot is taken for longer than the wait.
var ErrBusy = errors.New("authkit: too many password hashes at once")

// PolicyError is the refusal of a password the policy does not admit.
type PolicyError struct {
	MinRunes int
	MaxRunes int
	TooLong  bool
}

// Error names the limit the password missed.
func (e PolicyError) Error() string {
	if e.TooLong {
		return fmt.Sprintf("authkit: a password has at most %d characters", e.MaxRunes)
	}
	return fmt.Sprintf("authkit: a password has at least %d characters", e.MinRunes)
}
