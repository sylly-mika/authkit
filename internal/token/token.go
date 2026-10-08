// Package token makes authkit's opaque tokens and row ids from the injected
// randomness (spec §8.8): 32 bytes as base64url, stored only as sha256.
package token

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/google/uuid"
)

func New(r io.Reader) (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", nil, fmt.Errorf("authkit: random token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, Hash(raw), nil
}

// Hash is the stored form of a raw token: sha256 of its text as it travels.
func Hash(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// ID is a v4 uuid read from r, so inserts need no RETURNING.
func ID(r io.Reader) (uuid.UUID, error) {
	return uuid.NewRandomFromReader(r)
}
