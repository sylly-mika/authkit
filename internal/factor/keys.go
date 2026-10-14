// Package factor holds authkit's second-factor primitives: derived keys, sealed TOTP secrets, TOTP checks and the formats and hashes of recovery and email codes.
package factor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
)

const (
	nonceLen = 12
	tagLen   = 16
)

// Keys are the subkeys derived from SecondFactorRules.Key.
type Keys struct {
	SealKey     []byte
	EmailKey    []byte
	RecoveryKey []byte
}

// ErrSealBroken is returned when a sealed secret does not open for this key and principal.
var ErrSealBroken = errors.New("authkit: a sealed second-factor secret does not open")

// DeriveKeys derives the seal, email-code and recovery-code subkeys from key.
func DeriveKeys(key []byte) Keys {
	return Keys{
		SealKey:     subkey(key, "authkit totp seal"),
		EmailKey:    subkey(key, "authkit email code"),
		RecoveryKey: subkey(key, "authkit recovery code"),
	}
}

func subkey(key []byte, label string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(label))
	return m.Sum(nil)
}

func (k Keys) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(k.SealKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts secret for principalID with a nonce read from r.
func (k Keys) Seal(r io.Reader, secret []byte, principalID uuid.UUID) ([]byte, error) {
	a, err := k.aead()
	if err != nil {
		return nil, fmt.Errorf("authkit: seal cipher: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, fmt.Errorf("authkit: random seal nonce: %w", err)
	}
	return a.Seal(nonce, nonce, secret, principalID[:]), nil
}

// Open decrypts what Seal made for the same principalID.
func (k Keys) Open(sealed []byte, principalID uuid.UUID) ([]byte, error) {
	if len(sealed) < nonceLen+tagLen {
		return nil, ErrSealBroken
	}
	a, err := k.aead()
	if err != nil {
		return nil, ErrSealBroken
	}
	secret, err := a.Open(nil, sealed[:nonceLen], sealed[nonceLen:], principalID[:])
	if err != nil {
		return nil, ErrSealBroken
	}
	return secret, nil
}

// HashCode is the stored form of a code: HMAC-SHA256 under key over principal, purpose and code.
// It hashes code exactly as given: recovery callers pass NormalizeCode(code) under the recovery key, email callers the six digits under the email key.
func HashCode(key []byte, principalID uuid.UUID, purpose, code string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(principalID.String() + "|" + purpose + "|" + code))
	return m.Sum(nil)
}
