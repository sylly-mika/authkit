package token_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/sylly-mika/authkit/internal/token"
)

func TestNewIs32BytesOfRandAsBase64URL(t *testing.T) {
	seed := bytes.Repeat([]byte{0xfb}, 32)
	raw, hash, err := token.New(bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	if want := base64.RawURLEncoding.EncodeToString(seed); raw != want || len(raw) != 43 {
		t.Fatalf("raw = %q, want %q (spec §8.8)", raw, want)
	}
	if sum := sha256.Sum256([]byte(raw)); !bytes.Equal(hash, sum[:]) {
		t.Fatal("the stored form is not sha256 of the token's text")
	}
	if _, _, err := token.New(bytes.NewReader(seed[:31])); err == nil {
		t.Fatal("a short read made a token")
	}
}

func TestIDComesFromTheInjectedRand(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 16)
	a, err1 := token.ID(bytes.NewReader(seed))
	b, err2 := token.ID(bytes.NewReader(seed))
	if err1 != nil || err2 != nil || a != b || a.Version() != 4 {
		t.Fatalf("ID = %s, %s (%v, %v): want the same v4 uuid from the same bytes", a, b, err1, err2)
	}
}
