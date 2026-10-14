package factor_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/internal/factor"
)

var master = bytes.Repeat([]byte{0x11}, 32)
var otherMaster = bytes.Repeat([]byte{0x22}, 32)

var ada = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
var bob = uuid.MustParse("00000000-0000-4000-8000-00000000000b")

var rfcSecret = []byte("12345678901234567890")

func seq(from, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(from + i)
	}
	return b
}

func at(sec int64) time.Time { return time.Unix(sec, 0).UTC() }

func hmacOf(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

func TestDeriveKeysUsesTheThreeLabels(t *testing.T) {
	k := factor.DeriveKeys(master)
	for _, c := range []struct {
		name  string
		got   []byte
		label string
	}{
		{"SealKey", k.SealKey, "authkit totp seal"},
		{"EmailKey", k.EmailKey, "authkit email code"},
		{"RecoveryKey", k.RecoveryKey, "authkit recovery code"},
	} {
		want := hmacOf(master, c.label)
		if len(c.got) != 32 || !bytes.Equal(c.got, want) {
			t.Errorf("%s = <redacted>, want HMAC-SHA256 of its label, 32 bytes", c.name)
		}
	}
	if bytes.Equal(k.SealKey, k.EmailKey) || bytes.Equal(k.SealKey, k.RecoveryKey) || bytes.Equal(k.EmailKey, k.RecoveryKey) {
		t.Errorf("the three derived keys are not pairwise different: <redacted>")
	}
}

func TestSealOpensForTheSamePrincipal(t *testing.T) {
	k := factor.DeriveKeys(master)
	sealed, err := k.Seal(bytes.NewReader(seq(0, 12)), rfcSecret, ada)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed) != 48 {
		t.Errorf("len(sealed) = %d, want 48", len(sealed))
	}
	if bytes.Contains(sealed, rfcSecret) {
		t.Errorf("sealed blob contains the secret: <redacted>")
	}
	got, err := k.Open(sealed, ada)
	if err != nil || !bytes.Equal(got, rfcSecret) {
		t.Errorf("Open = <redacted>, %v, want the sealed secret, nil", err)
	}
}

func TestSealPrefixesANonceFromTheInjectedReader(t *testing.T) {
	k := factor.DeriveKeys(master)
	r := bytes.NewReader(seq(0, 24))
	first, err := k.Seal(r, rfcSecret, ada)
	if err != nil {
		t.Fatalf("first Seal: %v", err)
	}
	second, err := k.Seal(r, rfcSecret, ada)
	if err != nil {
		t.Fatalf("second Seal: %v", err)
	}
	if len(first) < 12 || !bytes.Equal(first[:12], seq(0, 12)) {
		t.Errorf("first nonce = <redacted>, want the first 12 bytes of the reader")
	}
	if len(second) < 12 || !bytes.Equal(second[:12], seq(12, 12)) {
		t.Errorf("second nonce = <redacted>, want the next 12 bytes of the reader")
	}
	if bytes.Equal(first, second) {
		t.Errorf("two seals of one secret are equal: <redacted>")
	}
	for _, s := range [][]byte{first, second} {
		if got, err := k.Open(s, ada); err != nil || !bytes.Equal(got, rfcSecret) {
			t.Errorf("Open of a seal = <redacted>, %v, want the secret", err)
		}
	}
	if blob, err := k.Seal(r, rfcSecret, ada); blob != nil || err == nil {
		t.Errorf("Seal on a drained reader = <redacted>, %v, want nil and an error", err)
	}
}

func TestOpenRefusesAnotherPrincipal(t *testing.T) {
	k := factor.DeriveKeys(master)
	sealed, err := k.Seal(bytes.NewReader(seq(0, 12)), rfcSecret, ada)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := k.Open(sealed, bob)
	if got != nil || !errors.Is(err, factor.ErrSealBroken) {
		t.Errorf("Open for another principal = <redacted>, %v, want nil and ErrSealBroken", err)
	}
	if err != nil && err.Error() != "authkit: a sealed second-factor secret does not open" {
		t.Errorf("Open error text = %q, want the ErrSealBroken text", err.Error())
	}
}

func TestOpenRefusesAnotherKey(t *testing.T) {
	sealed, err := factor.DeriveKeys(master).Seal(bytes.NewReader(seq(0, 12)), rfcSecret, ada)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := factor.DeriveKeys(otherMaster).Open(sealed, ada)
	if got != nil || !errors.Is(err, factor.ErrSealBroken) {
		t.Errorf("Open under another key = <redacted>, %v, want nil and ErrSealBroken", err)
	}
}

func TestOpenRefusesAChangedOrShortBlob(t *testing.T) {
	k := factor.DeriveKeys(master)
	good, err := k.Seal(bytes.NewReader(seq(0, 12)), rfcSecret, ada)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(good) < 28 {
		t.Fatalf("Seal made %d bytes, want at least 28", len(good))
	}
	flip := func(i int) []byte {
		b := bytes.Clone(good)
		b[i] ^= 0x01
		return b
	}
	for name, blob := range map[string][]byte{
		"nonce byte changed": flip(0),
		"tag byte changed":   flip(len(good) - 1),
		"27 bytes":           good[:27],
		"nil":                nil,
	} {
		got, err := k.Open(blob, ada)
		if got != nil || !errors.Is(err, factor.ErrSealBroken) {
			t.Errorf("%s: Open = <redacted>, %v, want nil and ErrSealBroken", name, err)
		}
	}
}

func TestHashCodeBindsKeyPrincipalPurposeAndCode(t *testing.T) {
	k := factor.DeriveKeys(master)
	h := factor.HashCode(k.RecoveryKey, ada, "recovery", "abcdefghjk")
	if want := hmacOf(k.RecoveryKey, ada.String()+"|recovery|abcdefghjk"); !bytes.Equal(h, want) {
		t.Errorf("HashCode = <redacted>, want HMAC-SHA256 of principal|purpose|code under the key")
	}
	if len(h) != 32 {
		t.Errorf("len(HashCode) = %d, want 32", len(h))
	}
	if again := factor.HashCode(k.RecoveryKey, ada, "recovery", "abcdefghjk"); !bytes.Equal(h, again) {
		t.Errorf("a second HashCode of the same input differs")
	}
	for name, other := range map[string][]byte{
		"another key":       factor.HashCode(k.EmailKey, ada, "recovery", "abcdefghjk"),
		"another principal": factor.HashCode(k.RecoveryKey, bob, "recovery", "abcdefghjk"),
		"another purpose":   factor.HashCode(k.RecoveryKey, ada, "sign_in", "abcdefghjk"),
		"another code":      factor.HashCode(k.RecoveryKey, ada, "recovery", "abcdefghjm"),
	} {
		if bytes.Equal(h, other) {
			t.Errorf("HashCode is the same for %s: <redacted>", name)
		}
	}
}
