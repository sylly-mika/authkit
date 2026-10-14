package factor_test

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sylly-mika/authkit/internal/factor"
)

var recoveryPattern = regexp.MustCompile(`^[0-9a-hjkmnp-tv-z]{5}-[0-9a-hjkmnp-tv-z]{5}$`)
var emailPattern = regexp.MustCompile(`^[0-9]{6}$`)

func TestNewRecoveryCodesUseTheCrockfordAlphabet(t *testing.T) {
	codes, err := factor.NewRecoveryCodes(bytes.NewReader(seq(0, 100)), 10)
	if err != nil {
		t.Fatalf("NewRecoveryCodes: %v", err)
	}
	want := []string{"01234-56789", "abcde-fghjk", "mnpqr-stvwx", "yz012-34567"}
	if len(codes) != 10 {
		t.Fatalf("got %d codes, want 10", len(codes))
	}
	for i, w := range want {
		if codes[i] != w {
			t.Errorf("code %d = <redacted>, want %s", i, w)
		}
	}
	for i, c := range codes {
		if !recoveryPattern.MatchString(c) {
			t.Errorf("code %d = <redacted> does not match the Crockford format", i)
		}
	}
	random, err := factor.NewRecoveryCodes(rand.Reader, 10)
	if err != nil || len(random) != 10 {
		t.Fatalf("NewRecoveryCodes(rand.Reader, 10) = %d codes, %v, want 10, nil", len(random), err)
	}
	seen := map[string]bool{}
	for i, c := range random {
		if !recoveryPattern.MatchString(c) {
			t.Errorf("random code %d = <redacted> does not match the Crockford format", i)
		}
		if seen[c] {
			t.Errorf("random code %d is a duplicate: <redacted>", i)
		}
		seen[c] = true
	}
}

func TestNewRecoveryCodesDrawAgainOnADuplicate(t *testing.T) {
	stream := append(make([]byte, 20), seq(1, 90)...)
	codes, err := factor.NewRecoveryCodes(bytes.NewReader(stream), 10)
	if err != nil {
		t.Fatalf("NewRecoveryCodes: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("got %d codes, want 10", len(codes))
	}
	if codes[0] != "00000-00000" {
		t.Errorf("codes[0] = <redacted>, want 00000-00000")
	}
	if codes[1] != "12345-6789a" {
		t.Errorf("codes[1] = <redacted>, want 12345-6789a (the repeat is dropped)")
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Errorf("duplicate code: <redacted>")
		}
		seen[c] = true
	}
	if codes, err := factor.NewRecoveryCodes(bytes.NewReader(stream[:109]), 10); codes != nil || err == nil {
		t.Errorf("NewRecoveryCodes on 109 bytes = %d codes, %v, want nil and an error", len(codes), err)
	}
	if codes, err := factor.NewRecoveryCodes(bytes.NewReader(stream), 0); codes != nil || err == nil || err.Error() != "authkit: recovery code count must be positive" {
		t.Errorf("NewRecoveryCodes with n = 0 = %d codes, %v, want nil and the positive-count error", len(codes), err)
	}
}

func TestNormalizeCodeMatchesTheWaysAUserTypesIt(t *testing.T) {
	k := factor.DeriveKeys(master)
	want := factor.HashCode(k.RecoveryKey, ada, "recovery", "abcdefghjk")
	for _, typed := range []string{"ABCDE-FGHJK", " abcde fghjk ", "abc-de fg-hjk", "abcdefghjk"} {
		got := factor.HashCode(k.RecoveryKey, ada, "recovery", factor.NormalizeCode(typed))
		if !bytes.Equal(got, want) {
			t.Errorf("NormalizeCode(%q) hashes differently from abcdefghjk: <redacted>", typed)
		}
	}
}

func TestNewEmailCodeIsUniformSixDigits(t *testing.T) {
	for _, c := range []struct {
		name   string
		stream []byte
		want   string
	}{
		{"4294000000 is dropped", []byte{0xFF, 0xF1, 0x3D, 0x80, 0xFF, 0xF1, 0x3D, 0x7F}, "999999"},
		{"4294967295 is dropped", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x07}, "000007"},
	} {
		got, err := factor.NewEmailCode(bytes.NewReader(c.stream))
		if err != nil || got != c.want {
			t.Errorf("%s: NewEmailCode = <redacted>, %v, want %s", c.name, err, c.want)
		}
	}
	for i := 0; i < 200; i++ {
		got, err := factor.NewEmailCode(rand.Reader)
		if err != nil || !emailPattern.MatchString(got) {
			t.Fatalf("NewEmailCode(rand.Reader) = <redacted>, %v, want six digits", err)
		}
	}
	if got, err := factor.NewEmailCode(bytes.NewReader([]byte{1, 2, 3})); got != "" || err == nil {
		t.Errorf("NewEmailCode on 3 bytes = <redacted>, %v, want an empty string and an error", err)
	}
}

func TestFactorSourcesCompareInConstantTime(t *testing.T) {
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			for _, banned := range []string{"bytes.Equal", "time.Now", "math/rand"} {
				if strings.Contains(line, banned) {
					t.Errorf("%s:%d uses %s; codes and hashes compare in constant time and time and randomness are injected", name, i+1, banned)
				}
			}
			if comparesSecret(line) {
				t.Errorf("%s:%d compares a code, hash, secret or token with ==; use subtle.ConstantTimeCompare or hmac.Equal", name, i+1)
			}
		}
	}
}

func comparesSecret(line string) bool {
	if !strings.Contains(line, "==") || strings.Contains(line, "== nil") {
		return false
	}
	lower := strings.ToLower(line)
	for _, word := range []string{"code", "hash", "secret", "token"} {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}
