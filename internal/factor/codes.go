package factor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const recoveryAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"

// NewRecoveryCodes reads n distinct recovery codes, xxxxx-xxxxx in lower-case Crockford base32, from r.
func NewRecoveryCodes(r io.Reader, n int) ([]string, error) {
	if n <= 0 {
		return nil, errors.New("authkit: recovery code count must be positive")
	}
	codes := make([]string, 0, n)
	seen := map[string]bool{}
	b := make([]byte, 10)
	for len(codes) < n {
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, fmt.Errorf("authkit: random recovery code: %w", err)
		}
		code := make([]byte, 0, 11)
		for _, v := range b[:5] {
			code = append(code, recoveryAlphabet[v&31])
		}
		code = append(code, '-')
		for _, v := range b[5:] {
			code = append(code, recoveryAlphabet[v&31])
		}
		s := string(code)
		if seen[s] {
			continue
		}
		seen[s] = true
		codes = append(codes, s)
	}
	return codes, nil
}

// NormalizeCode removes spaces and hyphens from a typed code and lower-cases it.
func NormalizeCode(code string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(code))
}

// NewEmailCode reads a uniform 6-digit code, 000000 to 999999, from r.
func NewEmailCode(r io.Reader) (string, error) {
	b := make([]byte, 4)
	for {
		if _, err := io.ReadFull(r, b); err != nil {
			return "", fmt.Errorf("authkit: random email code: %w", err)
		}
		v := binary.BigEndian.Uint32(b)
		if v >= 4294000000 {
			continue
		}
		return fmt.Sprintf("%06d", v%1000000), nil
	}
}
