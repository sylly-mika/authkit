package bearer_test

import (
	"strings"
	"testing"

	"github.com/sylly-mika/authkit/transport/bearer"
)

func FuzzParse(f *testing.F) {
	good, _, err := codec(f).Mint(sub, sid, "staff", map[string]any{"role": "member"})
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{good, good + "x", "", "a.b.c", "eyJhbGciOiJub25lIn0.e30."} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		c, err := codec(t).Parse(token, "staff")
		if err == nil && (c.Subject != sub || c.SessionID != sid) {
			t.Fatalf("Parse accepted a token it did not mint: %q → %+v", token, c)
		}
	})
}

func FuzzFromHeader(f *testing.F) {
	for _, s := range []string{"Bearer x", "bearer  y", "", "Basic z", "Bearer\tx"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, h string) {
		tok, err := bearer.FromHeader(h)
		if err == nil && (tok == "" || !strings.HasSuffix(h, tok)) {
			t.Fatalf("FromHeader(%q) = %q", h, tok)
		}
	})
}
