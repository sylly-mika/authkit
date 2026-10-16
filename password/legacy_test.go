package password_test

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/sylly-mika/authkit/password"
	"golang.org/x/crypto/bcrypt"
)

func bcryptOf(t *testing.T, pw string, cost int) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func TestBcryptOwnsItsFormatsAndVerifiesRawBytes(t *testing.T) {
	l := password.Bcrypt()
	h := bcryptOf(t, "correct horse", 4)
	nfd := "pārole ar čūsku"
	hn := bcryptOf(t, nfd, 4)
	argon, err := password.Encode(cheap, rand.Reader, "x")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []string{h, "$2b$" + h[4:], "$2y$" + h[4:]} {
		if !l.Owns(e) {
			t.Error("Owns is false for a bcrypt hash of a $2a$, $2b$ or $2y$ format")
		}
	}
	for _, e := range []string{argon, "", "$2x$" + h[4:]} {
		if l.Owns(e) {
			t.Error("Owns is true for a string that is not a bcrypt hash")
		}
	}
	if ok, err := l.Verify(h, "correct horse"); !ok || err != nil {
		t.Errorf("Verify of the right password = %v, %v; want true, nil", ok, err)
	}
	if ok, err := l.Verify(h, "correct horsE"); ok || err != nil {
		t.Errorf("Verify of a wrong password = %v, %v; want false, nil", ok, err)
	}
	if ok, err := l.Verify("$2y$"+h[4:], "correct horse"); !ok || err != nil {
		t.Errorf("Verify of a $2y$ hash = %v, %v; want true, nil", ok, err)
	}
	if ok, err := l.Verify(hn, nfd); !ok || err != nil {
		t.Errorf("Verify of a non-ASCII password = %v, %v; want true, nil", ok, err)
	}
	if ok, err := l.Verify("$2a$04$short", "x"); ok || !errors.Is(err, password.ErrMalformed) {
		t.Errorf("Verify of a truncated hash = %v, %v; want false, ErrMalformed", ok, err)
	}
}
