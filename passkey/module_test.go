package passkey_test

import (
	"errors"
	"testing"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/passkey"
)

func newPasskeyTestService(t *testing.T) *authkit.Service {
	t.Helper()
	svc, err := authkit.New(authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}, authkittest.NewPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestNewTwiceIsErrAttached(t *testing.T) {
	svc := newPasskeyTestService(t)
	first, err := passkey.New(svc, passkey.Rules{})
	if err != nil || first == nil {
		t.Fatalf("first New = %v, %v; want a module and nil", first, err)
	}
	second, err := passkey.New(svc, passkey.Rules{})
	if second != nil || !errors.Is(err, authkit.ErrAttached) {
		t.Fatalf("second New = %v, %v; want nil and ErrAttached", second, err)
	}
}

func TestARefusedNewLeavesThePasskeyNameFree(t *testing.T) {
	svc := newPasskeyTestService(t)
	bad := passkey.Rules{Origins: map[authkit.Audience][]string{"staff": {"https://tasks.example.invalid"}}}
	m, err := passkey.New(svc, bad)
	if m != nil {
		t.Fatalf("refused New returned a module")
	}
	if err == nil || err.Error() != "authkit: Config.Passkeys.Origins needs Config.Passkeys.RPID" {
		t.Fatalf("refused New error = %v; want the Origins refusal", err)
	}
	if _, err := passkey.New(svc, passkey.Rules{}); err != nil {
		t.Fatalf("New after a refusal = %v; want nil (the name stays free)", err)
	}
}
