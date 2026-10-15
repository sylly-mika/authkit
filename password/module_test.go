package password_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/password"
)

func newSvc(t *testing.T) *authkit.Service {
	t.Helper()
	svc, err := authkit.New(authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}, authkittest.NewPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestNewAttachesOnce(t *testing.T) {
	svc := newSvc(t)
	m, err := password.New(svc, password.Config{Hashing: cheap})
	if m == nil || err != nil {
		t.Fatalf("first New: module %v, err %v; want a module and no error", m, err)
	}
	again, err := password.New(svc, password.Config{Hashing: cheap})
	if again != nil || !errors.Is(err, authkit.ErrAttached) {
		t.Fatalf("second New: module %v, err %v; want nil and ErrAttached", again, err)
	}
	core, err := svc.Attach("password")
	if core != nil || !errors.Is(err, authkit.ErrAttached) {
		t.Fatalf(`Attach("password") after New: core %v, err %v; want nil and ErrAttached`, core, err)
	}
}

func TestNewRefusesBeforeItAttaches(t *testing.T) {
	svc := newSvc(t)
	bad, err := password.New(svc, password.Config{Hashing: cheap, Password: password.Policy{MinRunes: 20, MaxRunes: 10}})
	if bad != nil || err == nil || !strings.Contains(err.Error(), "Config.Password") {
		t.Fatalf("refused New: module %v, err %v; want nil and an error naming Config.Password", bad, err)
	}
	m, err := password.New(svc, password.Config{Hashing: cheap})
	if m == nil || err != nil {
		t.Fatalf("New after a refusal: module %v, err %v; want a module and no error", m, err)
	}
}
