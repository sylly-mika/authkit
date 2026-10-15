package register_test

import (
	"errors"
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/password"
	"github.com/sylly-mika/authkit/register"
)

func newService(t *testing.T) (*authkit.Service, *password.Module) {
	t.Helper()
	svc, err := authkit.New(authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}, authkittest.NewPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	pw, err := password.New(svc, password.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return svc, pw
}

func TestNewRefuses(t *testing.T) {
	svc, pw := newService(t)
	ok := register.Rules{Create: stub}
	refused := []struct {
		name string
		pw   *password.Module
		r    register.Rules
		want string
	}{
		{"Create nil", pw, register.Rules{}, "register: Rules.Create is nil"},
		{"password nil", nil, ok, "register: the password module is nil"},
		{"TTL negative", pw, register.Rules{Create: stub, TTL: -1}, "register: Rules.TTL is negative"},
		{"MailCap negative", pw, register.Rules{Create: stub, MailCap: -1}, "register: Rules.MailCap is negative"},
		{"MailWindow negative", pw, register.Rules{Create: stub, MailWindow: -1}, "register: Rules.MailWindow is negative"},
		{"Floor negative", pw, register.Rules{Create: stub, Floor: -1}, "register: Rules.Floor is negative"},
		{"MailWindow over 24h", pw, register.Rules{Create: stub, MailWindow: 24*time.Hour + time.Nanosecond}, "register: Rules.MailWindow is longer than 24h"},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			m, err := register.New(svc, c.pw, c.r)
			if m != nil {
				t.Fatal("New returned a module for a refused rule set")
			}
			if err == nil || err.Error() != c.want {
				t.Fatalf("New error = %v; want %q", err, c.want)
			}
		})
	}

	m, err := register.New(svc, pw, ok)
	if err != nil {
		t.Fatalf("New after the refusals: %v", err)
	}
	if got := m.Floor(); got != 500*time.Millisecond {
		t.Fatalf("Floor() = %v; want 500ms", got)
	}
	if _, err := register.New(svc, pw, ok); !errors.Is(err, authkit.ErrAttached) {
		t.Fatalf("second New error = %v; want authkit.ErrAttached", err)
	}

	svc2, pw2 := newService(t)
	if _, err := register.New(svc2, pw2, register.Rules{Create: stub, MailWindow: 24 * time.Hour}); err != nil {
		t.Fatalf("New with a 24h window: %v", err)
	}
}
