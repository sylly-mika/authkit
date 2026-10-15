package register_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/password"
	"github.com/sylly-mika/authkit/register"
)

const aud authkit.Audience = "staff"

const (
	ada  = "ada@example.invalid"
	bob  = "bob@example.invalid"
	good = "a long enough password"
)

var meta = authkit.Meta{IP: "192.0.2.1", UserAgent: "authkit-test"}

type actFixture struct {
	*kittest.World
	m      *register.Module
	race   bool
	refuse error
	totp   bool
}

func newActFixture(t *testing.T, tweaks ...func(*kittest.Rules)) *actFixture {
	t.Helper()
	f := &actFixture{World: kittest.New(t, tweaks...)}
	m, err := register.New(f.Svc.Service, f.Svc.Password, register.Rules{Create: f.create})
	if err != nil {
		t.Fatal(err)
	}
	f.m = m
	return f
}

func (f *actFixture) create(ctx context.Context, q db.Querier, p register.Pending) (authkit.Principal, error) {
	if f.race {
		f.D.NewPrincipal(f.T, p.Email)
	}
	id := uuid.New()
	n, err := q.Exec(ctx, `INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING`, id, p.Email)
	if err != nil {
		return authkit.Principal{}, err
	}
	if n == 0 {
		return authkit.Principal{}, fmt.Errorf("users: %w", register.ErrAddressHeld)
	}
	if f.refuse != nil {
		f.P.Refuse(id, f.refuse)
	}
	if f.totp {
		if _, err := q.Exec(ctx, f.D.SQL(`INSERT INTO auth_second_factors (principal_id, kind, secret, created_at, confirmed_at) VALUES ($1, 'totp', '\x01'::bytea, $2, $2)`), id, f.Clock.Now()); err != nil {
			return authkit.Principal{}, err
		}
	}
	return authkit.Principal{ID: id, Login: p.Email}, nil
}

func (f *actFixture) start(email, payload string) uuid.UUID {
	f.T.Helper()
	var st register.Started
	err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		st, err = f.m.Start(f.Ctx, q, aud, email, json.RawMessage(payload))
		return err
	})
	if err != nil {
		f.T.Fatal(err)
	}
	if st.TokenID == nil {
		f.T.Fatal("Start gave no link")
	}
	return *st.TokenID
}

func (f *actFixture) mint(tokID uuid.UUID) string {
	f.T.Helper()
	var mail register.Mail
	err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		mail, err = f.m.Mint(f.Ctx, q, tokID)
		return err
	})
	if err != nil {
		f.T.Fatal(err)
	}
	return mail.Raw
}

func (f *actFixture) link(email string) (uuid.UUID, string) {
	f.T.Helper()
	tok := f.start(email, "{}")
	return tok, f.mint(tok)
}

func (f *actFixture) activate(raw, pw string) authkit.Result {
	f.T.Helper()
	return f.InAuth(func(q db.Querier) (authkit.Result, error) {
		return f.m.Activate(f.Ctx, q, raw, pw, meta)
	})
}

func (f *actFixture) unspent(tok uuid.UUID) int {
	return f.Count("SELECT count(*) FROM auth_tokens WHERE id = $1 AND used_at IS NULL", tok)
}

func (f *actFixture) users(email string) int {
	return f.Count("SELECT count(*) FROM users WHERE email = $1", email)
}

func (f *actFixture) pending(email string) int {
	return f.Count("SELECT count(*) FROM auth_registrations WHERE email = $1", email)
}

func (f *actFixture) creds() int {
	return f.Count("SELECT count(*) FROM auth_credentials")
}

func (f *actFixture) sessions() int {
	return f.Count("SELECT count(*) FROM auth_sessions")
}

func TestActivatePolicy(t *testing.T) {
	f := newActFixture(t, func(r *kittest.Rules) { r.Password.Password = password.Policy{MinRunes: 12, MaxRunes: 256} })
	tok, raw := f.link(ada)
	res := f.activate(raw, strings.Repeat("a", 11))
	var pe password.PolicyError
	if !errors.As(res.Refusal, &pe) || pe != (password.PolicyError{MinRunes: 12, MaxRunes: 256}) {
		t.Fatalf("refusal %v; want the policy error", res.Refusal)
	}
	if res.Session != nil {
		t.Fatal("a refused activation opened a session")
	}
	if n := f.unspent(tok); n != 1 {
		t.Fatalf("unspent link count %d; want 1", n)
	}
	if f.users(ada) != 0 || f.pending(ada) != 1 || f.creds() != 0 {
		t.Fatal("a refused activation created the principal or spent the registration")
	}
	res = f.activate(raw, strings.Repeat("a", 12))
	if res.Refusal != nil || res.Session == nil {
		t.Fatalf("second activation: refusal %v, session %v; want a session", res.Refusal, res.Session)
	}
	if f.users(ada) != 1 {
		t.Fatal("the second activation did not create the principal")
	}
}

func TestActivateBusy(t *testing.T) {
	f := newActFixture(t, func(r *kittest.Rules) { r.Password.HashConcurrency = 1 })
	tok, raw := f.link(ada)
	_, release, _, err := f.Svc.Password.AcquireHashSlot(f.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	res := f.activate(raw, good)
	release()
	if res.Refusal != password.ErrBusy {
		t.Fatalf("refusal %v; want ErrBusy", res.Refusal)
	}
	if f.unspent(tok) != 1 || f.users(ada) != 0 {
		t.Fatal("a busy hasher spent the link or created the principal")
	}
	if res := f.activate(raw, good); res.Session == nil {
		t.Fatalf("second activation: refusal %v; want a session", res.Refusal)
	}
}

func TestActivateNFC(t *testing.T) {
	f := newActFixture(t)
	_, raw := f.link(ada)
	if res := f.activate(raw, "café au lait"); res.Session == nil {
		t.Fatalf("activation: refusal %v; want a session", res.Refusal)
	}
	if res := f.Login(aud, ada, "café au lait"); res.Refusal != nil || res.Session == nil {
		t.Fatalf("composed password: refusal %v; want a session", res.Refusal)
	}
}

func TestActivateAfterRegistrationExpiry(t *testing.T) {
	f := newActFixture(t)
	tok := f.start(ada, "{}")
	f.Clock.Advance(time.Hour)
	raw := f.mint(tok)
	f.Clock.Advance(47*time.Hour + 30*time.Minute)
	res := f.activate(raw, good)
	if res.Refusal != authkit.ErrTokenUnknown || res.Session != nil {
		t.Fatalf("refusal %v, session %v; want an unknown link and no session", res.Refusal, res.Session)
	}
	if f.users(ada) != 0 || f.creds() != 0 || f.sessions() != 0 {
		t.Fatal("an expired registration created a principal, a credential or a session")
	}
}

func TestActivateHeld(t *testing.T) {
	f := newActFixture(t)
	tok, raw := f.link(ada)
	holder := f.User(ada, "")
	res := f.activate(raw, good)
	if res.Refusal != register.ErrAddressHeld || res.Session != nil {
		t.Fatalf("refusal %v, session %v; want ErrAddressHeld and no session", res.Refusal, res.Session)
	}
	if f.pending(ada) != 0 || f.unspent(tok) != 0 || f.users(ada) != 1 {
		t.Fatal("a held address kept the registration, kept the link or made a second principal")
	}
	if n := f.Count("SELECT count(*) FROM auth_credentials WHERE principal_id = $1", holder); n != 0 {
		t.Fatalf("the holder got %d credentials; want 0", n)
	}
	if f.sessions() != 0 {
		t.Fatal("a held address opened a session")
	}
}

func TestActivateUnknownLink(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		f := newActFixture(t)
		res := f.activate(strings.Repeat("A", 43), good)
		if res.Refusal != authkit.ErrTokenUnknown || res.Session != nil {
			t.Fatalf("refusal %v, session %v; want an unknown link and no session", res.Refusal, res.Session)
		}
	})
	t.Run("reset", func(t *testing.T) {
		f := newActFixture(t)
		f.User(bob, good)
		r := f.InAuth(func(q db.Querier) (authkit.Result, error) {
			return f.Svc.Password.RequestReset(f.Ctx, q, aud, bob)
		})
		var raw string
		if err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
			mt, err := f.Svc.OneTime().Mint(f.Ctx, q, *r.TokenID)
			raw = mt.Raw
			return err
		}); err != nil {
			t.Fatal(err)
		}
		res := f.activate(raw, good)
		if res.Refusal != authkit.ErrTokenUnknown || res.Session != nil {
			t.Fatalf("refusal %v, session %v; want an unknown link and no session", res.Refusal, res.Session)
		}
		if f.unspent(*r.TokenID) != 1 {
			t.Fatal("a reset link was spent by an activation")
		}
		if res := f.Login(aud, bob, good); res.Session == nil {
			t.Fatalf("reset owner sign-in: refusal %v; want a session", res.Refusal)
		}
	})
	t.Run("spent", func(t *testing.T) {
		f := newActFixture(t)
		_, raw := f.link(ada)
		if res := f.activate(raw, good); res.Session == nil {
			t.Fatalf("first activation: refusal %v; want a session", res.Refusal)
		}
		res := f.activate(raw, good)
		if res.Refusal != authkit.ErrTokenUnknown || res.Session != nil {
			t.Fatalf("refusal %v, session %v; want an unknown link and no session", res.Refusal, res.Session)
		}
		if f.users(ada) != 1 || f.sessions() != 1 {
			t.Fatal("a spent link made a second principal or a second session")
		}
	})
}
