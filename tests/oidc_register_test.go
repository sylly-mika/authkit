package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest/oidcfake"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/oidc"
	"github.com/sylly-mika/authkit/register"
)

const oidcRedirect = "https://app.example.invalid/oidc/google/callback"

func (w *world) withOIDC(skip bool) *oidcfake.Server {
	w.T.Helper()
	fake := oidcfake.New(w.T, oidcfake.Google)
	fake.Now = w.Clock.Now
	p := fake.Provider(oidcRedirect)
	p.SkipSecondFactor = skip
	w.Cfg.OIDC = oidc.Rules{Providers: []oidc.Provider{p}, HTTPClient: fake.Client}
	w.Svc = w.Build(w.Cfg)
	return fake
}

func (w *world) withRegister(totp bool) {
	w.T.Helper()
	w.Cfg.Register = register.Rules{Create: func(ctx context.Context, q db.Querier, p register.Pending) (authkit.Principal, error) {
		id := uuid.New()
		n, err := q.Exec(ctx, `INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING`, id, p.Email)
		if err != nil {
			return authkit.Principal{}, err
		}
		if n == 0 {
			return authkit.Principal{}, fmt.Errorf("users: %w", register.ErrAddressHeld)
		}
		if totp {
			if _, err := q.Exec(ctx, w.D.SQL(`INSERT INTO auth_second_factors (principal_id, kind, secret, created_at, confirmed_at) VALUES ($1, 'totp', '\x01'::bytea, $2, $2)`), id, w.Clock.Now()); err != nil {
				return authkit.Principal{}, err
			}
		}
		return authkit.Principal{ID: id, Login: p.Email}, nil
	}}
	w.Svc = w.Build(w.Cfg)
}

func (w *world) googleSignIn(fake *oidcfake.Server, u oidcfake.User) (authkit.Result, *oidc.SignUp) {
	w.T.Helper()
	var r oidc.Redirect
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		var err error
		r, err = w.Svc.OIDC.Begin(w.Ctx, q, "google", "staff", authkit.Meta{})
		return err
	}); err != nil {
		w.T.Fatalf("begin: %v", err)
	}
	cb := fake.Authorize(w.T, r, u)
	var su *oidc.SignUp
	res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		res, s, err := w.Svc.OIDC.Finish(w.Ctx, q, cb, r.Binding, authkit.Meta{})
		su = s
		return res, err
	})
	return res, su
}

func (w *world) registerLink(email string) string {
	w.T.Helper()
	var raw string
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		st, err := w.Svc.Register.Start(w.Ctx, q, "staff", email, json.RawMessage(`{}`))
		if err != nil {
			return err
		}
		if st.TokenID == nil {
			return errors.New("start gave no link for a new address")
		}
		mail, err := w.Svc.Register.Mint(w.Ctx, q, *st.TokenID)
		raw = mail.Raw
		return err
	}); err != nil {
		w.T.Fatalf("register link: %v", err)
	}
	return raw
}

func (w *world) activate(raw, pass string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Register.Activate(w.Ctx, q, raw, pass, authkit.Meta{})
	})
}

func TestPendingThenOIDC(t *testing.T) {
	w := newWorld(t)
	fake := w.withOIDC(true)
	w.withRegister(false)
	const addr = "ada@example.invalid"
	raw := w.registerLink(addr)

	res, su := w.googleSignIn(fake, oidcfake.User{Subject: "g-ada", Email: addr, EmailVerified: true})
	if !errors.Is(res.Refusal, oidc.ErrIdentityUnknown) || su == nil {
		t.Fatalf("finish: refusal %v, sign-up set %v", res.Refusal, su != nil)
	}
	if su.Email != addr {
		t.Fatalf("sign-up email is not the registered address")
	}

	id := w.User(addr, "")
	up := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.OIDC.SignUp(w.Ctx, q, su.Ticket, id, "staff", authkit.Meta{})
	})
	if up.Refusal != nil || up.Session == nil || up.Session.SecondFactor != "oidc" {
		t.Fatalf("sign-up: refusal %v, session set %v", up.Refusal, up.Session != nil)
	}

	act := w.activate(raw, "a fresh activation password")
	if !errors.Is(act.Refusal, register.ErrAddressHeld) || act.Session != nil {
		t.Fatalf("activate: refusal %v, session set %v", act.Refusal, act.Session != nil)
	}

	checks := []struct {
		name  string
		query string
		args  []any
		want  int
	}{
		{"users with the address", `SELECT count(*) FROM users WHERE email = $1`, []any{addr}, 1},
		{"pending registrations", `SELECT count(*) FROM auth_registrations WHERE email = $1`, []any{addr}, 0},
		{"password credentials on the OIDC principal", `SELECT count(*) FROM auth_credentials WHERE principal_id = $1`, []any{id}, 0},
		{"google identities on the OIDC principal", `SELECT count(*) FROM auth_identities WHERE principal_id = $1 AND provider = 'google' AND subject = 'g-ada'`, []any{id}, 1},
		{"open sessions", `SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND revoked_at IS NULL`, []any{id}, 1},
		{"spent register links", `SELECT count(*) FROM auth_tokens WHERE purpose = 'register' AND used_at IS NOT NULL`, nil, 1},
		{"registered events", `SELECT count(*) FROM auth_events WHERE result = 'registered'`, nil, 0},
	}
	for _, c := range checks {
		if n := w.Count(c.query, c.args...); n != c.want {
			t.Errorf("%s = %d, want %d", c.name, n, c.want)
		}
	}
}
