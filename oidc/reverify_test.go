package oidc_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest/oidcfake"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/oidc"
)

func rvSetup(t *testing.T) (*acctEnv, uuid.UUID, *authkit.Claims) {
	t.Helper()
	e := acctSetup(t)
	id, cl := e.oidcOnly("ada@example.invalid", "g-ada")
	return e, id, cl
}

func (e *acctEnv) beginRV(cl *authkit.Claims, provider string) (oidc.Redirect, error) {
	e.w.T.Helper()
	var r oidc.Redirect
	err := e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		var err error
		r, err = e.m.BeginReverify(e.w.Ctx, q, cl, provider)
		return err
	})
	return r, err
}

func (e *acctEnv) rvCeremonies(spent bool) int {
	return e.w.Count("SELECT count(*) FROM auth_ceremonies WHERE kind = 'reverify' AND (spent_at IS NOT NULL) = $1", spent)
}

func endSession(e *acctEnv, cl *authkit.Claims) {
	e.w.T.Helper()
	e.w.D.Exec(e.w.T, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'user' WHERE id = $1`, cl.SessionID, e.w.Clock.Now())
}

func TestBeginReverifyPrompt(t *testing.T) {
	e, id, cl := rvSetup(t)
	r, err := e.beginRV(cl, "google")
	if err != nil {
		t.Fatalf("begin reverify = %v", err)
	}
	if got := queryOf(r); got.Get("prompt") != "login" || got.Get("max_age") != "0" {
		t.Fatalf("reverify URL query %v, want prompt=login and max_age=0", got)
	}
	e.google.Authorize(e.w.T, r, oidcfake.User{Subject: "g-ada", Email: "ada@example.invalid", EmailVerified: true})
	if got := e.google.LastAuthorize().Get("prompt"); got != "login" {
		t.Fatalf("the provider saw prompt %q, want login", got)
	}
	if n := e.w.Count("SELECT count(*) FROM auth_ceremonies WHERE kind = 'reverify' AND principal_id = $1 AND provider = 'google' AND audience = 'staff' AND spent_at IS NULL", id); n != 1 {
		t.Fatalf("unspent reverify ceremonies for Ada = %d, want 1", n)
	}
	var plain oidc.Redirect
	if err := e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		var err error
		plain, err = e.m.Begin(e.w.Ctx, q, "google", acctAud, acctMeta)
		return err
	}); err != nil {
		t.Fatalf("begin = %v", err)
	}
	if got := queryOf(plain); got.Has("prompt") || got.Has("max_age") {
		t.Fatalf("sign-in URL query %v, want no prompt or max_age", got)
	}
}

func TestBeginReverifyUnlinked(t *testing.T) {
	e, _, cl := rvSetup(t)
	cases := []struct {
		name, provider string
		want           error
	}{
		{name: "unlinked", provider: "apple", want: oidc.ErrNotLinked},
		{name: "unknown", provider: "github", want: oidc.ErrUnknownProvider},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.beginRV(cl, tc.provider); !errors.Is(err, tc.want) {
				t.Fatalf("begin reverify with %s = %v, want %v", tc.provider, err, tc.want)
			}
		})
	}
	if n := e.rvCeremonies(false); n != 0 {
		t.Fatalf("reverify ceremonies after refusals = %d, want 0", n)
	}
}

func TestBeginReverifyEnded(t *testing.T) {
	e, _, cl := rvSetup(t)
	endSession(e, cl)
	if _, err := e.beginRV(cl, "google"); !errors.Is(err, authkit.ErrSessionEnded) {
		t.Fatalf("begin reverify on an ended session = %v, want ErrSessionEnded", err)
	}
	if n := e.rvCeremonies(false); n != 0 {
		t.Fatalf("reverify ceremonies on an ended session = %d, want 0", n)
	}
}
