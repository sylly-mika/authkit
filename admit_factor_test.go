package authkit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
)

type factorClaim struct{ *authkittest.Principals }

func (f factorClaim) Admit(ctx context.Context, q db.Querier, prop authkit.Proposal) (authkit.Admission, error) {
	adm, err := f.Principals.Admit(ctx, q, prop)
	if err != nil || prop.SecondFactor == "" {
		return adm, err
	}
	claims := make(map[string]any, len(adm.Claims)+1)
	for k, v := range adm.Claims {
		claims[k] = v
	}
	claims["factor"] = string(prop.SecondFactor)
	adm.Claims = claims
	return adm, nil
}

func withFactorClaim(w *world) *world {
	w.t.Helper()
	svc, err := authkit.New(w.cfg, factorClaim{w.p})
	if err != nil {
		w.t.Fatal(err)
	}
	w.svc = svc
	return w
}

func (w *world) setFactor(sessionID uuid.UUID, f string) {
	w.t.Helper()
	w.d.Exec(w.t, "UPDATE auth_sessions SET second_factor = $2 WHERE id = $1", sessionID, f)
}

func (w *world) eventFactor(sessionID uuid.UUID) string {
	w.t.Helper()
	var kind string
	if err := w.d.Row(w.t, `SELECT second_factor FROM auth_events WHERE session_id = $1 AND result = 'signed_in'`, sessionID).Scan(&kind); err != nil {
		w.t.Fatal(err)
	}
	return kind
}

func TestRefreshAdmitsWithTheSessionsSecondFactor(t *testing.T) {
	w := withFactorClaim(newWorld(t))
	login := "ada@example.invalid"
	w.user(login, pw)
	res := w.signIn(login, pw)
	if got := w.claims(res).App["factor"]; got != nil {
		t.Fatalf("password sign-in carries factor %v", got)
	}
	w.setFactor(res.Session.ID, "totp")
	next := w.refresh("staff", res.Tokens.RefreshToken)
	if next.Refusal != nil {
		t.Fatalf("refresh refused: %v", next.Refusal)
	}
	if got := w.claims(next).App["factor"]; got != "totp" {
		t.Fatalf("refresh claim = %v, want totp", got)
	}
	if got := w.sessionFactor(res.Session.ID); got != "totp" {
		t.Fatalf("session factor = %q after refresh, want totp", got)
	}
}

func TestAuthenticateAdmitsWithTheSessionsSecondFactor(t *testing.T) {
	w := withFactorClaim(newWorld(t))
	login := "ada@example.invalid"
	w.user(login, pw)
	res := w.signIn(login, pw)
	w.setFactor(res.Session.ID, "totp")
	res2 := w.refresh("staff", res.Tokens.RefreshToken)
	if res2.Refusal != nil {
		t.Fatalf("refresh refused: %v", res2.Refusal)
	}
	got := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.Authenticate(w.ctx, q, w.claims(res2))
	})
	if got.Refusal != nil {
		t.Fatalf("Authenticate with the factor claim refused: %v", got.Refusal)
	}
	old := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.Authenticate(w.ctx, q, w.claims(res))
	})
	if !errors.Is(old.Refusal, authkit.ErrStale) {
		t.Fatalf("Authenticate with the pre-factor claim = %v, want ErrStale", old.Refusal)
	}
}

func TestAuthenticateSessionAdmitsWithTheSessionsSecondFactor(t *testing.T) {
	w := withFactorClaim(sessionWorld(t))
	login := "ada@example.invalid"
	w.user(login, pw)
	res := w.signIn(login, pw)
	w.setFactor(res.Session.ID, "totp")
	got := w.authenticateSession("staff", res.SessionToken)
	if got.Refusal != nil {
		t.Fatalf("AuthenticateSession refused: %v", got.Refusal)
	}
	if f := got.Admission.Claims["factor"]; f != "totp" {
		t.Fatalf("admit claim = %v, want totp", f)
	}
}

func TestOpenSessionFromKeepsTheSecondFactor(t *testing.T) {
	w := withFactorClaim(newWorld(t))
	login := "ada@example.invalid"
	id := w.user(login, pw)
	p := authkit.Principal{ID: id, Login: login}
	res := w.signIn(login, pw)
	w.setFactor(res.Session.ID, "totp")
	moved := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.OpenSessionFrom(w.ctx, q, res.Session.ID, p, "staff", meta)
	})
	if moved.Refusal != nil {
		t.Fatalf("OpenSessionFrom refused: %v", moved.Refusal)
	}
	if got := w.sessionFactor(moved.Session.ID); got != "totp" {
		t.Fatalf("switched session factor = %q, want totp", got)
	}
	if got := w.claims(moved).App["factor"]; got != "totp" {
		t.Fatalf("switched claim = %v, want totp", got)
	}
	if got := w.eventFactor(moved.Session.ID); got != "totp" {
		t.Fatalf("switch signed_in factor = %q, want totp", got)
	}
	plain := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.OpenSession(w.ctx, q, p, "staff", meta)
	})
	if plain.Refusal != nil {
		t.Fatalf("OpenSession refused: %v", plain.Refusal)
	}
	if got := w.sessionFactor(plain.Session.ID); got != "" {
		t.Fatalf("app sign-in session factor = %q, want none", got)
	}
	if got := w.claims(plain).App["factor"]; got != nil {
		t.Fatalf("app sign-in claim = %v, want none", got)
	}
	if got := w.eventFactor(plain.Session.ID); got != "" {
		t.Fatalf("app sign-in signed_in factor = %q, want none", got)
	}
}

func TestPasskeyLoginRecordsThePasskeyFactor(t *testing.T) {
	w := withFactorClaim(newWorld(t, passkeys))
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	res := w.passkeySignIn("staff", a)
	if res.Refusal != nil {
		t.Fatalf("passkey sign-in refused: %v", res.Refusal)
	}
	if res.SecondStep != nil {
		t.Fatal("passkey sign-in asked for a second step")
	}
	if got := w.sessionFactor(res.Session.ID); got != "passkey" {
		t.Fatalf("session factor = %q, want passkey", got)
	}
	if got := w.claims(res).App["factor"]; got != "passkey" {
		t.Fatalf("admit claim = %v, want passkey", got)
	}
	if got := w.eventFactor(res.Session.ID); got != "passkey" {
		t.Fatalf("signed_in factor = %q, want passkey", got)
	}
}

func TestChangePasswordRevokingAllKeepsTheSecondFactor(t *testing.T) {
	w := withFactorClaim(newWorld(t, func(c *authkit.Config) { c.RevokeOnPasswordChange = authkit.RevokeAll }))
	login := "ada@example.invalid"
	id := w.user(login, pw)
	res := w.signIn(login, pw)
	w.setFactor(res.Session.ID, "totp")
	changed := w.changePassword(w.pinned(id), w.claims(res), pw, "the changed password 2040")
	if changed.Refusal != nil {
		t.Fatalf("ChangePassword refused: %v", changed.Refusal)
	}
	if changed.Session.ID == res.Session.ID {
		t.Fatal("RevokeAll kept the old session")
	}
	if got := w.sessionFactor(changed.Session.ID); got != "totp" {
		t.Fatalf("reopened session factor = %q, want totp", got)
	}
	if got := w.claims(changed).App["factor"]; got != "totp" {
		t.Fatalf("reopened claim = %v, want totp", got)
	}
	if got := w.eventFactor(changed.Session.ID); got != "totp" {
		t.Fatalf("reopened signed_in factor = %q, want totp", got)
	}
	if n := w.count("SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NOT NULL", res.Session.ID); n != 1 {
		t.Fatalf("old session revoked %d times, want 1", n)
	}
}
