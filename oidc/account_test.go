package oidc_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest/oidcfake"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/oidc"
)

const acctAud authkit.Audience = "staff"

var acctMeta = authkit.Meta{IP: "192.0.2.1", UserAgent: "authkit-test"}

type acctEnv struct {
	w             *kittest.World
	m             *oidc.Module
	google, apple *oidcfake.Server
}

func acctSetup(t *testing.T) *acctEnv {
	t.Helper()
	w := kittest.New(t, kittest.Passkeys)
	g, a := oidcfake.New(t, oidcfake.Google), oidcfake.New(t, oidcfake.Apple)
	g.Now, a.Now = w.Clock.Now, w.Clock.Now
	// WHY: every httptest TLS server serves the same built-in certificate, so one fake's Client trusts both.
	m, err := oidc.New(w.Svc.Service, oidc.Rules{HTTPClient: g.Client, Providers: []oidc.Provider{
		g.Provider("https://app.example.invalid/oidc/google/callback"), a.Provider("https://app.example.invalid/oidc/apple/callback")}})
	if err != nil {
		t.Fatal(err)
	}
	return &acctEnv{w: w, m: m, google: g, apple: a}
}

func (e *acctEnv) gUser(sub, email string) oidcfake.User {
	return oidcfake.User{Subject: sub, Email: email, EmailVerified: true, GivenName: "Ada", FamilyName: "Lovelace"}
}

func (e *acctEnv) signIn(provider string, u oidcfake.User) (authkit.Result, *oidc.SignUp) {
	e.w.T.Helper()
	var r oidc.Redirect
	if err := e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		var err error
		r, err = e.m.Begin(e.w.Ctx, q, provider, acctAud, acctMeta)
		return err
	}); err != nil {
		e.w.T.Fatalf("begin %s: %v", provider, err)
	}
	return e.finish(provider, r, u)
}

func (e *acctEnv) finish(provider string, r oidc.Redirect, u oidcfake.User) (authkit.Result, *oidc.SignUp) {
	e.w.T.Helper()
	fake := e.google
	if provider == "apple" {
		fake = e.apple
	}
	cb := fake.Authorize(e.w.T, r, u)
	var res authkit.Result
	var su *oidc.SignUp
	if err := e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		var err error
		res, su, err = e.m.Finish(e.w.Ctx, q, cb, r.Binding, acctMeta)
		return err
	}); err != nil {
		e.w.T.Fatalf("finish %s: %v", provider, err)
	}
	return res, su
}

func (e *acctEnv) signUp(ticket string, id uuid.UUID, aud authkit.Audience) (authkit.Result, error) {
	e.w.T.Helper()
	var res authkit.Result
	err := e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		var err error
		res, err = e.m.SignUp(e.w.Ctx, q, ticket, id, aud, acctMeta)
		return err
	})
	return res, err
}

func (e *acctEnv) ticket(raw string) (*oidc.SignUp, error) {
	e.w.T.Helper()
	var su *oidc.SignUp
	err := e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		var err error
		su, err = e.m.Ticket(e.w.Ctx, q, raw)
		return err
	})
	return su, err
}

func (e *acctEnv) link(cl *authkit.Claims, provider string) (oidc.Redirect, error) {
	e.w.T.Helper()
	var r oidc.Redirect
	err := e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		var err error
		r, err = e.m.Link(e.w.Ctx, q, cl, provider, acctMeta)
		return err
	})
	return r, err
}

func (e *acctEnv) unlink(cl *authkit.Claims, provider string) error {
	e.w.T.Helper()
	return e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		return e.m.Unlink(e.w.Ctx, q, cl, provider, acctMeta)
	})
}

func (e *acctEnv) identities(id uuid.UUID) []oidc.Identity {
	e.w.T.Helper()
	var out []oidc.Identity
	if err := e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		var err error
		out, err = e.m.Identities(e.w.Ctx, q, id)
		return err
	}); err != nil {
		e.w.T.Fatalf("identities: %v", err)
	}
	return out
}

func (e *acctEnv) hasPassword(id uuid.UUID) bool {
	e.w.T.Helper()
	var has bool
	if err := e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		var err error
		has, err = e.w.Svc.Password.HasCredential(e.w.Ctx, q, id)
		return err
	}); err != nil {
		e.w.T.Fatalf("has credential: %v", err)
	}
	return has
}

func (e *acctEnv) addIdentity(id uuid.UUID, provider, sub, email string) {
	e.w.T.Helper()
	e.w.D.Exec(e.w.T, `INSERT INTO auth_identities (id, principal_id, provider, subject, email, created_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		uuid.New(), id, provider, sub, email, e.w.Clock.Now())
}

func (e *acctEnv) oidcOnly(login, sub string) (uuid.UUID, *authkit.Claims) {
	e.w.T.Helper()
	_, su := e.signIn("google", e.gUser(sub, login))
	id := e.w.User(login, "")
	res, err := e.signUp(su.Ticket, id, acctAud)
	if err != nil {
		e.w.T.Fatalf("sign-up: %v", err)
	}
	return id, e.w.Claims(res)
}

func (e *acctEnv) sessions(id uuid.UUID) int {
	return e.w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND revoked_at IS NULL", id)
}

func (e *acctEnv) identityRows(id uuid.UUID) int {
	return e.w.Count("SELECT count(*) FROM auth_identities WHERE principal_id = $1", id)
}

func zeroResult(res authkit.Result) bool {
	return reflect.DeepEqual(res, authkit.Result{})
}

func TestSignUpCreatesIdentity(t *testing.T) {
	e := acctSetup(t)
	res, su := e.signIn("google", e.gUser("g-ada", "ada@example.invalid"))
	if !errors.Is(res.Refusal, oidc.ErrIdentityUnknown) {
		t.Fatalf("first sign-in refusal = %v, want ErrIdentityUnknown", res.Refusal)
	}
	if su.Provider != "google" || su.Email != "ada@example.invalid" {
		t.Fatalf("sign-up = %+v", su)
	}
	id := e.w.User("ada@example.invalid", "")
	res, err := e.signUp(su.Ticket, id, acctAud)
	if err != nil || res.Refusal != nil {
		t.Fatalf("SignUp = %+v, %v; want no error and no refusal", res, err)
	}
	if res.Session == nil || res.Session.SecondFactor != "oidc" || res.Principal.ID != id {
		t.Fatalf("SignUp result = %+v; want a session for %v with second factor oidc", res, id)
	}
	if n := e.w.Count("SELECT count(*) FROM auth_identities WHERE principal_id = $1 AND provider = 'google' AND subject = 'g-ada' AND email = 'ada@example.invalid'", id); n != 1 {
		t.Fatalf("identity rows = %d, want 1", n)
	}
	if e.hasPassword(id) {
		t.Fatal("a sign-up principal has a password credential")
	}
	got := e.identities(id)
	if len(got) != 1 || got[0].Provider != "google" || got[0].Email != "ada@example.invalid" || got[0].LastUsedAt != nil || !got[0].CreatedAt.Equal(e.w.Clock.Now()) {
		t.Fatalf("identities = %+v", got)
	}
	res, su = e.signIn("google", e.gUser("g-ada", "ada@example.invalid"))
	if su != nil || res.Session == nil || res.Principal.ID != id {
		t.Fatalf("second sign-in = %+v, sign-up %+v; want a session for %v", res, su, id)
	}
}

func TestSignUpTicketOnce(t *testing.T) {
	e := acctSetup(t)
	_, su := e.signIn("google", e.gUser("g-ada", "ada@example.invalid"))
	ada := e.w.User("ada@example.invalid", "")
	bob := e.w.User("bob@example.invalid", "")
	res, err := e.signUp(su.Ticket, ada, acctAud)
	if err != nil || res.Session == nil {
		t.Fatalf("first SignUp = %+v, %v; want a session", res, err)
	}
	res, err = e.signUp(su.Ticket, bob, acctAud)
	if !errors.Is(err, oidc.ErrTicketUnknown) || !zeroResult(res) {
		t.Fatalf("second SignUp = %+v, %v; want a zero result and ErrTicketUnknown", res, err)
	}
	if n := e.sessions(bob); n != 0 {
		t.Fatalf("bob has %d sessions, want 0", n)
	}
	if n := e.identityRows(bob); n != 0 {
		t.Fatalf("bob has %d identities, want 0", n)
	}
	if n := e.w.Count("SELECT count(*) FROM auth_identities"); n != 1 {
		t.Fatalf("identity rows = %d, want 1", n)
	}
	if _, err := e.ticket(su.Ticket); !errors.Is(err, oidc.ErrTicketUnknown) {
		t.Fatalf("Ticket after spend = %v, want ErrTicketUnknown", err)
	}
}

func TestSignUpWrongAudience(t *testing.T) {
	e := acctSetup(t)
	_, su := e.signIn("google", e.gUser("g-ada", "ada@example.invalid"))
	id := e.w.User("ada@example.invalid", "")
	res, err := e.signUp(su.Ticket, id, "client")
	if !errors.Is(err, oidc.ErrTicketUnknown) || !zeroResult(res) {
		t.Fatalf("SignUp under client = %+v, %v; want a zero result and ErrTicketUnknown", res, err)
	}
	if n := e.sessions(id); n != 0 {
		t.Fatalf("sessions = %d, want 0", n)
	}
	if n := e.identityRows(id); n != 0 {
		t.Fatalf("identities = %d, want 0", n)
	}
	res, err = e.signUp(su.Ticket, id, acctAud)
	if err != nil || res.Session == nil || res.Session.Audience != string(acctAud) {
		t.Fatalf("SignUp under staff = %+v, %v; want a staff session", res, err)
	}
}

func TestTicketDoesNotSpend(t *testing.T) {
	e := acctSetup(t)
	_, su := e.signIn("google", e.gUser("g-ada", "ada@example.invalid"))
	for range 2 {
		got, err := e.ticket(su.Ticket)
		if err != nil {
			t.Fatalf("Ticket: %v", err)
		}
		if !reflect.DeepEqual(*got, *su) {
			t.Fatalf("Ticket = %+v, want %+v", *got, *su)
		}
	}
	const open = "SELECT count(*) FROM auth_ceremonies WHERE kind = 'signup' AND spent_at IS NULL"
	if n := e.w.Count(open); n != 1 {
		t.Fatalf("open tickets after reads = %d, want 1", n)
	}
	id := e.w.User("ada@example.invalid", "")
	res, err := e.signUp(su.Ticket, id, acctAud)
	if err != nil || res.Session == nil {
		t.Fatalf("SignUp = %+v, %v; want a session", res, err)
	}
	if n := e.w.Count(open); n != 0 {
		t.Fatalf("open tickets after SignUp = %d, want 0", n)
	}
}

func TestTicketExpired(t *testing.T) {
	e := acctSetup(t)
	_, su := e.signIn("google", e.gUser("g-ada", "ada@example.invalid"))
	e.w.Clock.Advance(10*time.Minute - time.Second)
	if _, err := e.ticket(su.Ticket); err != nil {
		t.Fatalf("Ticket before expiry: %v", err)
	}
	e.w.Clock.Advance(time.Second)
	if _, err := e.ticket(su.Ticket); !errors.Is(err, oidc.ErrTicketUnknown) {
		t.Fatalf("Ticket at expiry = %v, want ErrTicketUnknown", err)
	}
	id := e.w.User("ada@example.invalid", "")
	res, err := e.signUp(su.Ticket, id, acctAud)
	if !errors.Is(err, oidc.ErrTicketUnknown) || !zeroResult(res) {
		t.Fatalf("SignUp at expiry = %+v, %v; want a zero result and ErrTicketUnknown", res, err)
	}
	if n := e.identityRows(id); n != 0 {
		t.Fatalf("identities = %d, want 0", n)
	}
	if n := e.sessions(id); n != 0 {
		t.Fatalf("sessions = %d, want 0", n)
	}
}

func TestSignUpAdmitRefusal(t *testing.T) {
	e := acctSetup(t)
	_, su := e.signIn("google", e.gUser("g-ada", "ada@example.invalid"))
	id := e.w.User("ada@example.invalid", "")
	errNo := errors.New("no membership")
	e.w.P.Refuse(id, errNo)
	res, err := e.signUp(su.Ticket, id, acctAud)
	if err != nil || !errors.Is(res.Refusal, errNo) || res.Session != nil {
		t.Fatalf("SignUp = %+v, %v; want refusal %v and no session", res, err, errNo)
	}
	if n := e.sessions(id); n != 0 {
		t.Fatalf("sessions = %d, want 0", n)
	}
	if n := e.identityRows(id); n != 1 {
		t.Fatalf("identities = %d, want 1", n)
	}
	if _, err := e.ticket(su.Ticket); !errors.Is(err, oidc.ErrTicketUnknown) {
		t.Fatalf("Ticket after refused SignUp = %v, want ErrTicketUnknown", err)
	}
	e.w.P.Allow(id)
	res, _ = e.signIn("google", e.gUser("g-ada", "ada@example.invalid"))
	if res.Session == nil || res.Principal.ID != id {
		t.Fatalf("sign-in after Allow = %+v; want a session for %v", res, id)
	}
}

func TestSignUpIdentityTaken(t *testing.T) {
	e := acctSetup(t)
	_, t1 := e.signIn("google", e.gUser("g-x", "x@example.invalid"))
	_, t2 := e.signIn("google", e.gUser("g-x", "x@example.invalid"))
	id1 := e.w.User("one@example.invalid", "")
	id2 := e.w.User("two@example.invalid", "")
	if res, err := e.signUp(t1.Ticket, id1, acctAud); err != nil || res.Session == nil {
		t.Fatalf("first SignUp = %+v, %v; want a session", res, err)
	}
	res, err := e.signUp(t2.Ticket, id2, acctAud)
	if !errors.Is(err, oidc.ErrIdentityTaken) || !zeroResult(res) {
		t.Fatalf("second SignUp = %+v, %v; want a zero result and ErrIdentityTaken", res, err)
	}
	if n := e.sessions(id2); n != 0 {
		t.Fatalf("sessions = %d, want 0", n)
	}
	if n := e.identityRows(id2); n != 0 {
		t.Fatalf("identities = %d, want 0", n)
	}
	if n := e.w.Count("SELECT count(*) FROM auth_ceremonies WHERE kind = 'signup' AND spent_at IS NULL"); n != 1 {
		t.Fatalf("open tickets = %d, want 1 (the rollback keeps the ticket open)", n)
	}
}
