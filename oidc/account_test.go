package oidc_test

import (
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/authkittest/oidcfake"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
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

func (e *acctEnv) ticketEmail(raw string) (string, bool, error) {
	e.w.T.Helper()
	var email string
	var private bool
	var terr error
	if err := e.w.D.InAuthTx(e.w.Ctx, func(q db.Querier) error {
		email, private, terr = e.m.TicketEmail(e.w.Ctx, q, raw)
		return nil
	}); err != nil {
		e.w.T.Fatalf("InAuthTx: %v", err)
	}
	return email, private, terr
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

func TestTicketEmail(t *testing.T) {
	t.Run("google", func(t *testing.T) {
		e := acctSetup(t)
		_, su := e.signIn("google", e.gUser("g-ada", "Ada@Example.invalid"))
		for range 2 {
			email, private, err := e.ticketEmail(su.Ticket)
			if err != nil || email != "Ada@Example.invalid" || private {
				t.Fatalf("TicketEmail = %q, %v, %v; want Ada@Example.invalid, false, nil", email, private, err)
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
	})
	t.Run("apple", func(t *testing.T) {
		e := acctSetup(t)
		relay := "x7@privaterelay.appleid.com"
		_, su := e.signIn("apple", oidcfake.User{Subject: "a-x7", Email: relay, EmailVerified: true, PrivateEmail: true})
		email, private, err := e.ticketEmail(su.Ticket)
		if err != nil || email != relay || !private {
			t.Fatalf("TicketEmail = %q, %v, %v; want %s, true, nil", email, private, err, relay)
		}
	})
}

func TestTicketEmailUnknown(t *testing.T) {
	check := func(t *testing.T, e *acctEnv, raw string) {
		t.Helper()
		email, private, err := e.ticketEmail(raw)
		if !errors.Is(err, oidc.ErrTicketUnknown) || email != "" || private {
			t.Fatalf("TicketEmail = %q, %v, %v; want \"\", false, ErrTicketUnknown", email, private, err)
		}
		if err != nil && strings.Contains(err.Error(), raw) {
			t.Fatalf("error text contains the ticket: %v", err)
		}
	}
	t.Run("unknown", func(t *testing.T) {
		check(t, acctSetup(t), "no-such-ticket")
	})
	t.Run("spent", func(t *testing.T) {
		e := acctSetup(t)
		_, su := e.signIn("google", e.gUser("g-ada", "ada@example.invalid"))
		if _, err := e.signUp(su.Ticket, e.w.User("ada@example.invalid", ""), acctAud); err != nil {
			t.Fatalf("SignUp: %v", err)
		}
		check(t, e, su.Ticket)
	})
	t.Run("expired", func(t *testing.T) {
		e := acctSetup(t)
		_, su := e.signIn("google", e.gUser("g-ada", "ada@example.invalid"))
		e.w.Clock.Advance(10 * time.Minute)
		check(t, e, su.Ticket)
	})
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

func TestLinkNeedsFresh(t *testing.T) {
	e := acctSetup(t)
	id := e.w.User("ada@example.invalid", "a long password 1")
	cl := e.w.Claims(e.w.SignIn("ada@example.invalid", "a long password 1"))
	if _, err := e.link(cl, "nope"); !errors.Is(err, oidc.ErrUnknownProvider) {
		t.Fatalf("link unknown provider = %v, want ErrUnknownProvider", err)
	}
	e.w.Clock.Advance(5*time.Minute + time.Second)
	if _, err := e.link(cl, "google"); !errors.Is(err, authkit.ErrReauthRequired) {
		t.Fatalf("link with a stale session = %v, want ErrReauthRequired", err)
	}
	if n := e.w.Count("SELECT count(*) FROM auth_ceremonies WHERE kind = 'link'"); n != 0 {
		t.Fatalf("link ceremonies after a stale link = %d, want 0", n)
	}
	cl2 := e.w.Claims(e.w.SignIn("ada@example.invalid", "a long password 1"))
	g, err := e.link(cl2, "google")
	if err != nil {
		t.Fatalf("link google = %v", err)
	}
	a, err := e.link(cl2, "apple")
	if err != nil {
		t.Fatalf("link apple = %v", err)
	}
	if !strings.HasPrefix(g.URL, e.google.URL) || g.SameSite != http.SameSiteLaxMode {
		t.Fatalf("google redirect = %+v; want the Google authorize URL with SameSite Lax", g)
	}
	if !strings.HasPrefix(a.URL, e.apple.URL) || a.SameSite != http.SameSiteNoneMode {
		t.Fatalf("apple redirect = %+v; want the Apple authorize URL with SameSite None", a)
	}
	if n := e.w.Count("SELECT count(*) FROM auth_ceremonies WHERE kind = 'link' AND principal_id = $1", id); n != 2 {
		t.Fatalf("link ceremonies for Ada = %d, want 2", n)
	}
}

func TestLinkFinish(t *testing.T) {
	e := acctSetup(t)
	id := e.w.User("ada@example.invalid", "a long password 1")
	cl := e.w.Claims(e.w.SignIn("ada@example.invalid", "a long password 1"))
	r, err := e.link(cl, "google")
	if err != nil {
		t.Fatalf("link = %v", err)
	}
	res, su := e.finish("google", r, e.gUser("g-ada", "ada.work@example.invalid"))
	if res.Refusal != nil || su != nil || res.Session != nil || res.Tokens != nil || res.Principal.ID != id {
		t.Fatalf("link finish = %+v, sign-up %+v; want Ada with no refusal, no session and no tokens", res, su)
	}
	if n := e.sessions(id); n != 1 {
		t.Fatalf("sessions = %d, want 1 (the link adds none)", n)
	}
	got := e.identities(id)
	if len(got) != 1 || got[0].Provider != "google" || got[0].Email != "ada.work@example.invalid" || !got[0].CreatedAt.Equal(e.w.Clock.Now()) || got[0].LastUsedAt != nil {
		t.Fatalf("identities = %+v", got)
	}
	if !slices.Contains(e.w.Results(id), "identity_linked") {
		t.Fatalf("results = %v, want identity_linked", e.w.Results(id))
	}
	res, su = e.signIn("google", e.gUser("g-ada", "ada.work@example.invalid"))
	if su != nil || res.Session == nil || res.Session.SecondFactor != "oidc" || res.Principal.ID != id {
		t.Fatalf("later sign-in = %+v, sign-up %+v; want a session for %v", res, su, id)
	}
}

func TestLinkTaken(t *testing.T) {
	t.Run("subject", func(t *testing.T) {
		e := acctSetup(t)
		ada := e.w.User("ada@example.invalid", "a long password 1")
		bob := e.w.User("bob@example.invalid", "")
		e.addIdentity(bob, "google", "g-shared", "bob@example.invalid")
		cl := e.w.Claims(e.w.SignIn("ada@example.invalid", "a long password 1"))
		r, err := e.link(cl, "google")
		if err != nil {
			t.Fatalf("link = %v", err)
		}
		res, su := e.finish("google", r, e.gUser("g-shared", "x@example.invalid"))
		if !errors.Is(res.Refusal, oidc.ErrIdentityTaken) || su != nil || res.Session != nil {
			t.Fatalf("link finish = %+v, sign-up %+v; want ErrIdentityTaken and no session", res, su)
		}
		if n := e.sessions(ada); n != 1 {
			t.Fatalf("Ada sessions = %d, want 1", n)
		}
		if n := e.identityRows(ada); n != 0 {
			t.Fatalf("Ada identities = %d, want 0", n)
		}
		if n := e.w.Count("SELECT count(*) FROM auth_identities WHERE principal_id = $1 AND provider = 'google' AND subject = 'g-shared'", bob); n != 1 {
			t.Fatalf("Bob's identity rows = %d, want 1 unchanged", n)
		}
		if n := e.w.Count("SELECT count(*) FROM auth_ceremonies WHERE kind = 'link' AND spent_at IS NOT NULL"); n != 1 {
			t.Fatalf("spent link ceremonies = %d, want 1", n)
		}
	})
	t.Run("provider", func(t *testing.T) {
		e := acctSetup(t)
		ada := e.w.User("ada@example.invalid", "a long password 1")
		e.addIdentity(ada, "google", "g-1", "")
		cl := e.w.Claims(e.w.SignIn("ada@example.invalid", "a long password 1"))
		r, err := e.link(cl, "google")
		if err != nil {
			t.Fatalf("link = %v", err)
		}
		res, su := e.finish("google", r, e.gUser("g-2", "ada.2@example.invalid"))
		if !errors.Is(res.Refusal, oidc.ErrIdentityTaken) || su != nil || res.Session != nil {
			t.Fatalf("link finish = %+v, sign-up %+v; want ErrIdentityTaken and no session", res, su)
		}
		if n := e.sessions(ada); n != 1 {
			t.Fatalf("Ada sessions = %d, want 1", n)
		}
		if n := e.w.Count("SELECT count(*) FROM auth_identities WHERE principal_id = $1 AND provider = 'google' AND subject = 'g-1'", ada); n != 1 {
			t.Fatalf("Ada's Google subject g-1 rows = %d, want 1", n)
		}
		if n := e.w.Count("SELECT count(*) FROM auth_identities WHERE principal_id = $1 AND subject = 'g-2'", ada); n != 0 {
			t.Fatalf("Ada's g-2 rows = %d, want 0", n)
		}
		if n := e.w.Count("SELECT count(*) FROM auth_ceremonies WHERE kind = 'link' AND spent_at IS NOT NULL"); n != 1 {
			t.Fatalf("spent link ceremonies = %d, want 1", n)
		}
	})
}

func TestUnlinkLastCredential(t *testing.T) {
	t.Run("only", func(t *testing.T) {
		e := acctSetup(t)
		id, cl := e.oidcOnly("ada@example.invalid", "g-ada")
		if err := e.unlink(cl, "google"); !errors.Is(err, oidc.ErrLastCredential) {
			t.Fatalf("unlink the only identity = %v, want ErrLastCredential", err)
		}
		if n := e.identityRows(id); n != 1 {
			t.Fatalf("identities = %d, want 1", n)
		}
		if n := e.sessions(id); n != 1 {
			t.Fatalf("sessions = %d, want 1", n)
		}
	})
	t.Run("identity", func(t *testing.T) {
		e := acctSetup(t)
		id, cl := e.oidcOnly("ada@example.invalid", "g-ada")
		e.addIdentity(id, "apple", "a-1", "")
		if err := e.unlink(cl, "google"); err != nil {
			t.Fatalf("unlink google = %v", err)
		}
		if err := e.unlink(cl, "apple"); !errors.Is(err, oidc.ErrLastCredential) {
			t.Fatalf("unlink the last identity = %v, want ErrLastCredential", err)
		}
		got := e.identities(id)
		if len(got) != 1 || got[0].Provider != "apple" {
			t.Fatalf("identities = %+v, want [apple]", got)
		}
	})
	t.Run("passkey", func(t *testing.T) {
		e := acctSetup(t)
		id, cl := e.oidcOnly("ada@example.invalid", "g-ada")
		e.w.SeedPasskey(id, authkittest.NewAuthenticator("localhost", kittest.StaffOrigin))
		if err := e.unlink(cl, "google"); err != nil {
			t.Fatalf("unlink with a passkey = %v, want nil", err)
		}
		if n := e.identityRows(id); n != 0 {
			t.Fatalf("identities = %d, want 0", n)
		}
	})
	t.Run("password", func(t *testing.T) {
		e := acctSetup(t)
		ada := e.w.User("ada@example.invalid", "a long password 1")
		e.addIdentity(ada, "google", "g-ada", "")
		cl := e.w.Claims(e.w.SignIn("ada@example.invalid", "a long password 1"))
		if err := e.unlink(cl, "google"); err != nil {
			t.Fatalf("unlink with a password = %v, want nil", err)
		}
		if n := e.identityRows(ada); n != 0 {
			t.Fatalf("identities = %d, want 0", n)
		}
	})
}

func TestUnlinkRevokesOthers(t *testing.T) {
	e := acctSetup(t)
	ada := e.w.User("ada@example.invalid", "a long password 1")
	e.addIdentity(ada, "google", "g-ada", "ada.g@example.invalid")
	cl1 := e.w.Claims(e.w.SignIn("ada@example.invalid", "a long password 1"))
	cl2 := e.w.Claims(e.w.SignIn("ada@example.invalid", "a long password 1"))
	if err := e.unlink(cl1, "google"); err != nil {
		t.Fatalf("unlink = %v", err)
	}
	if n := e.w.Count("SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL", cl1.SessionID); n != 1 {
		t.Fatalf("the unlinking session is open = %d, want 1", n)
	}
	if n := e.w.Count("SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoke_reason = 'identity_removed'", cl2.SessionID); n != 1 {
		t.Fatalf("the other session revoked with identity_removed = %d, want 1", n)
	}
	if n := e.identityRows(ada); n != 0 {
		t.Fatalf("identities = %d, want 0", n)
	}
	if n := e.w.Count("SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'identity_unlinked' AND source = 'oidc'", ada); n != 1 {
		t.Fatalf("identity_unlinked events = %d, want 1", n)
	}
	res, _ := e.signIn("google", e.gUser("g-ada", "ada.g@example.invalid"))
	if !errors.Is(res.Refusal, oidc.ErrIdentityUnknown) || res.Session != nil {
		t.Fatalf("sign-in after unlink = %+v; want ErrIdentityUnknown and no session", res)
	}
}

func TestUnlinkRefusals(t *testing.T) {
	e := acctSetup(t)
	ada := e.w.User("ada@example.invalid", "a long password 1")
	e.addIdentity(ada, "google", "g-ada", "ada.g@example.invalid")
	cl := e.w.Claims(e.w.SignIn("ada@example.invalid", "a long password 1"))
	if err := e.unlink(cl, "apple"); !errors.Is(err, oidc.ErrNotLinked) {
		t.Fatalf("unlink an unlinked provider = %v, want ErrNotLinked", err)
	}
	if err := e.unlink(cl, "nope"); !errors.Is(err, oidc.ErrNotLinked) {
		t.Fatalf("unlink an unknown provider = %v, want ErrNotLinked", err)
	}
	e.w.Clock.Advance(5*time.Minute + time.Second)
	if err := e.unlink(cl, "google"); !errors.Is(err, authkit.ErrReauthRequired) {
		t.Fatalf("unlink with a stale session = %v, want ErrReauthRequired", err)
	}
	if n := e.identityRows(ada); n != 1 {
		t.Fatalf("identities = %d, want 1", n)
	}
	if n := e.w.Count("SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'identity_unlinked'", ada); n != 0 {
		t.Fatalf("identity_unlinked events = %d, want 0", n)
	}
}

func TestUnlinkConcurrent(t *testing.T) {
	e := acctSetup(t)
	id, cl := e.oidcOnly("ada@example.invalid", "g-ada")
	e.addIdentity(id, "apple", "a-1", "")
	ctx := e.w.Ctx
	tx1, err := e.w.D.App.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx1.Rollback()
	if err := e.m.Unlink(ctx, sqldb.Tx(tx1), cl, "google", acctMeta); err != nil {
		t.Fatalf("first unlink = %v", err)
	}
	second := make(chan error, 1)
	go func() { second <- e.unlink(cl, "apple") }()
	e.w.D.WaitForLockWaiters(e.w.T, 1)
	if err := tx1.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-second; !errors.Is(err, oidc.ErrLastCredential) {
		t.Fatalf("second unlink = %v, want ErrLastCredential", err)
	}
	got := e.identities(id)
	if len(got) != 1 || got[0].Provider != "apple" {
		t.Fatalf("identities = %+v, want [apple]", got)
	}
}

func TestResetThenOIDCIsUnknown(t *testing.T) {
	e := acctSetup(t)
	ada := e.w.User("ada@example.invalid", "a long password 1")
	e.addIdentity(ada, "google", "g-ada", "ada.g@example.invalid")
	res, _ := e.signIn("google", e.gUser("g-ada", "ada.g@example.invalid"))
	if res.Session == nil || res.Principal.ID != ada {
		t.Fatalf("sign-in before the reset = %+v; want a session for %v", res, ada)
	}
	ctx := e.w.Ctx
	var reset authkit.Result
	if err := e.w.D.InAuthTx(ctx, func(q db.Querier) error {
		var err error
		reset, err = e.w.Svc.Password.RequestReset(ctx, q, "staff", "ada@example.invalid")
		return err
	}); err != nil || reset.TokenID == nil {
		t.Fatalf("request reset = %+v, %v; want a token", reset, err)
	}
	var raw string
	if err := e.w.D.InGlobalSystemTx(ctx, func(q db.Querier) error {
		m, err := e.w.Svc.OneTime().Mint(ctx, q, *reset.TokenID)
		raw = m.Raw
		return err
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := e.w.D.InAuthTx(ctx, func(q db.Querier) error {
		res, err := e.w.Svc.Password.CompleteReset(ctx, q, "staff", raw, "another long password", acctMeta)
		if err == nil && res.Refusal != nil {
			return res.Refusal
		}
		return err
	}); err != nil {
		t.Fatalf("complete reset: %v", err)
	}
	res, su := e.signIn("google", e.gUser("g-ada", "ada.g@example.invalid"))
	if !errors.Is(res.Refusal, oidc.ErrIdentityUnknown) || su == nil || res.Session != nil {
		t.Fatalf("sign-in after the reset = %+v, sign-up %+v; want ErrIdentityUnknown and no session", res, su)
	}
	if n := e.identityRows(ada); n != 0 {
		t.Fatalf("identities = %d, want 0", n)
	}
}

func TestAccountNeedsTx(t *testing.T) {
	t.Run("sign-up", func(t *testing.T) {
		e := acctSetup(t)
		ada := e.w.User("ada@example.invalid", "a long password 1")
		_, su := e.signIn("google", e.gUser("g-bare", "bare@example.invalid"))
		bare := sqldb.Conn(e.w.Pinned(ada))
		if _, err := e.m.SignUp(e.w.Ctx, bare, su.Ticket, ada, acctAud, acctMeta); !errors.Is(err, db.ErrTxRequired) {
			t.Fatalf("SignUp on a bare connection = %v, want ErrTxRequired", err)
		}
		if _, err := e.ticket(su.Ticket); err != nil {
			t.Fatalf("the ticket after a refused SignUp = %v, want still open", err)
		}
	})
	t.Run("link", func(t *testing.T) {
		e := acctSetup(t)
		ada := e.w.User("ada@example.invalid", "a long password 1")
		cl := e.w.Claims(e.w.SignIn("ada@example.invalid", "a long password 1"))
		bare := sqldb.Conn(e.w.Pinned(ada))
		if _, err := e.m.Link(e.w.Ctx, bare, cl, "google", acctMeta); !errors.Is(err, db.ErrTxRequired) {
			t.Fatalf("Link on a bare connection = %v, want ErrTxRequired", err)
		}
		if n := e.w.Count("SELECT count(*) FROM auth_ceremonies WHERE kind = 'link'"); n != 0 {
			t.Fatalf("link ceremonies = %d, want 0", n)
		}
	})
	t.Run("unlink", func(t *testing.T) {
		e := acctSetup(t)
		ada := e.w.User("ada@example.invalid", "a long password 1")
		e.addIdentity(ada, "google", "g-ada", "")
		cl := e.w.Claims(e.w.SignIn("ada@example.invalid", "a long password 1"))
		bare := sqldb.Conn(e.w.Pinned(ada))
		if err := e.m.Unlink(e.w.Ctx, bare, cl, "google", acctMeta); !errors.Is(err, db.ErrTxRequired) {
			t.Fatalf("Unlink on a bare connection = %v, want ErrTxRequired", err)
		}
		if n := e.identityRows(ada); n != 1 {
			t.Fatalf("identities = %d, want 1", n)
		}
	})
	e := acctSetup(t)
	ada := e.w.User("ada@example.invalid", "a long password 1")
	bare := sqldb.Conn(e.w.Pinned(ada))
	if _, err := e.m.Ticket(e.w.Ctx, bare, "junk"); !errors.Is(err, oidc.ErrTicketUnknown) {
		t.Fatalf("Ticket on a bare connection = %v, want ErrTicketUnknown", err)
	}
	if _, err := e.m.Identities(e.w.Ctx, bare, ada); err != nil {
		t.Fatalf("Identities on a bare connection = %v, want nil", err)
	}
}
