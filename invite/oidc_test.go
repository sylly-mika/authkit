package invite_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest/oidcfake"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/invite"
	"github.com/sylly-mika/authkit/oidc"
)

var _ invite.Tickets = (*oidc.Module)(nil)

var oidcInput = json.RawMessage(`{"name":"Ada"}`)

type oidcFixture struct {
	*accFixture
	om            *oidc.Module
	google, apple *oidcfake.Server
	refuse        error
}

func newOIDCFixture(t *testing.T, wired bool) *oidcFixture {
	t.Helper()
	f := &oidcFixture{accFixture: &accFixture{World: kittest.New(t)}}
	f.google, f.apple = oidcfake.New(t, oidcfake.Google), oidcfake.New(t, oidcfake.Apple)
	f.google.Now, f.apple.Now = f.Clock.Now, f.Clock.Now
	// WHY: every httptest TLS server serves the same built-in certificate, so one fake's Client trusts both.
	om, err := oidc.New(f.Svc.Service, oidc.Rules{HTTPClient: f.google.Client, Providers: []oidc.Provider{
		f.google.Provider("https://app.example.invalid/oidc/google/callback"), f.apple.Provider("https://app.example.invalid/oidc/apple/callback")}})
	if err != nil {
		t.Fatal(err)
	}
	f.om = om
	r := invite.Rules{Create: f.createOIDC, Check: f.check, Join: f.join}
	if wired {
		r.OIDC = om
	}
	if f.m, err = invite.New(f.Svc.Service, f.Svc.Password, r); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *oidcFixture) createOIDC(ctx context.Context, q db.Querier, p invite.Pending, input json.RawMessage) (authkit.Principal, error) {
	pr, err := f.create(ctx, q, p, input)
	if err == nil && f.refuse != nil {
		f.P.Refuse(pr.ID, f.refuse)
	}
	return pr, err
}

func (f *oidcFixture) ticket(provider string, u oidcfake.User) string {
	f.T.Helper()
	var r oidc.Redirect
	if err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		r, err = f.om.Begin(f.Ctx, q, provider, accAud, accMeta)
		return err
	}); err != nil {
		f.T.Fatalf("begin %s: %v", provider, err)
	}
	fake := f.google
	if provider == "apple" {
		fake = f.apple
	}
	cb := fake.Authorize(f.T, r, u)
	var su *oidc.SignUp
	if err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		_, su, err = f.om.Finish(f.Ctx, q, cb, r.Binding, accMeta)
		return err
	}); err != nil {
		f.T.Fatalf("finish %s: %v", provider, err)
	}
	if su == nil {
		f.T.Fatal("finish: no sign-up ticket")
	}
	return su.Ticket
}

func (f *oidcFixture) gUser(sub, email string) oidcfake.User {
	return oidcfake.User{Subject: sub, Email: email, EmailVerified: true, GivenName: "Ada"}
}

func (f *oidcFixture) acceptOIDC(raw, tk string) authkit.Result {
	f.T.Helper()
	return f.InAuth(func(q db.Querier) (authkit.Result, error) {
		return f.m.AcceptOIDC(f.Ctx, q, raw, tk, oidcInput, accMeta)
	})
}

func (f *oidcFixture) acceptOIDCTx(raw, tk string) (authkit.Result, error) {
	f.T.Helper()
	var res authkit.Result
	err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		res, err = f.m.AcceptOIDC(f.Ctx, q, raw, tk, oidcInput, accMeta)
		return err
	})
	return res, err
}

func (f *oidcFixture) inviteIn(email string, scope uuid.UUID) (id, tok uuid.UUID, raw string) {
	f.T.Helper()
	var inv invite.Invited
	if err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		inv, err = f.m.Invite(f.Ctx, q, invite.Request{Audience: accAud, Email: email, ScopeID: &scope, Payload: json.RawMessage(`{"role":"member"}`)})
		return err
	}); err != nil {
		f.T.Fatal(err)
	}
	var mail invite.Mail
	if err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		mail, err = f.m.Mint(f.Ctx, q, inv.TokenID)
		return err
	}); err != nil {
		f.T.Fatal(err)
	}
	return inv.ID, inv.TokenID, mail.Raw
}

func (f *oidcFixture) openTickets() int {
	return f.Count("SELECT count(*) FROM auth_ceremonies WHERE kind = 'signup' AND spent_at IS NULL")
}

func (f *oidcFixture) idents(sub string) int {
	return f.Count("SELECT count(*) FROM auth_identities WHERE subject = $1", sub)
}

func (f *oidcFixture) identOf(sub string, p uuid.UUID) int {
	return f.Count("SELECT count(*) FROM auth_identities WHERE subject = $1 AND principal_id = $2", sub, p)
}

func (f *oidcFixture) oidcSessions(p uuid.UUID) int {
	return f.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND second_factor = 'oidc'", p)
}

func (f *oidcFixture) oidcSignedIn(p uuid.UUID) int {
	return f.Count("SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'signed_in' AND source = 'oidc' AND second_factor = 'oidc'", p)
}

func (f *oidcFixture) linkLive(id, tok uuid.UUID) {
	f.T.Helper()
	if f.unspent(tok) != 1 || f.open(id) != 1 {
		f.T.Fatal("the invite link is not live")
	}
}

func (f *oidcFixture) ticketLive() {
	f.T.Helper()
	if f.openTickets() != 1 {
		f.T.Fatal("the sign-up ticket is not live")
	}
}

func (f *oidcFixture) nothingMade(login string) {
	f.T.Helper()
	if len(f.created) != 0 || f.users(login) != 0 || f.creds() != 0 || f.sessions() != 0 {
		f.T.Fatal("a principal, credential or session was created")
	}
}

func (f *oidcFixture) clean(res authkit.Result, errs []error, secrets ...string) {
	f.T.Helper()
	for _, s := range secrets {
		f.noRaw(s, errs...)
		if strings.Contains(fmt.Sprintf("%+v", res), s) {
			f.T.Fatal("the result carries a secret")
		}
	}
}

func TestAcceptOIDC(t *testing.T) {
	f := newOIDCFixture(t, true)
	id, tok, raw := f.invite(accAda)
	tk := f.ticket("google", f.gUser("g-ada", "Ada@Example.invalid"))
	res := f.acceptOIDC(raw, tk)
	if res.Refusal != nil || res.Session == nil || res.Principal.Login != accAda {
		t.Fatalf("AcceptOIDC = %+v; want a session for %s", res, accAda)
	}
	if len(f.created) != 1 || f.created[0].ID != id || f.created[0].Email != accAda {
		t.Fatalf("Create = %+v; want one principal for invite %s", f.created, id)
	}
	if f.inputs[0] != `{"name":"Ada"}` {
		t.Fatalf("Create input = %s; want {\"name\":\"Ada\"}", f.inputs[0])
	}
	p := res.Principal.ID
	if f.users(accAda) != 1 || f.creds() != 0 || f.identOf("g-ada", p) != 1 || f.oidcSessions(p) != 1 {
		t.Fatal("the principal, identity or session is not as the sign-up made it")
	}
	if f.openTickets() != 0 || f.used(tok) != 1 || f.acceptedBy(id, p) != 1 {
		t.Fatal("the ticket or the link is not spent, or the invite is not accepted by the principal")
	}
	if got := f.trail(p); got != "registered/invite,signed_in/oidc" {
		t.Fatalf("trail = %q; want registered/invite,signed_in/oidc", got)
	}
	if f.oidcSignedIn(p) != 1 {
		t.Fatal("no signed_in event with factor oidc")
	}
	f.clean(res, nil, raw, tk)
}

func TestAcceptOIDCMismatch(t *testing.T) {
	f := newOIDCFixture(t, true)
	id, tok, raw := f.invite(accAda)
	tk := f.ticket("google", f.gUser("g-bob", accBob))
	res := f.acceptOIDC(raw, tk)
	if res.Refusal != invite.ErrEmailMismatch || res.Session != nil {
		t.Fatalf("AcceptOIDC = %+v; want ErrEmailMismatch and no session", res)
	}
	f.nothingMade(accAda)
	if f.idents("g-bob") != 0 || f.events("registered") != 0 {
		t.Fatal("an identity or a registered event was written")
	}
	f.linkLive(id, tok)
	f.ticketLive()
	f.clean(res, nil, raw, tk)
}

func TestAcceptOIDCPrivate(t *testing.T) {
	f := newOIDCFixture(t, true)
	const relay = "x7@privaterelay.appleid.com"
	id, tok, raw := f.invite(relay)
	tk := f.ticket("apple", oidcfake.User{Subject: "a-x7", Email: relay, EmailVerified: true, PrivateEmail: true})
	res := f.acceptOIDC(raw, tk)
	if res.Refusal != invite.ErrPrivateEmail || res.Session != nil {
		t.Fatalf("AcceptOIDC = %+v; want ErrPrivateEmail and no session", res)
	}
	f.nothingMade(relay)
	if f.idents("a-x7") != 0 {
		t.Fatal("an identity was written")
	}
	f.linkLive(id, tok)
	f.ticketLive()
	f.clean(res, nil, raw, tk)
}

func TestAcceptOIDCHeld(t *testing.T) {
	f := newOIDCFixture(t, true)
	id, tok, raw := f.invite(accAda)
	tk := f.ticket("google", f.gUser("g-ada", accAda))
	adaID := f.User(accAda, accPW)
	res := f.acceptOIDC(raw, tk)
	if res.Refusal != invite.ErrSignInToAccept {
		t.Fatalf("AcceptOIDC = %+v; want ErrSignInToAccept", res)
	}
	if len(f.created) != 0 || f.users(accAda) != 1 || f.idents("g-ada") != 0 || f.sessions() != 0 || f.events("registered") != 0 {
		t.Fatal("a principal, identity, session or registered event was written for a held address")
	}
	f.linkLive(id, tok)
	f.ticketLive()
	held := f.signedIn(f.Claims(f.SignIn(accAda, accPW)), raw)
	if held.Refusal != nil || held.Principal.ID != adaID {
		t.Fatalf("signed-in accept = %+v; want the holder %s", held, adaID)
	}
	f.clean(res, nil, raw, tk)
}

func TestAcceptOIDCNoOIDC(t *testing.T) {
	f := newOIDCFixture(t, false)
	id, tok, raw := f.invite(accAda)
	tk := f.ticket("google", f.gUser("g-ada", accAda))
	res, err := f.acceptOIDCTx(raw, tk)
	if !errors.Is(err, invite.ErrNoOIDC) || res.Refusal != nil || res.Session != nil {
		t.Fatalf("AcceptOIDC = %+v, %v; want ErrNoOIDC and no result", res, err)
	}
	f.nothingMade(accAda)
	f.linkLive(id, tok)
	f.ticketLive()
	f.clean(res, []error{err}, raw, tk)
}

func TestAcceptOIDCTicketUnknown(t *testing.T) {
	check := func(t *testing.T, f *oidcFixture, id, tok uuid.UUID, raw, tk string) {
		t.Helper()
		res, err := f.acceptOIDCTx(raw, tk)
		if !errors.Is(err, oidc.ErrTicketUnknown) || res.Refusal != nil || res.Session != nil {
			t.Fatalf("AcceptOIDC = %+v, %v; want ErrTicketUnknown and no result", res, err)
		}
		if len(f.created) != 0 {
			t.Fatal("a principal was created for an unknown ticket")
		}
		f.linkLive(id, tok)
		if f.users(accAda) != 0 || f.events("registered") != 0 {
			t.Fatal("a principal or a registered event survived the rollback")
		}
		f.clean(res, []error{err}, raw, tk)
	}
	t.Run("unknown", func(t *testing.T) {
		f := newOIDCFixture(t, true)
		id, tok, raw := f.invite(accAda)
		check(t, f, id, tok, raw, "no-such-ticket")
	})
	t.Run("expired", func(t *testing.T) {
		f := newOIDCFixture(t, true)
		id, tok, raw := f.invite(accAda)
		tk := f.ticket("google", f.gUser("g-ada", accAda))
		f.Clock.Advance(10 * time.Minute)
		check(t, f, id, tok, raw, tk)
	})
}

func TestAcceptOIDCAdmitRefused(t *testing.T) {
	f := newOIDCFixture(t, true)
	errNo := errors.New("app: no membership")
	f.refuse = errNo
	id, tok, raw := f.invite(accAda)
	tk := f.ticket("google", f.gUser("g-ada", accAda))
	res, err := f.acceptOIDCTx(raw, tk)
	f.refuse = nil
	if err == nil || !errors.Is(err, errNo) || err.Error() != "invite: the new principal was not admitted: app: no membership" {
		t.Fatalf("AcceptOIDC error = %v; want the wrapped admit refusal", err)
	}
	if res.Refusal != nil || res.Session != nil {
		t.Fatalf("AcceptOIDC result = %+v; want a zero result", res)
	}
	if f.users(accAda) != 0 || f.idents("g-ada") != 0 || f.sessions() != 0 || f.Count("SELECT count(*) FROM auth_events") != 0 {
		t.Fatal("the rollback left a principal, identity, session or event")
	}
	f.linkLive(id, tok)
	f.ticketLive()
	again := f.acceptOIDC(raw, tk)
	if again.Session == nil {
		t.Fatalf("AcceptOIDC after the refusal = %+v; want a session", again)
	}
	f.clean(res, []error{err}, raw, tk)
}

func TestAcceptOIDCIdentityTaken(t *testing.T) {
	f := newOIDCFixture(t, true)
	id, tok, raw := f.invite(accAda)
	tk := f.ticket("google", f.gUser("g-ada", accAda))
	bob := f.User(accBob, accPW)
	f.D.Exec(t, "INSERT INTO auth_identities (id, principal_id, provider, subject, email, created_at) VALUES ($1, $2, 'google', 'g-ada', $3, $4)", uuid.New(), bob, accBob, f.Clock.Now())
	res, err := f.acceptOIDCTx(raw, tk)
	if !errors.Is(err, oidc.ErrIdentityTaken) || res.Session != nil {
		t.Fatalf("AcceptOIDC = %+v, %v; want ErrIdentityTaken and no session", res, err)
	}
	if f.users(accAda) != 0 || f.idents("g-ada") != 1 || f.identOf("g-ada", bob) != 1 || f.sessions() != 0 {
		t.Fatal("the rollback left a principal or session, or the taken identity moved")
	}
	f.linkLive(id, tok)
	f.ticketLive()
	f.clean(res, []error{err}, raw, tk)
}

func TestAcceptRacesAcceptOIDC(t *testing.T) {
	f := newOIDCFixture(t, true)
	_, _, raw := f.invite(accAda)
	tk := f.ticket("google", f.gUser("g-ada", accAda))
	ready := make(chan struct{})
	var wg sync.WaitGroup
	var resA, resB authkit.Result
	var errA, errB error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-ready
		errA = f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
			var err error
			resA, err = f.m.Accept(f.Ctx, q, raw, accPW, oidcInput, accMeta)
			return err
		})
	}()
	go func() {
		defer wg.Done()
		<-ready
		errB = f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
			var err error
			resB, err = f.m.AcceptOIDC(f.Ctx, q, raw, tk, oidcInput, accMeta)
			return err
		})
	}()
	close(ready)
	wg.Wait()
	if errA != nil || errB != nil {
		t.Fatalf("errors: A = %v, B = %v; want none", errA, errB)
	}
	var gone authkit.ErrTokenGone
	aWon := resA.Session != nil
	if aWon == (resB.Session != nil) {
		t.Fatalf("results: A = %+v, B = %+v; want exactly one session", resA, resB)
	}
	if aWon && !errors.As(resB.Refusal, &gone) || !aWon && !errors.As(resA.Refusal, &gone) {
		t.Fatal("the losing accept was not refused as a gone link")
	}
	if f.users(accAda) != 1 || f.sessions() != 1 || f.events("registered") != 1 || len(f.created) != 1 {
		t.Fatal("the race left more or fewer than one principal, session or registration")
	}
	if !aWon {
		if f.idents("g-ada") != 1 || f.openTickets() != 0 || f.creds() != 0 {
			t.Fatal("OIDC won but the identity, ticket or credential is not as the sign-up made it")
		}
	} else {
		if f.idents("g-ada") != 0 || f.openTickets() != 1 || f.creds() != 1 {
			t.Fatal("password won but the identity, ticket or credential is not as the password made it")
		}
	}
	f.clean(resA, []error{errA, errB}, raw, tk)
	f.clean(resB, nil, raw, tk)
}

func TestTicketReplaySecondInvite(t *testing.T) {
	f := newOIDCFixture(t, true)
	id1, _, raw1 := f.inviteIn(accAda, uuid.New())
	id2, tok2, raw2 := f.inviteIn(accAda, uuid.New())
	tk := f.ticket("google", f.gUser("g-ada", accAda))
	first := f.acceptOIDC(raw1, tk)
	if first.Session == nil || f.acceptedBy(id1, first.Principal.ID) != 1 {
		t.Fatalf("first AcceptOIDC = %+v; want a session and the first invite accepted", first)
	}
	f.D.Exec(t, "DELETE FROM users WHERE id = $1", first.Principal.ID)
	if f.idents("g-ada") != 0 {
		t.Fatal("the principal's identity survived its delete")
	}
	res, err := f.acceptOIDCTx(raw2, tk)
	if !errors.Is(err, oidc.ErrTicketUnknown) || res.Session != nil {
		t.Fatalf("replay = %+v, %v; want ErrTicketUnknown and no session", res, err)
	}
	if f.unspent(tok2) != 1 || f.open(id2) != 1 || f.users(accAda) != 0 || f.idents("g-ada") != 0 || len(f.created) != 1 {
		t.Fatal("the rollback left the second invite spent or a principal behind")
	}
	f.clean(res, []error{err}, raw2, tk)
}

func TestAcceptOIDCCheckVoids(t *testing.T) {
	f := newOIDCFixture(t, true)
	id, tok, raw := f.invite(accAda)
	tk := f.ticket("google", f.gUser("g-ada", accAda))
	f.checkErr = errAccCheck
	res := f.acceptOIDC(raw, tk)
	if res.Refusal != errAccCheck {
		t.Fatalf("AcceptOIDC = %+v; want the Check refusal", res)
	}
	if f.revokedRow(id) != 1 || f.revokedTok(tok) != 1 {
		t.Fatal("the Check refusal did not void the invite and its link")
	}
	f.nothingMade(accAda)
	if f.idents("g-ada") != 0 {
		t.Fatal("an identity was written")
	}
	f.ticketLive()
	f.clean(res, nil, raw, tk)
}
