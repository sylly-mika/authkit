package invite_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/invite"
	"github.com/sylly-mika/authkit/onetime"
)

const accAud authkit.Audience = "staff"

const (
	accAda = "ada@example.invalid"
	accBob = "bob@example.invalid"
	accPW  = "a long enough password"
)

var (
	accMeta     = authkit.Meta{IP: "192.0.2.1", UserAgent: "authkit-test"}
	errAccCheck = errors.New("app: the inviter lost authority")
	errAccHeld  = errors.New("app: users: email taken")
)

type accFixture struct {
	*kittest.World
	m         *invite.Module
	mu        sync.Mutex
	race      bool
	createErr error
	checkErr  error
	created   []invite.Pending
	inputs    []string
	joined    []uuid.UUID
}

func newAccFixture(t *testing.T, join bool) *accFixture {
	t.Helper()
	f := &accFixture{World: kittest.New(t)}
	r := invite.Rules{Create: f.create, Check: f.check}
	if join {
		r.Join = f.join
	}
	m, err := invite.New(f.Svc.Service, f.Svc.Password, r)
	if err != nil {
		t.Fatal(err)
	}
	f.m = m
	return f
}

func (f *accFixture) create(ctx context.Context, q db.Querier, p invite.Pending, input json.RawMessage) (authkit.Principal, error) {
	f.mu.Lock()
	f.created, f.inputs = append(f.created, p), append(f.inputs, string(input))
	f.mu.Unlock()
	if f.createErr != nil {
		return authkit.Principal{}, f.createErr
	}
	if f.race {
		f.D.NewPrincipal(f.T, p.Email)
	}
	id := uuid.New()
	n, err := q.Exec(ctx, `INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING`, id, p.Email)
	if err != nil {
		return authkit.Principal{}, err
	}
	if n == 0 {
		return authkit.Principal{}, errAccHeld
	}
	return authkit.Principal{ID: id, Login: p.Email}, nil
}

func (f *accFixture) check(context.Context, db.Querier, invite.Pending) error {
	return f.checkErr
}

func (f *accFixture) join(_ context.Context, _ db.Querier, _ invite.Pending, holder authkit.Principal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.joined = append(f.joined, holder.ID)
	return nil
}

func (f *accFixture) invite(email string) (id, tok uuid.UUID, raw string) {
	f.T.Helper()
	var inv invite.Invited
	if err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		inv, err = f.m.Invite(f.Ctx, q, invite.Request{Audience: accAud, Email: email, Payload: json.RawMessage(`{"role":"member"}`)})
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

func (f *accFixture) accept(raw, pw string) authkit.Result {
	f.T.Helper()
	return f.InAuth(func(q db.Querier) (authkit.Result, error) {
		return f.m.Accept(f.Ctx, q, raw, pw, json.RawMessage(`{"name":"Ada"}`), accMeta)
	})
}

func (f *accFixture) acceptTx(raw, pw string) (authkit.Result, error) {
	f.T.Helper()
	var res authkit.Result
	err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		res, err = f.m.Accept(f.Ctx, q, raw, pw, json.RawMessage(`{"name":"Ada"}`), accMeta)
		return err
	})
	return res, err
}

func (f *accFixture) signedIn(cl *authkit.Claims, raw string) authkit.Result {
	f.T.Helper()
	return f.InAuth(func(q db.Querier) (authkit.Result, error) {
		return f.m.AcceptSignedIn(f.Ctx, q, cl, raw, accMeta)
	})
}

func (f *accFixture) unspent(tok uuid.UUID) int {
	return f.Count(`SELECT count(*) FROM auth_tokens WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL`, tok)
}

func (f *accFixture) used(tok uuid.UUID) int {
	return f.Count(`SELECT count(*) FROM auth_tokens WHERE id = $1 AND used_at IS NOT NULL`, tok)
}

func (f *accFixture) revokedTok(tok uuid.UUID) int {
	return f.Count(`SELECT count(*) FROM auth_tokens WHERE id = $1 AND revoked_at IS NOT NULL`, tok)
}

func (f *accFixture) open(id uuid.UUID) int {
	return f.Count(`SELECT count(*) FROM auth_invites WHERE id = $1 AND accepted_at IS NULL AND revoked_at IS NULL`, id)
}

func (f *accFixture) acceptedBy(id, p uuid.UUID) int {
	return f.Count(`SELECT count(*) FROM auth_invites WHERE id = $1 AND accepted_at IS NOT NULL AND accepted_by = $2`, id, p)
}

func (f *accFixture) revokedRow(id uuid.UUID) int {
	return f.Count(`SELECT count(*) FROM auth_invites WHERE id = $1 AND revoked_at IS NOT NULL AND accepted_at IS NULL`, id)
}

func (f *accFixture) users(email string) int {
	return f.Count(`SELECT count(*) FROM users WHERE email = $1`, email)
}

func (f *accFixture) sessions() int {
	return f.Count(`SELECT count(*) FROM auth_sessions`)
}

func (f *accFixture) creds() int {
	return f.Count(`SELECT count(*) FROM auth_credentials`)
}

func (f *accFixture) events(result string) int {
	return f.Count(`SELECT count(*) FROM auth_events WHERE result = $1 AND source = 'invite'`, result)
}

func (f *accFixture) trail(p uuid.UUID) string {
	f.T.Helper()
	var s string
	if err := f.D.Row(f.T, `SELECT coalesce(string_agg(result || '/' || source, ',' ORDER BY at, result), '') FROM auth_events WHERE principal_id = $1`, p).Scan(&s); err != nil {
		f.T.Fatal(err)
	}
	return s
}

func (f *accFixture) nothingCreated() {
	f.T.Helper()
	if len(f.created) != 0 || f.users(accAda) != 0 || f.creds() != 0 || f.sessions() != 0 {
		f.T.Fatal("a principal, credential or session was created")
	}
}

func (f *accFixture) noRaw(raw string, errs ...error) {
	f.T.Helper()
	for _, err := range errs {
		if err != nil && strings.Contains(err.Error(), raw) {
			f.T.Fatal("an error text carries the link")
		}
	}
	var n int
	if err := f.D.Row(f.T, `SELECT count(*) FROM auth_events e WHERE strpos(row_to_json(e)::text, $1) > 0`, raw).Scan(&n); err != nil {
		f.T.Fatal(err)
	}
	if n != 0 {
		f.T.Fatal("the link is in an audit event")
	}
}

func TestAcceptCreatesAndSignsIn(t *testing.T) {
	f := newAccFixture(t, true)
	id, tok, raw := f.invite(accAda)
	res := f.accept(raw, accPW)
	if res.Refusal != nil || res.Session == nil || res.Tokens == nil || res.Principal.Login != accAda {
		t.Fatalf("refusal %v; want a session for %s", res.Refusal, accAda)
	}
	if len(f.created) != 1 {
		t.Fatalf("Create ran %d times; want once", len(f.created))
	}
	p := f.created[0]
	var payload map[string]string
	if err := json.Unmarshal(p.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if p.ID != id || p.Email != accAda || p.Audience != accAud || payload["role"] != "member" {
		t.Fatalf("Create got invite %v for %s; want the invite's id, address and payload", p.ID, p.Email)
	}
	if f.inputs[0] != `{"name":"Ada"}` {
		t.Fatalf("Create input %s; want the accept's input", f.inputs[0])
	}
	if f.users(accAda) != 1 || f.used(tok) != 1 || f.acceptedBy(id, res.Principal.ID) != 1 {
		t.Fatal("the principal, the spent link or the accepted invite is wrong")
	}
	if got := f.trail(res.Principal.ID); got != "registered/invite,signed_in/invite" {
		t.Fatalf("audit trail %q; want registered and signed in, from the invite", got)
	}
	if r := f.Login(accAud, accAda, accPW); r.Refusal != nil {
		t.Fatalf("password sign-in refused: %v", r.Refusal)
	}
	f.noRaw(raw, res.Refusal)
}

func TestAcceptPolicy(t *testing.T) {
	f := newAccFixture(t, true)
	id, tok, raw := f.invite(accAda)
	res := f.accept(raw, "short")
	var pe authkit.PolicyError
	if !errors.As(res.Refusal, &pe) || res.Session != nil {
		t.Fatalf("refusal %v; want a policy refusal and no session", res.Refusal)
	}
	f.nothingCreated()
	if f.unspent(tok) != 1 || f.open(id) != 1 {
		t.Fatal("a refused password wrote to the link or the invite")
	}
	if f.accept(raw, accPW).Session == nil {
		t.Fatal("the link did not accept a good password after the refusal")
	}
	f.noRaw(raw, res.Refusal)
}

func TestAcceptOnce(t *testing.T) {
	f := newAccFixture(t, true)
	id, _, raw := f.invite(accAda)
	var (
		wg    sync.WaitGroup
		ready = make(chan struct{})
		res   [2]authkit.Result
		errs  [2]error
	)
	for i := range res {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-ready
			errs[i] = f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
				var err error
				res[i], err = f.m.Accept(f.Ctx, q, raw, accPW, json.RawMessage(`{"name":"Ada"}`), accMeta)
				return err
			})
		}(i)
	}
	close(ready)
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("errors %v, %v; want none", errs[0], errs[1])
	}
	var (
		winner authkit.Result
		gone   authkit.ErrTokenGone
		wins   int
		spent  int
	)
	for _, r := range res {
		switch {
		case r.Session != nil:
			winner = r
			wins++
		case errors.As(r.Refusal, &gone):
			spent++
		}
	}
	if wins != 1 || spent != 1 {
		t.Fatalf("refusals %v, %v; want one session and one spent link", res[0].Refusal, res[1].Refusal)
	}
	if f.users(accAda) != 1 || f.sessions() != 1 || f.creds() != 1 || f.events("registered") != 1 || len(f.created) != 1 {
		t.Fatal("two accepts of one link did not make exactly one principal, session, credential and registration")
	}
	if f.acceptedBy(id, winner.Principal.ID) != 1 {
		t.Fatal("the invite was not accepted by the winner")
	}
	f.noRaw(raw, errs[0], errs[1], res[0].Refusal, res[1].Refusal)
}

func TestAcceptRevoked(t *testing.T) {
	want := authkit.ErrTokenGone{State: onetime.StateRevoked}
	t.Run("revoke", func(t *testing.T) {
		f := newAccFixture(t, true)
		id, _, raw := f.invite(accAda)
		if err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error { return f.m.Revoke(f.Ctx, q, id) }); err != nil {
			t.Fatal(err)
		}
		res := f.accept(raw, accPW)
		if res.Refusal != want {
			t.Fatalf("refusal %v; want revoked", res.Refusal)
		}
		var openErr error
		if err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
			_, openErr = f.m.Open(f.Ctx, q, raw)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		var gone authkit.ErrTokenGone
		if !errors.As(openErr, &gone) || gone.State != onetime.StateRevoked {
			t.Fatalf("Open answered %v; want revoked", openErr)
		}
		f.nothingCreated()
		f.noRaw(raw, res.Refusal, openErr)
	})
	t.Run("row", func(t *testing.T) {
		f := newAccFixture(t, true)
		id, tok, raw := f.invite(accAda)
		f.D.Exec(t, "UPDATE auth_invites SET revoked_at = $2 WHERE id = $1", id, f.Clock.Now())
		res := f.accept(raw, accPW)
		if res.Refusal != want {
			t.Fatalf("refusal %v; want revoked", res.Refusal)
		}
		f.nothingCreated()
		if f.unspent(tok) != 1 {
			t.Fatal("a revoked invite spent its link")
		}
		f.noRaw(raw, res.Refusal)
	})
}

func TestAcceptCheckVoids(t *testing.T) {
	f := newAccFixture(t, true)
	id, tok, raw := f.invite(accAda)
	f.checkErr = errAccCheck
	res := f.accept(raw, accPW)
	if res.Refusal != errAccCheck {
		t.Fatalf("refusal %v; want the app's check error", res.Refusal)
	}
	if f.revokedRow(id) != 1 || f.revokedTok(tok) != 1 {
		t.Fatal("a failed check did not void the invite and its link")
	}
	f.nothingCreated()
	f.checkErr = nil
	again := f.accept(raw, accPW)
	if again.Refusal != (authkit.ErrTokenGone{State: onetime.StateRevoked}) {
		t.Fatalf("refusal %v; want the voided link to answer revoked", again.Refusal)
	}
	f.noRaw(raw, res.Refusal, again.Refusal)
}

func TestAcceptCreateError(t *testing.T) {
	f := newAccFixture(t, true)
	id, tok, raw := f.invite(accAda)
	f.createErr = errors.New("app: create failed")
	res, err := f.acceptTx(raw, accPW)
	if !errors.Is(err, f.createErr) || res.Refusal != nil || res.Session != nil {
		t.Fatalf("accept gave error %v and refusal %v; want the create error returned", err, res.Refusal)
	}
	if f.unspent(tok) != 1 || f.open(id) != 1 || f.users(accAda) != 0 || f.creds() != 0 || f.sessions() != 0 || f.events("registered") != 0 {
		t.Fatal("a failed create was not rolled back")
	}
	f.noRaw(raw, err)
}

func TestAcceptCreateRace(t *testing.T) {
	f := newAccFixture(t, true)
	id, tok, raw := f.invite(accAda)
	f.race = true
	res, err := f.acceptTx(raw, accPW)
	f.race = false
	if !errors.Is(err, errAccHeld) || res.Session != nil {
		t.Fatalf("accept gave error %v and session %v; want the held address returned as an error", err, res.Session != nil)
	}
	if f.unspent(tok) != 1 || f.open(id) != 1 || f.users(accAda) != 1 || f.creds() != 0 || f.sessions() != 0 {
		t.Fatal("a racing create left the link spent, or a credential or session behind")
	}
	again := f.accept(raw, accPW)
	if again.Refusal != invite.ErrSignInToAccept {
		t.Fatalf("retry refusal %v; want sign-in to accept", again.Refusal)
	}
	if f.unspent(tok) != 1 || f.open(id) != 1 || f.users(accAda) != 1 {
		t.Fatal("the retry changed the link or the invite")
	}
	f.noRaw(raw, err, again.Refusal)
}

func TestAcceptOldLink(t *testing.T) {
	f := newAccFixture(t, true)
	id, _, raw := f.invite(accAda)
	var re invite.Invited
	if err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		re, err = f.m.Resend(f.Ctx, q, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var mail invite.Mail
	if err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		mail, err = f.m.Mint(f.Ctx, q, re.TokenID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.User(accAda, accPW)
	res := f.accept(raw, accPW)
	if res.Refusal != authkit.ErrTokenUnknown {
		t.Fatalf("refusal %v; want the superseded link to be unknown", res.Refusal)
	}
	if f.open(id) != 1 || len(f.created) != 0 {
		t.Fatal("a superseded link voided the invite or created a principal")
	}
	again := f.accept(mail.Raw, accPW)
	if again.Refusal != invite.ErrSignInToAccept || f.unspent(re.TokenID) != 1 {
		t.Fatalf("the new link refusal %v; want the held address refused, with the link unspent", again.Refusal)
	}
	f.noRaw(raw, res.Refusal)
	f.noRaw(mail.Raw, again.Refusal)
}

func TestAcceptHeld(t *testing.T) {
	f := newAccFixture(t, true)
	id, tok, raw := f.invite(accAda)
	adaID := f.User(accAda, accPW)
	res := f.accept(raw, accPW)
	if res.Refusal != invite.ErrSignInToAccept || res.Session != nil {
		t.Fatalf("refusal %v; want the held address to need a sign-in", res.Refusal)
	}
	if len(f.created) != 0 || f.users(accAda) != 1 || f.creds() != 1 || f.sessions() != 0 {
		t.Fatal("the held address gained a principal, a credential or a session")
	}
	if f.unspent(tok) != 1 || f.open(id) != 1 || f.events("registered") != 0 {
		t.Fatal("a held address spent the link or accepted the invite")
	}
	cl := f.Claims(f.SignIn(accAda, accPW))
	if r := f.signedIn(cl, raw); r.Refusal != nil || r.Principal.ID != adaID {
		t.Fatalf("the signed-in holder got refusal %v; want the link to join it", r.Refusal)
	}
	f.noRaw(raw, res.Refusal)
}

func TestAcceptSignedIn(t *testing.T) {
	f := newAccFixture(t, true)
	adaID := f.User(accAda, accPW)
	id, tok, raw := f.invite(accAda)
	cl := f.Claims(f.SignIn(accAda, accPW))
	n := f.sessions()
	res := f.signedIn(cl, raw)
	if res.Refusal != nil || res.Principal.ID != adaID {
		t.Fatalf("refusal %v; want the holder joined", res.Refusal)
	}
	if res.Session != nil || res.Tokens != nil || res.SessionToken != "" {
		t.Fatal("joining created a session or a token")
	}
	if f.sessions() != n {
		t.Fatal("joining changed the sessions")
	}
	if len(f.joined) != 1 || f.joined[0] != adaID {
		t.Fatalf("Join ran for %v; want the holder once", f.joined)
	}
	if f.acceptedBy(id, adaID) != 1 || f.used(tok) != 1 {
		t.Fatal("the invite or the link was not accepted by the holder")
	}
	if got := f.trail(adaID); !strings.Contains(got, "invite_accepted/invite") {
		t.Fatalf("audit trail %q; want the join recorded from the invite", got)
	}
	if len(f.created) != 0 {
		t.Fatal("joining created a principal")
	}
	f.noRaw(raw, res.Refusal)
}

func TestAcceptSignedInOtherAccount(t *testing.T) {
	f := newAccFixture(t, true)
	f.User(accBob, accPW)
	id, tok, raw := f.invite(accAda)
	cl := f.Claims(f.SignIn(accBob, accPW))
	res := f.signedIn(cl, raw)
	if res.Refusal != invite.ErrOtherAccount {
		t.Fatalf("refusal %v; want the other account refused", res.Refusal)
	}
	if f.unspent(tok) != 1 || f.open(id) != 1 || len(f.joined) != 0 || f.events("invite_accepted") != 0 {
		t.Fatal("another account spent the link, joined or accepted the invite")
	}
	f.noRaw(raw, res.Refusal)
}

func TestAcceptSignedInOtherAudience(t *testing.T) {
	f := newAccFixture(t, true)
	f.User(accAda, accPW)
	id, tok, raw := f.invite(accAda)
	res := f.Login("client", accAda, accPW)
	if res.Refusal != nil {
		t.Fatalf("sign-in to client refused: %v", res.Refusal)
	}
	got := f.signedIn(f.Claims(res), raw)
	if got.Refusal != invite.ErrOtherAccount {
		t.Fatalf("refusal %v; want a session outside the invite's audience refused", got.Refusal)
	}
	if f.unspent(tok) != 1 || f.open(id) != 1 || len(f.joined) != 0 || f.events("invite_accepted") != 0 {
		t.Fatal("a session outside the invite's audience spent the link or joined")
	}
	f.noRaw(raw, got.Refusal)
}

func TestAcceptSignedInEnded(t *testing.T) {
	f := newAccFixture(t, true)
	f.User(accAda, accPW)
	id, tok, raw := f.invite(accAda)
	cl := f.Claims(f.SignIn(accAda, accPW))
	f.InAuth(func(q db.Querier) (authkit.Result, error) {
		return f.Svc.Logout(f.Ctx, q, cl, accMeta)
	})
	res := f.signedIn(cl, raw)
	if res.Refusal != authkit.ErrSessionEnded {
		t.Fatalf("refusal %v; want the ended session refused", res.Refusal)
	}
	if f.unspent(tok) != 1 || f.open(id) != 1 || len(f.joined) != 0 || f.events("invite_accepted") != 0 {
		t.Fatal("an ended session spent the link or joined")
	}
	f.noRaw(raw, res.Refusal)
}

func TestAcceptSignedInNoJoin(t *testing.T) {
	f := newAccFixture(t, false)
	id, tok, raw := f.invite(accAda)
	f.User(accAda, accPW)
	cl := f.Claims(f.SignIn(accAda, accPW))
	res := f.signedIn(cl, raw)
	if res.Refusal != invite.ErrAddressHeld {
		t.Fatalf("refusal %v; want the held address refused without a Join", res.Refusal)
	}
	if f.unspent(tok) != 1 || f.open(id) != 1 || f.events("invite_accepted") != 0 {
		t.Fatal("a module without Join spent the link or accepted the invite")
	}
	f.noRaw(raw, res.Refusal)
}

func TestAcceptSignedInCheckVoids(t *testing.T) {
	f := newAccFixture(t, true)
	f.User(accAda, accPW)
	id, tok, raw := f.invite(accAda)
	cl := f.Claims(f.SignIn(accAda, accPW))
	f.checkErr = errAccCheck
	res := f.signedIn(cl, raw)
	if res.Refusal != errAccCheck {
		t.Fatalf("refusal %v; want the Check refusal", res.Refusal)
	}
	if f.revokedRow(id) != 1 || f.revokedTok(tok) != 1 {
		t.Fatal("a Check refusal did not void the invite and its link")
	}
	if len(f.joined) != 0 || f.events("invite_accepted") != 0 {
		t.Fatal("a Check refusal joined the holder")
	}
	f.noRaw(raw, res.Refusal)
}
