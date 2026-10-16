package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest/oidcfake"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/emailchange"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/invite"
	"github.com/sylly-mika/authkit/oidc"
)

const v7Pass = "an invited password"

func (w *world) withInvite(totp bool) {
	w.T.Helper()
	w.Cfg.Invite = &invite.Rules{
		Create: func(ctx context.Context, q db.Querier, p invite.Pending, _ json.RawMessage) (authkit.Principal, error) {
			id := uuid.New()
			n, err := q.Exec(ctx, `INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING`, id, p.Email)
			if err != nil {
				return authkit.Principal{}, err
			}
			if n == 0 {
				return authkit.Principal{}, fmt.Errorf("users: %w", invite.ErrAddressHeld)
			}
			if totp {
				if _, err := q.Exec(ctx, w.D.SQL(`INSERT INTO auth_second_factors (principal_id, kind, secret, created_at, confirmed_at) VALUES ($1, 'totp', '\x01'::bytea, $2, $2)`), id, w.Clock.Now()); err != nil {
					return authkit.Principal{}, err
				}
			}
			return authkit.Principal{ID: id, Login: p.Email}, nil
		},
		Join: func(context.Context, db.Querier, invite.Pending, authkit.Principal) error { return nil },
	}
	w.Svc = w.Build(w.Cfg)
}

func (w *world) withEmailChange() {
	w.T.Helper()
	w.Cfg.EmailChange = &emailchange.Rules{Change: func(ctx context.Context, q db.Querier, p authkit.Principal, newLogin string) error {
		_, err := q.Exec(ctx, `UPDATE users SET email = $2 WHERE id = $1`, p.ID, newLogin)
		return err
	}}
	w.Svc = w.Build(w.Cfg)
}

func (w *world) inviteLink(email string) string {
	w.T.Helper()
	var raw string
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		inv, err := w.Svc.Invite.Invite(w.Ctx, q, invite.Request{Audience: "staff", Email: email})
		if err != nil {
			return err
		}
		mail, err := w.Svc.Invite.Mint(w.Ctx, q, inv.TokenID)
		raw = mail.Raw
		return err
	}); err != nil {
		w.T.Fatalf("invite link: %v", err)
	}
	return raw
}

func (w *world) acceptInvite(raw, pass string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Invite.Accept(w.Ctx, q, raw, pass, nil, authkit.Meta{})
	})
}

func (w *world) acceptInviteOIDC(raw, ticket string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Invite.AcceptOIDC(w.Ctx, q, raw, ticket, nil, authkit.Meta{})
	})
}

func (w *world) acceptInviteSignedIn(c *authkit.Claims, raw string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Invite.AcceptSignedIn(w.Ctx, q, c, raw, authkit.Meta{})
	})
}

func (w *world) changeEmail(c *authkit.Claims, to string) emailchange.Changed {
	w.T.Helper()
	var raw string
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		st, err := w.Svc.EmailChange.Start(w.Ctx, q, c, to)
		if err != nil {
			return err
		}
		if st.TokenID == nil {
			return fmt.Errorf("start opened no link")
		}
		mail, err := w.Svc.EmailChange.Mint(w.Ctx, q, *st.TokenID)
		raw = mail.Raw
		return err
	}); err != nil {
		w.T.Fatalf("email change link: %v", err)
	}
	var ch emailchange.Changed
	w.InAuth(func(q db.Querier) (authkit.Result, error) {
		var err error
		ch, err = w.Svc.EmailChange.Confirm(w.Ctx, q, raw, authkit.Meta{})
		return authkit.Result{}, err
	})
	return ch
}

// erase is the app's erasure: Forget, then a tombstone in place of the user row.
func (w *world) erase(id uuid.UUID, login string) {
	w.T.Helper()
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		var got uuid.UUID
		if err := q.QueryRow(w.Ctx, "SELECT id FROM users WHERE id = $1 FOR UPDATE", id).Scan(&got); err != nil {
			return err
		}
		if _, err := w.Svc.Forget(w.Ctx, q, authkit.Principal{ID: id, Login: login}); err != nil {
			return err
		}
		_, err := q.Exec(w.Ctx, "UPDATE users SET email = $2 WHERE id = $1", id, "erased-"+id.String()+"@example.invalid")
		return err
	}); err != nil {
		w.T.Fatalf("erase: %v", err)
	}
}

func TestForgetLeavesNoRowAcrossModules(t *testing.T) {
	w := newWorld(t, func(c *kittest.Rules) { c.Throttle.PlainLoginKey = false })
	w.withOIDC(true)
	w.withInvite(false)
	w.withEmailChange()
	seed := func(login string) forgetIDs {
		id := w.User(login, v7Pass)
		w.seedIdentity(id, "google", "g-"+login)
		c := w.Claims(w.SignIn(login, v7Pass))
		w.seedTOTP(id)
		w.InAuth(func(q db.Querier) (authkit.Result, error) {
			return w.Svc.Password.Login(w.Ctx, q, "staff", login, "a wrong password", authkit.Meta{})
		})
		w.inviteLink(login)
		if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
			st, err := w.Svc.EmailChange.Start(w.Ctx, q, c, "new-"+login)
			if err != nil {
				return err
			}
			if st.TokenID == nil {
				return fmt.Errorf("start opened no link")
			}
			_, err = w.Svc.OIDC.BeginReverify(w.Ctx, q, c, "google")
			return err
		}); err != nil {
			w.T.Fatalf("pending changes for %s: %v", login, err)
		}
		var inv uuid.UUID
		if err := w.D.Row(w.T, `SELECT id FROM auth_invites WHERE email = $1`, login).Scan(&inv); err != nil {
			w.T.Fatalf("invite of %s: %v", login, err)
		}
		return forgetIDs{principal: id, session: c.SessionID, invite: inv, login: authkit.Normalize(login), key: kittest.HashedKey(authkit.Normalize(login))}
	}
	ada := seed("ada@example.invalid")
	bob := seed("bob@example.invalid")
	tables := []string{"auth_sessions", "auth_credentials", "auth_tokens", "auth_events", "auth_throttle", "auth_second_factors", "auth_ceremonies", "auth_identities", "auth_email_changes", "auth_invites"}
	for _, c := range forgetChecks {
		if slices.Contains(tables, c.table) && w.countFor(c, ada) == 0 {
			t.Fatalf("before Forget: %s (%s) holds no row for ada", c.table, c.where)
		}
	}
	bobBefore := make([]int, len(forgetChecks))
	for i, c := range forgetChecks {
		bobBefore[i] = w.countFor(c, bob)
	}
	w.forget(authkit.Principal{ID: ada.principal, Login: "ada@example.invalid"})
	for i, c := range forgetChecks {
		if n := w.countFor(c, ada); n != 0 {
			t.Errorf("after Forget: %s (%s) still holds %d row(s) for ada", c.table, c.where, n)
		}
		if n := w.countFor(c, bob); n != bobBefore[i] {
			t.Errorf("after Forget: %s (%s) for bob = %d, was %d", c.table, c.where, n, bobBefore[i])
		}
	}
}

func TestForgetThenOIDCSignsUp(t *testing.T) {
	w := newWorld(t)
	fake := w.withOIDC(true)
	ada := w.User("ada@example.invalid", "")
	w.seedIdentity(ada, "google", "g-ada")
	u := oidcfake.User{Subject: "g-ada", Email: "ada@example.invalid", EmailVerified: true}
	first, _ := w.googleSignIn(fake, u)
	if first.Session == nil {
		t.Fatal("first sign-in opened no session")
	}
	c := w.Claims(first)
	w.erase(ada, "ada@example.invalid")
	res, su := w.googleSignIn(fake, u)
	if !errors.Is(res.Refusal, oidc.ErrIdentityUnknown) {
		t.Errorf("sign-in after erasure = %v, want ErrIdentityUnknown", res.Refusal)
	}
	if su == nil {
		t.Error("sign-in after erasure gave no sign-up ticket")
	}
	if res.Session != nil {
		t.Error("sign-in after erasure opened a session")
	}
	if n := w.sessions(ada); n != 0 {
		t.Errorf("sessions for the erased principal = %d, want 0", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_identities WHERE subject = 'g-ada'`); n != 0 {
		t.Errorf("identities for g-ada = %d, want 0", n)
	}
	if got := w.authenticate(w.Pinned(ada), c); !errors.Is(got.Refusal, authkit.ErrSessionEnded) {
		t.Errorf("Authenticate of the erased session = %v, want ErrSessionEnded", got.Refusal)
	}
}

func TestForgetRacesAccept(t *testing.T) {
	w := newWorld(t)
	w.withInvite(false)
	ada := w.User("ada@example.invalid", v7Pass)
	c := w.Claims(w.SignIn("ada@example.invalid", v7Pass))
	raw := w.inviteLink("ada@example.invalid")
	holder, err := w.D.Owner.BeginTx(w.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(w.Ctx, w.D.SQL("SELECT id FROM auth_tokens WHERE purpose = 'invite' FOR UPDATE")); err != nil {
		t.Fatal(err)
	}
	forgotten := make(chan error, 1)
	go func() {
		forgotten <- w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
			_, err := w.Svc.Forget(w.Ctx, q, authkit.Principal{ID: ada, Login: "ada@example.invalid"})
			return err
		})
	}()
	w.D.WaitForLockWaiters(t, 1)
	var res authkit.Result
	accepted := make(chan error, 1)
	go func() {
		accepted <- w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
			var err error
			res, err = w.Svc.Invite.AcceptSignedIn(w.Ctx, q, c, raw, authkit.Meta{})
			return err
		})
	}()
	w.D.WaitForLockWaiters(t, 2)
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-forgotten; err != nil {
		t.Errorf("Forget: %v", err)
	}
	if err := <-accepted; err != nil {
		t.Errorf("AcceptSignedIn: %v", err)
	}
	if !errors.Is(res.Refusal, authkit.ErrTokenUnknown) {
		t.Errorf("AcceptSignedIn after Forget = %v, want ErrTokenUnknown", res.Refusal)
	}
	if n := w.Count(`SELECT count(*) FROM auth_invites WHERE email = 'ada@example.invalid'`); n != 0 {
		t.Errorf("invites for ada = %d, want 0", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_tokens WHERE purpose = 'invite'`); n != 0 {
		t.Errorf("invite tokens = %d, want 0", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_events WHERE result = 'invite_accepted'`); n != 0 {
		t.Errorf("invite_accepted events = %d, want 0", n)
	}
	if n := w.sessions(ada); n != 0 {
		t.Errorf("sessions for ada = %d, want 0", n)
	}
}

func TestEmailChangeThenInvite(t *testing.T) {
	w := newWorld(t)
	w.withInvite(false)
	w.withEmailChange()
	bob := w.User("bob@example.invalid", v7Pass)
	c := w.Claims(w.SignIn("bob@example.invalid", v7Pass))
	raw := w.inviteLink("carol@example.invalid")
	ch := w.changeEmail(c, "carol@example.invalid")
	if ch.Refusal != nil {
		t.Fatalf("email change to carol: %v", ch.Refusal)
	}
	res := w.acceptInvite(raw, v7Pass)
	if !errors.Is(res.Refusal, invite.ErrSignInToAccept) {
		t.Fatalf("accept by address after the change = %v, want ErrSignInToAccept", res.Refusal)
	}
	if n := w.Count(`SELECT count(*) FROM users`); n != 1 {
		t.Errorf("users after the refusal = %d, want 1", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_tokens WHERE purpose = 'invite' AND used_at IS NULL AND revoked_at IS NULL`); n != 1 {
		t.Errorf("open invite links after the refusal = %d, want 1", n)
	}
	res2 := w.acceptInviteSignedIn(c, raw)
	if res2.Refusal != nil {
		t.Fatalf("signed-in accept: %v", res2.Refusal)
	}
	if res2.Principal.ID != bob {
		t.Errorf("signed-in accept principal = %s, want bob", res2.Principal.ID)
	}
	var by uuid.UUID
	if err := w.D.Row(w.T, `SELECT accepted_by FROM auth_invites WHERE email = 'carol@example.invalid'`).Scan(&by); err != nil {
		t.Fatalf("invite accepted_by: %v", err)
	}
	if by != bob {
		t.Errorf("invite accepted_by = %s, want bob", by)
	}
	if n := w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'invite_accepted'`, bob); n != 1 {
		t.Errorf("invite_accepted events for bob = %d, want 1", n)
	}
	if n := w.sessions(bob); n != 1 {
		t.Errorf("sessions for bob = %d, want 1", n)
	}
}

// WHY: the app's goroutines may log while the test reads the buffer.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestNoSecretInOutput(t *testing.T) {
	var mu sync.Mutex
	var events []string
	w := newWorld(t, func(c *kittest.Rules) {
		c.OnEvent = func(_ context.Context, _ db.Querier, e authkit.Event) error {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, fmt.Sprintf("%+v", e))
			return nil
		}
	})
	logs := &syncBuf{}
	prevLog, prevSlog := log.Writer(), slog.Default()
	log.SetOutput(logs)
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() {
		log.SetOutput(prevLog)
		slog.SetDefault(prevSlog)
	})
	fake := w.withOIDC(true)
	w.withInvite(false)
	w.withEmailChange()

	secrets := map[string]string{}
	var out []string
	see := func(vs ...any) {
		for _, v := range vs {
			out = append(out, fmt.Sprintf("%+v", v))
		}
	}
	call := func(name string, fn func(q db.Querier) error) {
		t.Helper()
		if err := w.D.InAuthTx(w.Ctx, fn); err != nil {
			t.Fatalf("%s: unexpected error", name)
		}
	}
	meta := authkit.Meta{IP: "192.0.2.1", UserAgent: "authkit-test"}

	ada := w.User("ada@example.invalid", "ada's first password")
	c := w.Claims(w.SignIn("ada@example.invalid", "ada's first password"))
	secrets["password"] = "ada's first password"

	raw := w.inviteLink("carol@example.invalid")
	secrets["invite link"] = raw
	call("Invite.Open", func(q db.Querier) error {
		opened, err := w.Svc.Invite.Open(w.Ctx, q, raw)
		see(opened, err)
		return err
	})
	secrets["invite password"] = "carol's new password"
	call("Invite.Accept", func(q db.Querier) error {
		res, err := w.Svc.Invite.Accept(w.Ctx, q, raw, "carol's new password", nil, meta)
		see(res, err)
		return err
	})
	call("Invite.Accept again", func(q db.Querier) error {
		res, err := w.Svc.Invite.Accept(w.Ctx, q, raw, "carol's new password", nil, meta)
		see(res, err)
		return nil
	})

	_, su := w.googleSignIn(fake, oidcfake.User{Subject: "g-erin", Email: "erin@example.invalid", EmailVerified: true})
	if su == nil {
		t.Fatal("the erin sign-up opened no ticket")
	}
	raw2 := w.inviteLink("dan@example.invalid")
	secrets["invite link 2"] = raw2
	secrets["ticket"] = su.Ticket
	call("Invite.AcceptOIDC mismatch", func(q db.Querier) error {
		_, refused := w.Svc.Invite.AcceptOIDC(w.Ctx, q, raw2, su.Ticket, nil, meta)
		see(refused)
		return nil
	})
	_, su2 := w.googleSignIn(fake, oidcfake.User{Subject: "g-dan", Email: "dan@example.invalid", EmailVerified: true})
	if su2 == nil {
		t.Fatal("the dan sign-up opened no ticket")
	}
	secrets["ticket 2"] = su2.Ticket
	call("Invite.AcceptOIDC", func(q db.Querier) error {
		res, err := w.Svc.Invite.AcceptOIDC(w.Ctx, q, raw2, su2.Ticket, nil, meta)
		see(res, err)
		return err
	})
	call("OIDC.TicketEmail", func(q db.Querier) error {
		email, private, err := w.Svc.OIDC.TicketEmail(w.Ctx, q, su2.Ticket)
		see(email, private, err)
		return nil
	})

	raw3 := w.inviteLink("ada@example.invalid")
	secrets["invite link 3"] = raw3
	call("Invite.AcceptSignedIn", func(q db.Querier) error {
		res, err := w.Svc.Invite.AcceptSignedIn(w.Ctx, q, c, raw3, meta)
		see(res, err)
		return err
	})

	secrets["wrong password"] = "a wrong password 1"
	call("Password.Reverify wrong", func(q db.Querier) error {
		res, err := w.Svc.Password.Reverify(w.Ctx, q, c, "a wrong password 1", meta)
		see(res, err)
		return nil
	})
	call("Password.Reverify", func(q db.Querier) error {
		res, err := w.Svc.Password.Reverify(w.Ctx, q, c, "ada's first password", meta)
		see(res, err)
		return err
	})

	w.seedIdentity(ada, "google", "g-ada")
	var r oidc.Redirect
	call("OIDC.BeginReverify", func(q db.Querier) error {
		var err error
		r, err = w.Svc.OIDC.BeginReverify(w.Ctx, q, c, "google")
		return err
	})
	u, err := url.Parse(r.URL)
	if err != nil {
		t.Fatal("the reverify redirect is not a URL")
	}
	secrets["binding"] = r.Binding
	secrets["nonce"] = u.Query().Get("nonce")
	cb := fake.Authorize(t, r, oidcfake.User{Subject: "g-ada", Email: "ada@example.invalid", EmailVerified: true})
	secrets["state"] = cb.State
	secrets["code"] = cb.Code
	call("OIDC.FinishReverify", func(q db.Querier) error {
		res, err := w.Svc.OIDC.FinishReverify(w.Ctx, q, c, cb, r.Binding, meta)
		see(res, err)
		return err
	})

	var st emailchange.Started
	call("EmailChange.Start", func(q db.Querier) error {
		var err error
		st, err = w.Svc.EmailChange.Start(w.Ctx, q, c, "ada.new@example.invalid")
		return err
	})
	if st.TokenID == nil {
		t.Fatal("the email change opened no link")
	}
	var ecRaw string
	call("EmailChange.Mint", func(q db.Querier) error {
		mail, err := w.Svc.EmailChange.Mint(w.Ctx, q, *st.TokenID)
		ecRaw = mail.Raw
		return err
	})
	secrets["email change link"] = ecRaw
	call("EmailChange.Confirm", func(q db.Querier) error {
		ch, err := w.Svc.EmailChange.Confirm(w.Ctx, q, ecRaw, meta)
		see(ch, err)
		return err
	})
	call("EmailChange.Confirm again", func(q db.Querier) error {
		ch, err := w.Svc.EmailChange.Confirm(w.Ctx, q, ecRaw, meta)
		see(ch, err)
		return nil
	})
	p := authkit.Principal{ID: ada, Login: "ada.new@example.invalid"}
	call("EmailChange.Pending", func(q db.Querier) error {
		pend, err := w.Svc.EmailChange.Pending(w.Ctx, q, p)
		see(pend, err)
		return err
	})
	call("EmailChange.Cancel", func(q db.Querier) error {
		err := w.Svc.EmailChange.Cancel(w.Ctx, q, p)
		see(err)
		return err
	})

	for name, v := range secrets {
		if v == "" {
			t.Fatalf("the %s is empty", name)
		}
	}
	mu.Lock()
	evs, n := strings.Join(events, "\n"), len(events)
	mu.Unlock()
	if n == 0 {
		t.Fatal("OnEvent never ran")
	}
	var dump string
	if err := w.D.Row(t, `SELECT coalesce(string_agg(row_to_json(e)::text, ' '), '') FROM auth_events e`).Scan(&dump); err != nil {
		t.Fatalf("auth_events: %v", err)
	}
	outputs := []struct{ where, text string }{
		{"a result or error", strings.Join(out, "\n")},
		{"an OnEvent event", evs},
		{"the log", logs.String()},
		{"auth_events", dump},
	}
	for name, v := range secrets {
		for _, o := range outputs {
			if strings.Contains(o.text, v) {
				t.Errorf("the %s appears in %s", name, o.where)
			}
		}
	}
}
