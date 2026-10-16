package emailchange_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/emailchange"
	"github.com/sylly-mika/authkit/onetime"
)

var cmeta = authkit.Meta{IP: "192.0.2.9", UserAgent: "authkit-test"}

func (f *fixture) link(cl *authkit.Claims) string {
	f.T.Helper()
	return f.minted(f.start(cl, addr))
}

func (f *fixture) linkFor() string {
	f.T.Helper()
	return f.minted(f.startFor(ada, addr))
}

func (f *fixture) minted(st emailchange.Started) string {
	f.T.Helper()
	if st.TokenID == nil {
		f.T.Fatal("Start gave no TokenID")
	}
	mail, err := f.mint(*st.TokenID)
	if err != nil {
		f.T.Fatal(err)
	}
	return mail.Raw
}

func (f *fixture) confirm(raw string) (emailchange.Changed, error) {
	f.T.Helper()
	var ch emailchange.Changed
	err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		ch, err = f.EC.Confirm(f.Ctx, q, raw, cmeta)
		return err
	})
	f.noRaw(raw, ch, err)
	return ch, err
}

func (f *fixture) noRaw(raw string, ch emailchange.Changed, err error) {
	f.T.Helper()
	if strings.Contains(fmt.Sprintf("%+v", ch), raw) {
		f.T.Fatal("Changed carries the raw link token")
	}
	if err != nil && strings.Contains(err.Error(), raw) {
		f.T.Fatal("the error carries the raw link token")
	}
	if n := f.Count("SELECT count(*) FROM auth_events WHERE position($1 in concat_ws(' ', login, ip, user_agent, result, source)) > 0", raw); n != 0 {
		f.T.Fatalf("%d auth_events rows carry the raw link token", n)
	}
}

func (f *fixture) refusal(cl *authkit.Claims) error {
	f.T.Helper()
	var res authkit.Result
	err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		res, err = f.Svc.Authenticate(f.Ctx, q, cl)
		return err
	})
	if err != nil {
		f.T.Fatal(err)
	}
	return res.Refusal
}

func (f *fixture) changed() int {
	return f.Count("SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'email_changed'", f.ID)
}

func (f *fixture) reason(cl *authkit.Claims) string {
	f.T.Helper()
	var r string
	if err := f.D.Row(f.T, "SELECT coalesce(revoke_reason, '') FROM auth_sessions WHERE id = $1", cl.SessionID).Scan(&r); err != nil {
		f.T.Fatal(err)
	}
	return r
}

func (f *fixture) assertUnchanged() {
	f.T.Helper()
	if f.login() != ada || f.changes != 0 || f.changed() != 0 {
		f.T.Fatalf("login %q, Change calls %d, email_changed events %d; want %q, 0, 0", f.login(), f.changes, f.changed(), ada)
	}
}

func TestConfirm(t *testing.T) {
	f := newFixture(t)
	cl := f.session()
	raw := f.link(cl)
	ch, err := f.confirm(raw)
	if err != nil || ch.Refusal != nil {
		t.Fatalf("Confirm = refusal %v, err %v; want a change", ch.Refusal, err)
	}
	if ch.Old != ada || ch.New != addr || ch.Principal != (authkit.Principal{ID: f.ID, Login: addr}) {
		t.Fatalf("Confirm = %+v; want %q to %q", ch, ada, addr)
	}
	if f.login() != addr || f.changes != 1 || f.rows() != 0 {
		t.Fatalf("login %q, Change calls %d, change rows %d; want %q, 1, 0", f.login(), f.changes, f.rows(), addr)
	}
	if f.pending() != nil {
		t.Fatal("the change is still pending after Confirm")
	}
	if st := f.peek(raw).State; st != onetime.StateUsed {
		t.Fatalf("link state = %v; want used", st)
	}
	var login, source, audience, ip string
	if err := f.D.Row(f.T, `SELECT login, source, audience, ip FROM auth_events WHERE principal_id = $1 AND result = 'email_changed'`, f.ID).
		Scan(&login, &source, &audience, &ip); err != nil {
		t.Fatal(err)
	}
	if n := f.changed(); n != 1 || login != addr || source != "email_change" || audience != "staff" || ip != "192.0.2.9" {
		t.Fatalf("email_changed events %d: login %q, source %q, audience %q, ip %q; want 1, %q, email_change, staff, 192.0.2.9", n, login, source, audience, ip, addr)
	}
}

func TestConfirmWrongPurpose(t *testing.T) {
	f := newFixture(t)
	t0 := f.Clock.Now()
	cl := f.session()
	raw := f.link(cl)
	var reset string
	err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		id, err := f.Svc.OneTime().Create(f.Ctx, q, authkit.PurposeReset, f.ID, time.Hour)
		if err != nil {
			return err
		}
		mt, err := f.Svc.OneTime().Mint(f.Ctx, q, id)
		reset = mt.Raw
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	ch, err := f.confirm(reset)
	if err != nil || ch.Refusal != authkit.ErrTokenUnknown {
		t.Fatalf("Confirm with a reset link = refusal %v, err %v; want ErrTokenUnknown", ch.Refusal, err)
	}
	f.assertUnchanged()
	p := f.pending()
	if p == nil || p.Old != ada || p.New != addr || !p.ExpiresAt.Equal(t0.Add(24*time.Hour)) {
		t.Fatalf("pending = %+v; want %q to %q, expiring at %v", p, ada, addr, t0.Add(24*time.Hour))
	}
	if f.peek(reset).State != onetime.StateLive || f.peek(raw).State != onetime.StateLive {
		t.Fatal("a refused purpose spent a link")
	}
}

func TestConfirmOnce(t *testing.T) {
	f := newFixture(t)
	cl := f.session()
	raw := f.link(cl)
	if ch, err := f.confirm(raw); err != nil || ch.Refusal != nil {
		t.Fatalf("first Confirm = refusal %v, err %v; want a change", ch.Refusal, err)
	}
	ch, err := f.confirm(raw)
	var gone authkit.ErrTokenGone
	if err != nil || !errors.As(ch.Refusal, &gone) || gone.State != onetime.StateUsed {
		t.Fatalf("second Confirm = refusal %v, err %v; want ErrTokenGone used", ch.Refusal, err)
	}
	if f.login() != addr || f.changes != 1 || f.changed() != 1 {
		t.Fatalf("login %q, Change calls %d, email_changed events %d; want %q, 1, 1", f.login(), f.changes, f.changed(), addr)
	}
}

func TestConfirmUnknown(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		f := newFixture(t)
		raw := f.link(f.session())
		f.Clock.Advance(24*time.Hour + time.Second)
		ch, err := f.confirm(raw)
		var gone authkit.ErrTokenGone
		if err != nil || !errors.As(ch.Refusal, &gone) || gone.State != onetime.StateExpired {
			t.Fatalf("Confirm of an expired link = refusal %v, err %v; want ErrTokenGone expired", ch.Refusal, err)
		}
		f.assertUnchanged()
	})
	t.Run("cancelled", func(t *testing.T) {
		f := newFixture(t)
		raw := f.link(f.session())
		f.cancel()
		ch, err := f.confirm(raw)
		var gone authkit.ErrTokenGone
		if err != nil || !errors.As(ch.Refusal, &gone) || gone.State != onetime.StateRevoked {
			t.Fatalf("Confirm of a cancelled link = refusal %v, err %v; want ErrTokenGone revoked", ch.Refusal, err)
		}
		f.assertUnchanged()
	})
	t.Run("replaced", func(t *testing.T) {
		f := newFixture(t)
		cl := f.session()
		raw := f.link(cl)
		f.start(cl, "a2@example.invalid")
		ch, err := f.confirm(raw)
		if err != nil || ch.Refusal != authkit.ErrTokenUnknown {
			t.Fatalf("Confirm of a replaced link = refusal %v, err %v; want ErrTokenUnknown", ch.Refusal, err)
		}
		if p := f.pending(); p == nil || p.New != "a2@example.invalid" {
			t.Fatalf("pending = %+v; want the replacement kept", p)
		}
		f.assertUnchanged()
	})
}

func TestConfirmStale(t *testing.T) {
	f := newFixture(t)
	cl := f.session()
	raw := f.link(cl)
	c2 := f.session()
	f.D.Exec(f.T, "UPDATE users SET email = $1 WHERE id = $2", "ada.other@example.invalid", f.ID)
	ch, err := f.confirm(raw)
	if err != nil || ch.Refusal != emailchange.ErrStale {
		t.Fatalf("Confirm after the login moved = refusal %v, err %v; want ErrStale", ch.Refusal, err)
	}
	if f.login() != "ada.other@example.invalid" || f.changes != 0 || f.changed() != 0 {
		t.Fatalf("login %q, Change calls %d, email_changed events %d; want the moved login, 0, 0", f.login(), f.changes, f.changed())
	}
	if f.rows() != 0 || f.pending() != nil {
		t.Fatal("the stale change is still pending")
	}
	if f.peek(raw).State != onetime.StateUsed {
		t.Fatal("the stale link was not spent")
	}
	if f.refusal(c2) != nil {
		t.Fatal("a stale confirm ended a session")
	}
}

func TestConfirmHeld(t *testing.T) {
	f := newFixture(t)
	cl := f.session()
	raw := f.link(cl)
	c2 := f.session()
	f.User(addr, "")
	ch, err := f.confirm(raw)
	if err != nil || ch.Refusal != emailchange.ErrAddressHeld {
		t.Fatalf("Confirm to a held address = refusal %v, err %v; want ErrAddressHeld", ch.Refusal, err)
	}
	f.assertUnchanged()
	if f.rows() != 0 || f.peek(raw).State != onetime.StateUsed {
		t.Fatal("the held change is still pending or its link is live")
	}
	if f.refusal(c2) != nil {
		t.Fatal("a held confirm ended a session")
	}
}

func TestConfirmSessions(t *testing.T) {
	t.Run("starter kept", func(t *testing.T) {
		f := newFixture(t)
		c1 := f.session()
		raw := f.link(c1)
		c2 := f.session()
		if ch, err := f.confirm(raw); err != nil || ch.Refusal != nil {
			t.Fatalf("Confirm = refusal %v, err %v; want a change", ch.Refusal, err)
		}
		if f.refusal(c1) != nil {
			t.Fatal("the starter's session ended")
		}
		if f.refusal(c2) != authkit.ErrSessionEnded || f.reason(c2) != "email_changed" || f.reason(c1) != "" {
			t.Fatalf("other session = refusal %v, reason %q; want ErrSessionEnded, email_changed, and the starter's reason empty", f.refusal(c2), f.reason(c2))
		}
	})
	t.Run("RevokeAll", func(t *testing.T) {
		f := newFixture(t, func(r *emailchange.Rules) { r.RevokeAll = true })
		c1 := f.session()
		raw := f.link(c1)
		c2 := f.session()
		if ch, err := f.confirm(raw); err != nil || ch.Refusal != nil {
			t.Fatalf("Confirm = refusal %v, err %v; want a change", ch.Refusal, err)
		}
		for _, cl := range []*authkit.Claims{c1, c2} {
			if f.refusal(cl) != authkit.ErrSessionEnded || f.reason(cl) != "email_changed" {
				t.Fatalf("session after RevokeAll = refusal %v, reason %q; want ErrSessionEnded, email_changed", f.refusal(cl), f.reason(cl))
			}
		}
	})
	t.Run("StartFor", func(t *testing.T) {
		f := newFixture(t)
		c1 := f.session()
		c2 := f.session()
		raw := f.linkFor()
		if ch, err := f.confirm(raw); err != nil || ch.Refusal != nil {
			t.Fatalf("Confirm = refusal %v, err %v; want a change", ch.Refusal, err)
		}
		for _, cl := range []*authkit.Claims{c1, c2} {
			if f.refusal(cl) != authkit.ErrSessionEnded || f.reason(cl) != "email_changed" {
				t.Fatalf("session after StartFor's confirm = refusal %v, reason %q; want ErrSessionEnded, email_changed", f.refusal(cl), f.reason(cl))
			}
		}
	})
}

func TestConfirmThrottleMoves(t *testing.T) {
	f := newFixture(t)
	cl := f.session()
	raw := f.link(cl)
	for i := 0; i < 2; i++ {
		if res := f.Login("staff", ada, "a wrong password"); res.Refusal == nil {
			t.Fatal("a wrong password was accepted")
		}
	}
	n := f.Count("SELECT failures FROM auth_throttle WHERE login = $1 AND audience = 'staff'", ada)
	if n <= 0 {
		t.Fatalf("failures under %q = %d; want the failed logins counted", ada, n)
	}
	if ch, err := f.confirm(raw); err != nil || ch.Refusal != nil {
		t.Fatalf("Confirm = refusal %v, err %v; want a change", ch.Refusal, err)
	}
	if got := f.Count("SELECT failures FROM auth_throttle WHERE login = $1 AND audience = 'staff'", addr); got != n {
		t.Fatalf("failures under %q = %d; want %d moved", addr, got, n)
	}
	if got := f.Count("SELECT count(*) FROM auth_throttle WHERE login = $1", ada); got != 0 {
		t.Fatalf("%d throttle rows still under %q; want none", got, ada)
	}
}

func TestConfirmChallengesGone(t *testing.T) {
	f := newFixture(t)
	cl := f.session()
	raw := f.link(cl)
	bob := f.User("bob@example.invalid", "")
	t0 := f.Clock.Now()
	for _, c := range []struct {
		id  uuid.UUID
		key string
	}{{f.ID, ada}, {bob, "bob@example.invalid"}} {
		f.D.Exec(f.T, "INSERT INTO auth_second_step_challenges (id, challenge_hash, principal_id, audience, origin, throttle_key, created_at, expires_at) VALUES ($1, $2, $3, 'staff', 'login', $4, $5, $6)",
			uuid.New(), []byte(c.id.String()), c.id, c.key, t0, t0.Add(5*time.Minute))
	}
	if ch, err := f.confirm(raw); err != nil || ch.Refusal != nil {
		t.Fatalf("Confirm = refusal %v, err %v; want a change", ch.Refusal, err)
	}
	if n := f.Count("SELECT count(*) FROM auth_second_step_challenges WHERE principal_id = $1", f.ID); n != 0 {
		t.Fatalf("the principal keeps %d challenges; want 0", n)
	}
	if n := f.Count("SELECT count(*) FROM auth_second_step_challenges WHERE principal_id = $1", bob); n != 1 {
		t.Fatalf("another principal has %d challenges; want 1", n)
	}
}

func TestConfirmChangeError(t *testing.T) {
	boom := errors.New("change failed")
	f := newFixture(t, func(r *emailchange.Rules) {
		r.Change = func(context.Context, db.Querier, authkit.Principal, string) error { return boom }
	})
	cl := f.session()
	raw := f.link(cl)
	c2 := f.session()
	_, err := f.confirm(raw)
	if !errors.Is(err, boom) {
		t.Fatalf("Confirm with a failing Change = %v; want the Change error", err)
	}
	if f.rows() != 1 || f.peek(raw).State != onetime.StateLive || f.login() != ada || f.changed() != 0 {
		t.Fatal("the failed change was not rolled back")
	}
	if f.refusal(c2) != nil {
		t.Fatal("a failed change ended a session")
	}
}

func TestConfirmWaitsForTheRow(t *testing.T) {
	f := newFixture(t)
	cl := f.session()
	raw := f.link(cl)
	tx, err := f.D.Owner.BeginTx(f.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(f.Ctx, f.D.SQL("SELECT 1 FROM auth_email_changes WHERE principal_id = $1 FOR UPDATE"), f.ID); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		ch  emailchange.Changed
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		var ch emailchange.Changed
		err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
			var err error
			ch, err = f.EC.Confirm(f.Ctx, q, raw, cmeta)
			return err
		})
		done <- outcome{ch, err}
	}()
	f.D.WaitForLockWaiters(f.T, 1)
	if _, err := tx.ExecContext(f.Ctx, f.D.SQL("DELETE FROM auth_email_changes WHERE principal_id = $1"), f.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got := <-done
	f.noRaw(raw, got.ch, got.err)
	if got.err != nil || got.ch.Refusal != authkit.ErrTokenUnknown {
		t.Fatalf("Confirm after the row was deleted = refusal %v, err %v; want ErrTokenUnknown", got.ch.Refusal, got.err)
	}
	f.assertUnchanged()
	if f.peek(raw).State != onetime.StateLive {
		t.Fatal("the link was spent before the row was locked")
	}
}
