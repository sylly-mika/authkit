package authkit_test

import (
	crand "crypto/rand"
	"database/sql"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/password"
)

func (w *world) changePassword(conn *sql.Conn, c *authkit.Claims, current, next string) authkit.Result {
	w.t.Helper()
	return w.inConn(conn, func(q db.Querier) (authkit.Result, error) {
		return w.svc.ChangePassword(w.ctx, q, c, current, next, authkit.Meta{IP: "192.0.2.3"})
	})
}

// TestChangePasswordRevokesTheOtherSessions is spec §8.10.
func TestChangePasswordRevokesTheOtherSessions(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the old password")
	keep := w.signIn("ada@example.invalid", "the old password")
	other := w.signIn("ada@example.invalid", "the old password")
	w.clock.Advance(time.Minute)
	res := w.changePassword(w.pinned(id), w.claims(keep), "the old password", "the new password")
	if res.Refusal != nil {
		t.Fatalf("refused: %v", res.Refusal)
	}
	if !res.Session.AuthenticatedAt.Equal(w.clock.Now()) {
		t.Fatalf("the result's session authenticated at %v, want the change's now %v", res.Session.AuthenticatedAt, w.clock.Now())
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoke_reason = 'password_changed'`, other.Session.ID) != 1 {
		t.Fatal("the other session survived the change")
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL AND authenticated_at = $2`, keep.Session.ID, w.clock.Now()) != 1 {
		t.Fatal("the current session was revoked or its authenticated_at not renewed")
	}
	if w.count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'password_reset' AND session_id = $2 AND scope_id = $3 AND login = 'ada@example.invalid'`,
		id, keep.Session.ID, w.p.Scope) != 1 {
		t.Fatal("no password_reset event for the current session (ino-tasks' result for a change)")
	}
	if res := w.login("staff", "ada@example.invalid", "the old password"); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("the old password = %v", res.Refusal)
	}
	w.signIn("ada@example.invalid", "the new password")
}

func TestChangePasswordRefusalsWriteNothing(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the old password")
	keep := w.signIn("ada@example.invalid", "the old password")
	other := w.signIn("ada@example.invalid", "the old password")
	conn, c := w.pinned(id), w.claims(keep)
	if res := w.changePassword(conn, c, "a wrong password", "the new password"); !errors.Is(res.Refusal, authkit.ErrCurrentPasswordWrong) {
		t.Errorf("a wrong current password = %v", res.Refusal)
	}
	var pe authkit.PolicyError
	if res := w.changePassword(conn, c, "the old password", "short"); !errors.As(res.Refusal, &pe) || pe.TooLong {
		t.Errorf("a short new password = %v, want PolicyError", res.Refusal)
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL`, other.Session.ID) != 1 || len(w.results(id)) != 2 {
		t.Fatal("a refused change revoked a session or logged")
	}
	w.signIn("ada@example.invalid", "the old password")
}

func TestChangePasswordWithoutACredentialIsAWrongCurrentPassword(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the old password")
	keep := w.signIn("ada@example.invalid", "the old password")
	w.d.Exec(t, `DELETE FROM auth_credentials WHERE principal_id = $1`, id)
	if res := w.changePassword(w.pinned(id), w.claims(keep), "the old password", "the new password"); !errors.Is(res.Refusal, authkit.ErrCurrentPasswordWrong) {
		t.Fatalf("no credential = %v, want ErrCurrentPasswordWrong (ino-tasks 422)", res.Refusal)
	}
}

func (w *world) changeBehind(holder *sql.Tx, conn *sql.Conn, c *authkit.Claims) authkit.Result {
	w.t.Helper()
	type outcome struct {
		res authkit.Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		var res authkit.Result
		err := authkittest.InConnTx(w.ctx, conn, func(q db.Querier) error {
			var err error
			res, err = w.svc.ChangePassword(w.ctx, q, c, "the old password", "the changed password", authkit.Meta{})
			return err
		})
		done <- outcome{res, err}
	}()
	w.d.WaitForLockWaiters(w.t, 1)
	if err := holder.Commit(); err != nil {
		w.t.Fatal(err)
	}
	o := <-done
	if o.err != nil {
		w.t.Fatal(o.err)
	}
	return o.res
}

// TestChangePasswordLosesToAResetThatLands: the change verified the old hash,
// then waits on the credential row a reset holds, then finds it replaced.
func TestChangePasswordLosesToAResetThatLands(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the old password")
	keep := w.signIn("ada@example.invalid", "the old password")
	holder, err := w.d.Owner.BeginTx(w.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	replaced, err := password.Encode(cheap, crand.Reader, "the reset password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.ExecContext(w.ctx, `UPDATE auth_credentials SET password_hash = $2 WHERE principal_id = $1`, id, replaced); err != nil {
		t.Fatal(err)
	}
	if res := w.changeBehind(holder, w.pinned(id), w.claims(keep)); !errors.Is(res.Refusal, authkit.ErrCurrentPasswordWrong) {
		t.Fatalf("a change behind a reset = %v, want ErrCurrentPasswordWrong", res.Refusal)
	}
	w.signIn("ada@example.invalid", "the reset password")
	if res := w.login("staff", "ada@example.invalid", "the changed password"); res.Refusal == nil {
		t.Fatal("the refused change's password works")
	}
}

func TestChangePasswordLosesToARevokeThatLands(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the old password")
	keep := w.signIn("ada@example.invalid", "the old password")
	holder, err := w.d.Owner.BeginTx(w.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(w.ctx, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'user' WHERE id = $1`, keep.Session.ID, w.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if res := w.changeBehind(holder, w.pinned(id), w.claims(keep)); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a change behind a revoke = %v, want ErrSessionEnded", res.Refusal)
	}
	w.signIn("ada@example.invalid", "the old password")
}

func TestSetPasswordAndVerifyPassword(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "")
	p := authkit.Principal{ID: id, Login: "ada@example.invalid"}
	if res := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.SetPassword(w.ctx, q, p, "staff", "a first password", authkit.Meta{})
	}); res.Refusal != nil {
		t.Fatalf("SetPassword = %v", res.Refusal)
	}
	w.clock.Advance(time.Second)
	if res := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.VerifyPassword(w.ctx, q, p, "staff", "a first password", authkit.Meta{})
	}); res.Refusal != nil {
		t.Fatalf("VerifyPassword with the right password = %v", res.Refusal)
	}
	if res := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.VerifyPassword(w.ctx, q, p, "staff", "a wrong password", authkit.Meta{})
	}); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("VerifyPassword with a wrong password = %v", res.Refusal)
	}
	if got := w.results(id); !slices.Equal(got, []string{"password_set", "bad_password"}) {
		t.Fatalf("log = %v, want password_set, then bad_password", got)
	}
}

// TestChangePasswordHashesBeforeItLocks: both argon2id steps finish before the
// change waits on the credential row, so a hash ceiling that fills while it
// waits cannot refuse it.
func TestChangePasswordHashesBeforeItLocks(t *testing.T) {
	w := newWorld(t, func(c *authkit.Config) { c.HashConcurrency = 1 })
	id := w.user("ada@example.invalid", "the old password")
	keep := w.signIn("ada@example.invalid", "the old password")
	holder, err := w.d.Owner.BeginTx(w.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(w.ctx, `SELECT 1 FROM auth_credentials WHERE principal_id = $1 FOR UPDATE`, id); err != nil {
		t.Fatal(err)
	}
	conn, c := w.pinned(id), w.claims(keep)
	var res authkit.Result
	done := make(chan error, 1)
	go func() {
		done <- authkittest.InConnTx(w.ctx, conn, func(q db.Querier) error {
			var err error
			res, err = w.svc.ChangePassword(w.ctx, q, c, "the old password", "the changed password", authkit.Meta{})
			return err
		})
	}()
	w.d.WaitForLockWaiters(t, 1)
	release, err := authkit.HoldHashSlot(w.ctx, w.svc)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if res.Refusal != nil {
		t.Fatalf("a change that waited on the credential row = %v; it hashed under the lock", res.Refusal)
	}
}

// TestChangePasswordLocksTheCredentialBeforeTheSession is Spec correction 6:
// a change that waits on the credential row a reset holds holds no session
// row, so the reset's revoke of every session goes through instead of
// deadlocking with it.
func TestChangePasswordLocksTheCredentialBeforeTheSession(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the old password")
	keep := w.signIn("ada@example.invalid", "the old password")
	reset, err := w.d.Owner.BeginTx(w.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reset.Rollback()
	replaced, err := password.Encode(cheap, crand.Reader, "the reset password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reset.ExecContext(w.ctx, `UPDATE auth_credentials SET password_hash = $2 WHERE principal_id = $1`, id, replaced); err != nil {
		t.Fatal(err)
	}
	conn, c := w.pinned(id), w.claims(keep)
	var res authkit.Result
	done := make(chan error, 1)
	go func() {
		done <- authkittest.InConnTx(w.ctx, conn, func(q db.Querier) error {
			var err error
			res, err = w.svc.ChangePassword(w.ctx, q, c, "the old password", "the changed password", authkit.Meta{})
			return err
		})
	}()
	w.d.WaitForLockWaiters(t, 1)
	if _, err := reset.ExecContext(w.ctx, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'password_reset' WHERE principal_id = $1 AND revoked_at IS NULL`,
		id, w.clock.Now()); err != nil {
		t.Fatalf("the reset's revoke of every session: %v", err)
	}
	if err := reset.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the change behind the reset: %v", err)
	}
	if !errors.Is(res.Refusal, authkit.ErrCurrentPasswordWrong) {
		t.Fatalf("a change behind a reset = %v, want ErrCurrentPasswordWrong", res.Refusal)
	}
}
