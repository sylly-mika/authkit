package tests

import (
	"context"
	crand "crypto/rand"
	"database/sql"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/password"
)

func (w *world) changePassword(conn *sql.Conn, c *authkit.Claims, current, next string) authkit.Result {
	w.T.Helper()
	return w.InConn(conn, func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Password.ChangePassword(w.Ctx, q, c, current, next, authkit.Meta{IP: "192.0.2.3"})
	})
}

func TestChangePasswordRevokesTheOtherSessions(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the old password")
	keep := w.SignIn("ada@example.invalid", "the old password")
	other := w.SignIn("ada@example.invalid", "the old password")
	w.Clock.Advance(time.Minute)
	res := w.changePassword(w.Pinned(id), w.Claims(keep), "the old password", "the new password")
	if res.Refusal != nil {
		t.Fatalf("refused: %v", res.Refusal)
	}
	if !res.Session.AuthenticatedAt.Equal(w.Clock.Now()) {
		t.Fatalf("the result's session authenticated at %v, want the change's now %v", res.Session.AuthenticatedAt, w.Clock.Now())
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoke_reason = 'password_changed'`, other.Session.ID) != 1 {
		t.Fatal("the other session survived the change")
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL AND authenticated_at = $2`, keep.Session.ID, w.Clock.Now()) != 1 {
		t.Fatal("the current session was revoked or its authenticated_at not renewed")
	}
	if w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'password_reset' AND session_id = $2 AND scope_id = $3 AND login = 'ada@example.invalid'`,
		id, keep.Session.ID, w.P.Scope) != 1 {
		t.Fatal("no password_reset event for the current session (ino-tasks' result for a change)")
	}
	if res := w.Login("staff", "ada@example.invalid", "the old password"); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("the old password = %v", res.Refusal)
	}
	w.SignIn("ada@example.invalid", "the new password")
}

func TestChangePasswordRefusalsWriteNothing(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the old password")
	keep := w.SignIn("ada@example.invalid", "the old password")
	other := w.SignIn("ada@example.invalid", "the old password")
	conn, c := w.Pinned(id), w.Claims(keep)
	if res := w.changePassword(conn, c, "a wrong password", "the new password"); !errors.Is(res.Refusal, authkit.ErrCurrentPasswordWrong) {
		t.Errorf("a wrong current password = %v", res.Refusal)
	}
	var pe authkit.PolicyError
	if res := w.changePassword(conn, c, "the old password", "short"); !errors.As(res.Refusal, &pe) || pe.TooLong {
		t.Errorf("a short new password = %v, want PolicyError", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL`, other.Session.ID) != 1 || len(w.Results(id)) != 2 {
		t.Fatal("a refused change revoked a session or logged")
	}
	w.SignIn("ada@example.invalid", "the old password")
}

func TestChangePasswordWithoutACredentialIsAWrongCurrentPassword(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the old password")
	keep := w.SignIn("ada@example.invalid", "the old password")
	w.D.Exec(t, `DELETE FROM auth_credentials WHERE principal_id = $1`, id)
	if res := w.changePassword(w.Pinned(id), w.Claims(keep), "the old password", "the new password"); !errors.Is(res.Refusal, authkit.ErrCurrentPasswordWrong) {
		t.Fatalf("no credential = %v, want ErrCurrentPasswordWrong (ino-tasks 422)", res.Refusal)
	}
}

func (w *world) changeBehind(holder *sql.Tx, conn *sql.Conn, c *authkit.Claims) authkit.Result {
	w.T.Helper()
	type outcome struct {
		res authkit.Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		var res authkit.Result
		err := authkittest.InConnTx(w.Ctx, conn, func(q db.Querier) error {
			var err error
			res, err = w.Svc.Password.ChangePassword(w.Ctx, q, c, "the old password", "the changed password", authkit.Meta{})
			return err
		})
		done <- outcome{res, err}
	}()
	w.D.WaitForLockWaiters(w.T, 1)
	if err := holder.Commit(); err != nil {
		w.T.Fatal(err)
	}
	o := <-done
	if o.err != nil {
		w.T.Fatal(o.err)
	}
	return o.res
}

func TestChangePasswordLosesToAResetThatLands(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the old password")
	keep := w.SignIn("ada@example.invalid", "the old password")
	holder, err := w.D.Owner.BeginTx(w.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	replaced, err := password.Encode(kittest.Cheap, crand.Reader, "the reset password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.ExecContext(w.Ctx, `UPDATE auth_credentials SET password_hash = $2 WHERE principal_id = $1`, id, replaced); err != nil {
		t.Fatal(err)
	}
	if res := w.changeBehind(holder, w.Pinned(id), w.Claims(keep)); !errors.Is(res.Refusal, authkit.ErrCurrentPasswordWrong) {
		t.Fatalf("a change behind a reset = %v, want ErrCurrentPasswordWrong", res.Refusal)
	}
	w.SignIn("ada@example.invalid", "the reset password")
	if res := w.Login("staff", "ada@example.invalid", "the changed password"); res.Refusal == nil {
		t.Fatal("the refused change's password works")
	}
}

func TestChangePasswordLosesToARevokeThatLands(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the old password")
	keep := w.SignIn("ada@example.invalid", "the old password")
	holder, err := w.D.Owner.BeginTx(w.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(w.Ctx, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'user' WHERE id = $1`, keep.Session.ID, w.Clock.Now()); err != nil {
		t.Fatal(err)
	}
	if res := w.changeBehind(holder, w.Pinned(id), w.Claims(keep)); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a change behind a revoke = %v, want ErrSessionEnded", res.Refusal)
	}
	w.SignIn("ada@example.invalid", "the old password")
}

func TestSetPasswordAndVerifyPassword(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "")
	p := authkit.Principal{ID: id, Login: "ada@example.invalid"}
	if res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Password.SetPassword(w.Ctx, q, p, "staff", "a first password", authkit.Meta{})
	}); res.Refusal != nil {
		t.Fatalf("SetPassword = %v", res.Refusal)
	}
	w.Clock.Advance(time.Second)
	if res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Password.VerifyPassword(w.Ctx, q, p, "staff", "a first password", authkit.Meta{})
	}); res.Refusal != nil {
		t.Fatalf("VerifyPassword with the right password = %v", res.Refusal)
	}
	if res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Password.VerifyPassword(w.Ctx, q, p, "staff", "a wrong password", authkit.Meta{})
	}); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("VerifyPassword with a wrong password = %v", res.Refusal)
	}
	if got := w.Results(id); !slices.Equal(got, []string{"password_set", "bad_password"}) {
		t.Fatalf("log = %v, want password_set, then bad_password", got)
	}
}

// WHY: the change locks the credential row before the session row, so a reset revoking every session cannot deadlock with it.
func TestChangePasswordLocksTheCredentialBeforeTheSession(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the old password")
	keep := w.SignIn("ada@example.invalid", "the old password")
	reset, err := w.D.Owner.BeginTx(w.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reset.Rollback()
	replaced, err := password.Encode(kittest.Cheap, crand.Reader, "the reset password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reset.ExecContext(w.Ctx, `UPDATE auth_credentials SET password_hash = $2 WHERE principal_id = $1`, id, replaced); err != nil {
		t.Fatal(err)
	}
	conn, c := w.Pinned(id), w.Claims(keep)
	var res authkit.Result
	done := make(chan error, 1)
	go func() {
		done <- authkittest.InConnTx(w.Ctx, conn, func(q db.Querier) error {
			var err error
			res, err = w.Svc.Password.ChangePassword(w.Ctx, q, c, "the old password", "the changed password", authkit.Meta{})
			return err
		})
	}()
	w.D.WaitForLockWaiters(t, 1)
	if _, err := reset.ExecContext(w.Ctx, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'password_reset' WHERE principal_id = $1 AND revoked_at IS NULL`,
		id, w.Clock.Now()); err != nil {
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

func TestAnAppHeldSlotServesTheHashingMethods(t *testing.T) {
	for name, tweak := range map[string]func(*kittest.Rules){"count-before": kittest.DefaultRules, "CountAfterVerify": func(*kittest.Rules) {}} {
		w := newWorld(t, tweak, func(c *kittest.Rules) { c.Password.HashConcurrency, c.Password.HashWait = 1, 50*time.Millisecond })
		ada := authkit.Principal{ID: w.User("ada@example.invalid", "the right password"), Login: "ada@example.invalid"}
		invited := authkit.Principal{ID: w.User("invited@example.invalid", ""), Login: "invited@example.invalid"}
		held, release, res, err := w.Svc.Password.AcquireHashSlot(w.Ctx)
		if err != nil || res.Refusal != nil {
			t.Fatalf("%s: AcquireHashSlot = %v, %v", name, res.Refusal, err)
		}
		for call, fn := range map[string]func(ctx context.Context, q db.Querier) (authkit.Result, error){
			"Login": func(ctx context.Context, q db.Querier) (authkit.Result, error) {
				return w.Svc.Password.Login(ctx, q, "staff", "ada@example.invalid", "the right password", authkit.Meta{})
			},
			"SetPassword": func(ctx context.Context, q db.Querier) (authkit.Result, error) {
				return w.Svc.Password.SetPassword(ctx, q, invited, "staff", "a first password", authkit.Meta{})
			},
			"VerifyPassword": func(ctx context.Context, q db.Querier) (authkit.Result, error) {
				return w.Svc.Password.VerifyPassword(ctx, q, ada, "staff", "the right password", authkit.Meta{})
			},
		} {
			if res := w.InAuth(func(q db.Querier) (authkit.Result, error) { return fn(held, q) }); res.Refusal != nil {
				t.Errorf("%s: %s under the held slot = %v", name, call, res.Refusal)
			}
			if res := w.InAuth(func(q db.Querier) (authkit.Result, error) { return fn(w.Ctx, q) }); !errors.Is(res.Refusal, authkit.ErrBusy) {
				t.Errorf("%s: %s outside it = %v, want ErrBusy", name, call, res.Refusal)
			}
		}
		release()
	}
}

func TestAcquireHashSlotRefusesBusyAndReturnsTheContextsError(t *testing.T) {
	w := newWorld(t, kittest.DefaultRules, func(c *kittest.Rules) { c.Password.HashConcurrency, c.Password.HashWait = 1, 50*time.Millisecond })
	_, release, _, err := w.Svc.Password.AcquireHashSlot(w.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctx, noop, res, err := w.Svc.Password.AcquireHashSlot(w.Ctx)
	if err != nil || !errors.Is(res.Refusal, authkit.ErrBusy) || ctx != w.Ctx || noop == nil {
		t.Fatalf("a second slot of one = %v, %v; want the Busy refusal, the caller's context and a release", res.Refusal, err)
	}
	noop()
	cancelled, cancel := context.WithCancel(w.Ctx)
	cancel()
	if _, _, res, err := w.Svc.Password.AcquireHashSlot(cancelled); !errors.Is(err, context.Canceled) || res.Refusal != nil {
		t.Fatalf("a cancelled wait = %v, %v; want context.Canceled as the error", res.Refusal, err)
	}
	release()
	if _, again, res, err := w.Svc.Password.AcquireHashSlot(w.Ctx); err != nil || res.Refusal != nil {
		t.Fatalf("after the release = %v, %v", res.Refusal, err)
	} else {
		again()
	}
}

// WHY: the clock moves after the change reads its now and before its writes, so a write that reads the clock itself stamps a later time.
type slowByID struct {
	*authkittest.Principals
	clock *authkittest.Clock
}

func (s slowByID) ByID(ctx context.Context, q db.Querier, id uuid.UUID, aud authkit.Audience) (authkit.Principal, error) {
	s.clock.Advance(time.Second)
	return s.Principals.ByID(ctx, q, id, aud)
}

func TestChangePasswordStampsOneTime(t *testing.T) {
	for _, mode := range []struct {
		name string
		rev  authkit.RevokeOnChange
	}{{"revoke others", authkit.RevokeOthers}, {"revoke all", authkit.RevokeAll}} {
		t.Run(mode.name, func(t *testing.T) {
			w := newWorld(t, func(r *kittest.Rules) { r.Password.RevokeOnPasswordChange = mode.rev })
			w.Svc = w.BuildWith(w.Cfg, slowByID{w.P, w.Clock})
			id := w.User("ada@example.invalid", "the old password")
			keep := w.SignIn("ada@example.invalid", "the old password")
			other := w.SignIn("ada@example.invalid", "the old password")
			res := w.changePassword(w.Pinned(id), w.Claims(keep), "the old password", "the new password")
			if res.Refusal != nil {
				t.Fatalf("refused: %v", res.Refusal)
			}
			var changedAt time.Time
			if err := w.D.Row(t, `SELECT changed_at FROM auth_credentials WHERE principal_id = $1`, id).Scan(&changedAt); err != nil {
				t.Fatal(err)
			}
			if !res.Session.AuthenticatedAt.Equal(changedAt) {
				t.Fatalf("the result's session authenticated at %v, the credential changed at %v", res.Session.AuthenticatedAt, changedAt)
			}
			if mode.rev == authkit.RevokeOthers {
				if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND authenticated_at = $2`, keep.Session.ID, changedAt) != 1 {
					t.Fatal("the current session's authenticated_at is not the credential's changed_at")
				}
				if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at = $2`, other.Session.ID, changedAt) != 1 {
					t.Fatal("the other session's revoked_at is not the credential's changed_at")
				}
				return
			}
			if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at = $2`, keep.Session.ID, changedAt) != 1 {
				t.Fatal("the old session's revoked_at is not the credential's changed_at")
			}
			if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at = $2`, other.Session.ID, changedAt) != 1 {
				t.Fatal("the other session's revoked_at is not the credential's changed_at")
			}
		})
	}
}
