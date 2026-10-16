package tests

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/internal/token"
)

func prvWorld(t *testing.T, aud authkit.Audience) (w *world, id uuid.UUID, a *authkittest.Authenticator, c *authkit.Claims) {
	t.Helper()
	w = newWorld(t, kittest.Passkeys)
	id = w.User("ada@example.invalid", "pw")
	origin := kittest.StaffOrigin
	if aud == "client" {
		origin = kittest.ClientOrigin
	}
	a = authkittest.NewAuthenticator("localhost", origin)
	w.SeedPasskey(id, a)
	c = w.Claims(w.Login(aud, "ada@example.invalid", "pw"))
	w.Clock.Advance(10 * time.Minute)
	return w, id, a, c
}

func prvBegin(w *world, c *authkit.Claims) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Passkeys.BeginReverify(w.Ctx, q, c)
	})
}

func prvFinish(w *world, c *authkit.Claims, ceremonyID string, resp []byte) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Passkeys.FinishReverify(w.Ctx, q, c, ceremonyID, resp, passkeyMeta)
	})
}

func prvGet(w *world, a *authkittest.Authenticator, res authkit.Result) []byte {
	w.T.Helper()
	if res.Ceremony == nil {
		w.T.Fatalf("begin refused: %v", res.Refusal)
	}
	resp, err := a.Get(res.Ceremony.Options)
	if err != nil {
		w.T.Fatalf("authenticator: %v", err)
	}
	return resp
}

func prvEvents(w *world, id uuid.UUID, result string) int {
	w.T.Helper()
	return w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = $2 AND source = 'reverify'`, id, result)
}

func prvOpen(w *world, ceremonyID string) int {
	w.T.Helper()
	return w.Count(`SELECT count(*) FROM auth_passkey_ceremonies WHERE ceremony_hash = $1 AND used_at IS NULL`, token.Hash(ceremonyID))
}

func prvStamped(w *world, sess uuid.UUID) int {
	w.T.Helper()
	return w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND authenticated_at = $2`, sess, w.Clock.Now())
}

func TestPasskeyReverify(t *testing.T) {
	w, id, a, c := prvWorld(t, "staff")
	recent := func() authkit.Result {
		return w.InAuth(func(q db.Querier) (authkit.Result, error) {
			return w.Svc.RequireRecent(w.Ctx, q, c, 0)
		})
	}
	if res := recent(); !errors.Is(res.Refusal, authkit.ErrReauthRequired) {
		t.Fatalf("RequireRecent before a re-verify = %v, want ErrReauthRequired", res.Refusal)
	}
	r := prvBegin(w, c)
	if r.Ceremony == nil {
		t.Fatalf("begin refused: %v", r.Refusal)
	}
	if n := w.Count(`SELECT count(*) FROM auth_passkey_ceremonies WHERE kind = 'reverify' AND principal_id = $1 AND session_id = $2 AND audience = 'staff'`, id, c.SessionID); n != 1 {
		t.Fatalf("reverify ceremony rows = %d, want 1", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_events WHERE source = 'reverify'`); n != 0 {
		t.Fatalf("reverify events after begin = %d, want 0", n)
	}
	res := prvFinish(w, c, r.Ceremony.ID, prvGet(w, a, r))
	if res.Refusal != nil {
		t.Fatalf("re-verify refused: %v", res.Refusal)
	}
	if res.Principal.ID != id {
		t.Fatalf("re-verify principal = %v, want %v", res.Principal.ID, id)
	}
	if res.Session != nil || res.Tokens != nil {
		t.Fatal("re-verify returned a session or tokens")
	}
	if n := prvStamped(w, c.SessionID); n != 1 {
		t.Fatalf("session stamped rows = %d, want 1", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, id); n != 1 {
		t.Fatalf("sessions after re-verify = %d, want 1", n)
	}
	if res := w.authenticate(w.Pinned(id), c); res.Refusal != nil {
		t.Fatalf("the same session after re-verify: %v", res.Refusal)
	}
	if n := w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'reverified' AND source = 'reverify' AND session_id = $2 AND audience = 'staff' AND second_factor = 'passkey'`, id, c.SessionID); n != 1 {
		t.Fatalf("reverified events = %d, want 1", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_passkeys WHERE principal_id = $1 AND last_used_at = $2`, id, w.Clock.Now()); n != 1 {
		t.Fatalf("passkey last_used_at rows = %d, want 1", n)
	}
	if res := recent(); res.Refusal != nil {
		t.Fatalf("RequireRecent after a re-verify = %v, want nil", res.Refusal)
	}
	if n := w.Count(`SELECT count(*) FROM auth_events e WHERE strpos(e::text, $1) > 0`, r.Ceremony.ID); n != 0 {
		t.Fatalf("events holding the ceremony ID = %d, want 0", n)
	}
}

func TestPasskeyReverifyOtherSession(t *testing.T) {
	w, _, a, c := prvWorld(t, "staff")
	cB := w.Claims(w.SignIn("ada@example.invalid", "pw"))
	w.Clock.Advance(time.Minute)
	r := prvBegin(w, c)
	resp := prvGet(w, a, r)
	res := prvFinish(w, cB, r.Ceremony.ID, resp)
	if !errors.Is(res.Refusal, authkit.ErrPasskeyRejected) {
		t.Fatalf("re-verify from another session = %v, want ErrPasskeyRejected", res.Refusal)
	}
	if n := prvOpen(w, r.Ceremony.ID); n != 1 {
		t.Fatalf("open ceremony after the other session's try = %d, want 1", n)
	}
	if n := prvStamped(w, cB.SessionID); n != 0 {
		t.Fatalf("the other session stamped = %d, want 0", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_events WHERE source = 'reverify'`); n != 0 {
		t.Fatalf("reverify events after the other session's try = %d, want 0", n)
	}
	res = prvFinish(w, c, r.Ceremony.ID, resp)
	if res.Refusal != nil {
		t.Fatalf("re-verify from the begin session: %v", res.Refusal)
	}
	if n := prvStamped(w, c.SessionID); n != 1 {
		t.Fatalf("begin session stamped = %d, want 1", n)
	}
	if n := prvStamped(w, cB.SessionID); n != 0 {
		t.Fatalf("the other session stamped after the begin session's re-verify = %d, want 0", n)
	}
}

func TestPasskeyReverifyOtherPrincipalsKey(t *testing.T) {
	w, id, _, c := prvWorld(t, "staff")
	bob := w.User("bob@example.invalid", "pw")
	b := authkittest.NewAuthenticator("localhost", kittest.StaffOrigin)
	w.SeedPasskey(bob, b)
	r := prvBegin(w, c)
	res := prvFinish(w, c, r.Ceremony.ID, prvGet(w, b, r))
	if !errors.Is(res.Refusal, authkit.ErrPasskeyRejected) {
		t.Fatalf("re-verify with another principal's key = %v, want ErrPasskeyRejected", res.Refusal)
	}
	if n := prvStamped(w, c.SessionID); n != 0 {
		t.Fatalf("session stamped = %d, want 0", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'bad_passkey' AND source = 'reverify' AND session_id = $2`, id, c.SessionID); n != 1 {
		t.Fatalf("bad_passkey events for the session's principal = %d, want 1", n)
	}
	if n := prvEvents(w, bob, "bad_passkey"); n != 0 {
		t.Fatalf("bad_passkey events for the other principal = %d, want 0", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_passkeys WHERE principal_id = $1 AND last_used_at IS NULL`, bob); n != 1 {
		t.Fatalf("the other principal's passkey rows never used = %d, want 1", n)
	}
	if n := prvEvents(w, id, "reverified"); n != 0 {
		t.Fatalf("reverified events = %d, want 0", n)
	}
}

func TestPasskeyReverifyNotALogin(t *testing.T) {
	t.Run("reverify-in-login", func(t *testing.T) {
		w, id, a, c := prvWorld(t, "staff")
		r := prvBegin(w, c)
		resp := prvGet(w, a, r)
		login := w.finish("staff", r.Ceremony.ID, resp)
		if !errors.Is(login.Refusal, authkit.ErrPasskeyRejected) || login.Session != nil {
			t.Fatalf("sign-in with a re-verify ceremony = %v (session %v), want ErrPasskeyRejected", login.Refusal, login.Session != nil)
		}
		if n := w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, id); n != 1 {
			t.Fatalf("sessions after the refused sign-in = %d, want 1", n)
		}
		if n := prvOpen(w, r.Ceremony.ID); n != 1 {
			t.Fatalf("open ceremony after the refused sign-in = %d, want 1", n)
		}
		if got := w.loginEvents(id); len(got) != 0 {
			t.Fatalf("login events after the refused sign-in = %v, want none", got)
		}
		res := prvFinish(w, c, r.Ceremony.ID, resp)
		if res.Refusal != nil {
			t.Fatalf("re-verify after the refused sign-in: %v", res.Refusal)
		}
		if n := prvStamped(w, c.SessionID); n != 1 {
			t.Fatalf("session stamped = %d, want 1", n)
		}
	})
	t.Run("login-in-reverify", func(t *testing.T) {
		w, _, a, c := prvWorld(t, "staff")
		r := w.begin("staff")
		res := prvFinish(w, c, r.Ceremony.ID, prvGet(w, a, r))
		if !errors.Is(res.Refusal, authkit.ErrPasskeyRejected) {
			t.Fatalf("re-verify with a sign-in ceremony = %v, want ErrPasskeyRejected", res.Refusal)
		}
		if n := prvStamped(w, c.SessionID); n != 0 {
			t.Fatalf("session stamped = %d, want 0", n)
		}
		if n := w.Count(`SELECT count(*) FROM auth_passkey_ceremonies WHERE kind = 'login' AND used_at IS NULL`); n != 1 {
			t.Fatalf("open sign-in ceremonies = %d, want 1", n)
		}
		if n := w.Count(`SELECT count(*) FROM auth_events WHERE source = 'reverify'`); n != 0 {
			t.Fatalf("reverify events = %d, want 0", n)
		}
	})
}

func TestPasskeyReverifyOnce(t *testing.T) {
	w, id, a, c := prvWorld(t, "staff")
	r := prvBegin(w, c)
	if res := prvFinish(w, c, r.Ceremony.ID, prvGet(w, a, r)); res.Refusal != nil {
		t.Fatalf("first re-verify: %v", res.Refusal)
	}
	res := prvFinish(w, c, r.Ceremony.ID, prvGet(w, a, r))
	if !errors.Is(res.Refusal, authkit.ErrPasskeyRejected) {
		t.Fatalf("second re-verify on the same ceremony = %v, want ErrPasskeyRejected", res.Refusal)
	}
	if n := prvEvents(w, id, "reverified"); n != 1 {
		t.Fatalf("reverified events = %d, want 1", n)
	}
	if n := prvEvents(w, id, "bad_passkey"); n != 0 {
		t.Fatalf("bad_passkey events = %d, want 0", n)
	}
}

func TestPasskeyReverifyEnded(t *testing.T) {
	t.Run("begin", func(t *testing.T) {
		w, id, _, c := prvWorld(t, "staff")
		w.logout(w.Pinned(id), c)
		res := prvBegin(w, c)
		if !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
			t.Fatalf("begin on an ended session = %v, want ErrSessionEnded", res.Refusal)
		}
		if res.Ceremony != nil {
			t.Fatal("begin on an ended session made a ceremony")
		}
		if n := w.Count(`SELECT count(*) FROM auth_passkey_ceremonies`); n != 0 {
			t.Fatalf("ceremony rows = %d, want 0", n)
		}
		if n := w.Count(`SELECT count(*) FROM auth_events WHERE source = 'reverify'`); n != 0 {
			t.Fatalf("reverify events = %d, want 0", n)
		}
	})
	t.Run("finish", func(t *testing.T) {
		w, id, a, c := prvWorld(t, "staff")
		r := prvBegin(w, c)
		resp := prvGet(w, a, r)
		w.logout(w.Pinned(id), c)
		res := prvFinish(w, c, r.Ceremony.ID, resp)
		if !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
			t.Fatalf("re-verify on an ended session = %v, want ErrSessionEnded", res.Refusal)
		}
		if n := prvOpen(w, r.Ceremony.ID); n != 1 {
			t.Fatalf("open ceremony = %d, want 1", n)
		}
		if n := w.Count(`SELECT count(*) FROM auth_passkeys WHERE principal_id = $1 AND last_used_at IS NULL`, id); n != 1 {
			t.Fatalf("passkeys never used = %d, want 1", n)
		}
		if n := w.Count(`SELECT count(*) FROM auth_events WHERE source = 'reverify'`); n != 0 {
			t.Fatalf("reverify events = %d, want 0", n)
		}
		if n := prvStamped(w, c.SessionID); n != 0 {
			t.Fatalf("ended session stamped = %d, want 0", n)
		}
	})
}

func TestPasskeyReverifyOtherAudience(t *testing.T) {
	w, id, a, c := prvWorld(t, "client")
	cl := *c
	cl.Audience = "staff"
	r := prvBegin(w, &cl)
	if n := w.Count(`SELECT count(*) FROM auth_passkey_ceremonies WHERE kind = 'reverify' AND principal_id = $1 AND audience = 'client'`, id); n != 1 {
		t.Fatalf("reverify ceremonies on the session's audience = %d, want 1", n)
	}
	res := prvFinish(w, &cl, r.Ceremony.ID, prvGet(w, a, r))
	if res.Refusal != nil {
		t.Fatalf("re-verify: %v", res.Refusal)
	}
	if n := prvStamped(w, c.SessionID); n != 1 {
		t.Fatalf("session stamped = %d, want 1", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'reverified' AND source = 'reverify' AND audience = 'client'`, id); n != 1 {
		t.Fatalf("reverified events on the session's audience = %d, want 1", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_events WHERE audience = 'staff' AND source = 'reverify'`); n != 0 {
		t.Fatalf("reverify events on the caller's audience = %d, want 0", n)
	}
}

func TestPasskeyReverifyLocksTheCredentialFirst(t *testing.T) {
	w, id, a, c := prvWorld(t, "staff")
	cB := w.Claims(w.SignIn("ada@example.invalid", "pw"))
	r := prvBegin(w, cB)
	resp := prvGet(w, a, r)
	del, err := w.D.Owner.BeginTx(w.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer del.Rollback()
	if _, err := del.ExecContext(w.Ctx, w.D.SQL(`SELECT 1 FROM auth_credentials WHERE principal_id = $1 FOR UPDATE`), id); err != nil {
		t.Fatal(err)
	}
	if _, err := del.ExecContext(w.Ctx, w.D.SQL(`SELECT 1 FROM auth_passkeys WHERE principal_id = $1 FOR UPDATE`), id); err != nil {
		t.Fatal(err)
	}
	var res authkit.Result
	done := make(chan error, 1)
	go func() {
		done <- w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
			var err error
			res, err = w.Svc.Passkeys.FinishReverify(w.Ctx, q, cB, r.Ceremony.ID, resp, passkeyMeta)
			return err
		})
	}()
	w.D.WaitForLockWaiters(t, 1)
	if _, err := del.ExecContext(w.Ctx, w.D.SQL(`UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'password_reset' WHERE principal_id = $1 AND id <> $3 AND revoked_at IS NULL`),
		id, w.Clock.Now(), c.SessionID); err != nil {
		t.Fatalf("the delete's revoke of the other sessions: %v", err)
	}
	if _, err := del.ExecContext(w.Ctx, w.D.SQL(`DELETE FROM auth_passkeys WHERE principal_id = $1`), id); err != nil {
		t.Fatalf("the delete of the passkeys: %v", err)
	}
	if err := del.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the re-verify behind the delete: %v", err)
	}
	if !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("re-verify behind the delete = %v, want ErrSessionEnded", res.Refusal)
	}
	if n := prvOpen(w, r.Ceremony.ID); n != 1 {
		t.Fatalf("open ceremony = %d, want 1", n)
	}
	if n := prvEvents(w, id, "reverified"); n != 0 {
		t.Fatalf("reverified events = %d, want 0", n)
	}
}

func TestPasskeyReverifyNoPasskey(t *testing.T) {
	w := newWorld(t, kittest.Passkeys)
	w.User("ada@example.invalid", "pw")
	c := w.Claims(w.SignIn("ada@example.invalid", "pw"))
	res := prvBegin(w, c)
	if !errors.Is(res.Refusal, authkit.ErrPasskeyRejected) {
		t.Fatalf("begin without a passkey = %v, want ErrPasskeyRejected", res.Refusal)
	}
	if res.Ceremony != nil {
		t.Fatal("begin without a passkey made a ceremony")
	}
	if n := w.Count(`SELECT count(*) FROM auth_passkey_ceremonies`); n != 0 {
		t.Fatalf("ceremony rows = %d, want 0", n)
	}
}
