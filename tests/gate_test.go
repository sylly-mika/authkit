package tests

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
)

const gateLogin = "ada@example.invalid"

const gateNewPassword = "a brand new password"

func (w *world) gateFailures() int {
	w.T.Helper()
	return w.Count(`SELECT COALESCE(sum(failures), 0) FROM auth_throttle`)
}

func (w *world) gatePasskeys(id uuid.UUID) int {
	w.T.Helper()
	return w.Count(`SELECT count(*) FROM auth_passkeys WHERE principal_id = $1`, id)
}

func (w *world) badLogin() {
	w.T.Helper()
	res := w.Login("staff", gateLogin, "a wrong password")
	if !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) || w.gateFailures() != 1 {
		w.T.Fatalf("bad login: refusal %v, failures %d", res.Refusal, w.gateFailures())
	}
}

func wantSources(t *testing.T, got []string, src string) {
	t.Helper()
	if len(got) == 0 {
		t.Errorf("Admit was not called, want source %q", src)
		return
	}
	for _, g := range got {
		if g != src {
			t.Errorf("Admit sources = %v, want only %q", got, src)
			return
		}
	}
}

func gateNoSession(t *testing.T, res authkit.Result) {
	t.Helper()
	if res.Session != nil || res.Tokens != nil || res.SessionToken != "" {
		t.Errorf("a session was opened: Session set %v, Tokens set %v, SessionToken set %v", res.Session != nil, res.Tokens != nil, res.SessionToken != "")
	}
}

func gateResetWithFactor(t *testing.T, w *world, rec *sourceLog, id uuid.UUID) {
	t.Helper()
	h := w.StoredHash(id)
	w.seedTOTP(id)
	link := w.mintLink(*w.requestReset(gateLogin).TokenID)
	rec.take()
	res := w.completeReset(link, gateNewPassword)
	if res.Refusal != nil || res.SecondStep == nil {
		t.Fatalf("reset: refusal %v, second step %v", res.Refusal, res.SecondStep != nil)
	}
	gateNoSession(t, res)
	if n := w.sessions(id); n != 0 {
		t.Errorf("sessions = %d, want 0", n)
	}
	if n := w.challenges(id); n != 1 {
		t.Errorf("challenges = %d, want 1", n)
	}
	if w.StoredHash(id) == h {
		t.Error("the credential is unchanged, want the new password set before the second step")
	}
	wantSources(t, rec.take(), "complete_reset")
}

func TestGateEveryPath(t *testing.T) {
	t.Run("login", func(t *testing.T) {
		w := newWorld(t, factors)
		rec := withSourceLog(w)
		ada := w.User(gateLogin, pw)
		w.seedTOTP(ada)
		rec.take()
		res := w.Login("staff", gateLogin, pw)
		if res.Refusal != nil || res.SecondStep == nil {
			t.Fatalf("login: refusal %v, second step %v", res.Refusal, res.SecondStep != nil)
		}
		gateNoSession(t, res)
		if n := w.sessions(ada); n != 0 {
			t.Errorf("sessions = %d, want 0", n)
		}
		if n := w.challenges(ada); n != 1 {
			t.Errorf("challenges = %d, want 1", n)
		}
		wantSources(t, rec.take(), "login")
	})

	t.Run("reset bearer", func(t *testing.T) {
		w := newWorld(t, factors)
		rec := withSourceLog(w)
		ada := w.User(gateLogin, pw)
		gateResetWithFactor(t, w, rec, ada)
	})

	t.Run("reset session", func(t *testing.T) {
		w := sessionWorld(t, factors)
		rec := withSourceLog(w)
		ada := w.User(gateLogin, pw)
		gateResetWithFactor(t, w, rec, ada)
	})

	t.Run("passkey", func(t *testing.T) {
		w := newWorld(t, factors, kittest.Passkeys)
		rec := withSourceLog(w)
		id := w.User(gateLogin, "")
		w.seedTOTP(id)
		a := authkittest.NewAuthenticator("localhost", kittest.StaffOrigin)
		w.SeedPasskey(id, a)
		a.SetCounter(4)
		rec.take()
		res := w.passkeySignIn("staff", a)
		if res.Refusal != nil || res.Session == nil || res.Tokens == nil || res.SecondStep != nil {
			t.Fatalf("passkey sign-in: refusal %v, session set %v, second step %v", res.Refusal, res.Session != nil, res.SecondStep != nil)
		}
		if n := w.openSessions(id); n != 1 {
			t.Errorf("open sessions = %d, want 1", n)
		}
		if n := w.challenges(id); n != 0 {
			t.Errorf("challenges = %d, want 0", n)
		}
		wantSources(t, rec.take(), "passkey_login")
	})

	t.Run("change password", func(t *testing.T) {
		revokeAll := func(c *kittest.Rules) { c.RevokeOnPasswordChange = authkit.RevokeAll }
		w := newWorld(t, factors, revokeAll)
		rec := withSourceLog(w)
		ada := w.User(gateLogin, pw)
		first := w.SignIn(gateLogin, pw)
		w.seedTOTP(ada)
		rec.take()
		res := w.changePassword(w.Pinned(ada), w.Claims(first), pw, gateNewPassword)
		if res.Refusal != nil || res.Session == nil || res.SecondStep != nil {
			t.Fatalf("change password: refusal %v, session set %v, second step %v", res.Refusal, res.Session != nil, res.SecondStep != nil)
		}
		if res.Session.ID == first.Session.ID {
			t.Error("the session was not reopened: the new session has the old id")
		}
		if n := w.openSessions(ada); n != 1 {
			t.Errorf("open sessions = %d, want 1", n)
		}
		if n := w.challenges(ada); n != 0 {
			t.Errorf("challenges = %d, want 0", n)
		}
		wantSources(t, rec.take(), "change_password")
	})

	t.Run("refresh", func(t *testing.T) {
		w := newWorld(t, factors)
		rec := withSourceLog(w)
		ada := w.User(gateLogin, pw)
		first := w.SignIn(gateLogin, pw)
		w.seedTOTP(ada)
		rec.take()
		res := w.refresh("staff", first.Tokens.RefreshToken)
		if res.Refusal != nil || res.Tokens == nil || res.SecondStep != nil {
			t.Fatalf("refresh: refusal %v, tokens set %v, second step %v", res.Refusal, res.Tokens != nil, res.SecondStep != nil)
		}
		if n := w.challenges(ada); n != 0 {
			t.Errorf("challenges = %d, want 0", n)
		}
		wantSources(t, rec.take(), "refresh")
	})

	t.Run("rotation", func(t *testing.T) {
		w := sessionWorld(t, factors)
		rec := withSourceLog(w)
		ada := w.User(gateLogin, pw)
		signed := w.SignIn(gateLogin, pw)
		w.seedTOTP(ada)
		w.Clock.Advance(15 * time.Minute)
		rec.take()
		res := w.authenticateSession("staff", signed.SessionToken)
		if res.Refusal != nil || res.SessionToken == "" || res.SessionToken == signed.SessionToken || res.SecondStep != nil {
			t.Fatalf("rotation: refusal %v, rotated token set %v, second step %v", res.Refusal, res.SessionToken != "", res.SecondStep != nil)
		}
		if n := w.challenges(ada); n != 0 {
			t.Errorf("challenges = %d, want 0", n)
		}
		wantSources(t, rec.take(), "authenticate_session")
	})

	t.Run("open session from", func(t *testing.T) {
		w := newWorld(t, factors)
		rec := withSourceLog(w)
		ada := w.User(gateLogin, pw)
		first := w.SignIn(gateLogin, pw)
		w.seedTOTP(ada)
		rec.take()
		res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
			return w.Svc.OpenSessionFrom(w.Ctx, q, first.Session.ID, authkit.Principal{ID: ada, Login: gateLogin}, "staff", authkit.Meta{})
		})
		if res.Refusal != nil || res.Session == nil || res.SecondStep != nil {
			t.Fatalf("open session from: refusal %v, session set %v, second step %v", res.Refusal, res.Session != nil, res.SecondStep != nil)
		}
		if res.Session.ID == first.Session.ID {
			t.Error("the session was not opened: the new session has the old id")
		}
		if n := w.challenges(ada); n != 0 {
			t.Errorf("challenges = %d, want 0", n)
		}
		wantSources(t, rec.take(), "open_session")
	})

	t.Run("open session", func(t *testing.T) {
		w := sessionWorld(t, factors)
		rec := withSourceLog(w)
		ada := w.User(gateLogin, pw)
		w.seedTOTP(ada)
		rec.take()
		res := w.openSession(authkit.Principal{ID: ada, Login: gateLogin})
		if res.Refusal != nil || res.SessionToken == "" || res.SecondStep != nil {
			t.Fatalf("open session: refusal %v, session token set %v, second step %v", res.Refusal, res.SessionToken != "", res.SecondStep != nil)
		}
		if n := w.openSessions(ada); n != 1 {
			t.Errorf("open sessions = %d, want 1", n)
		}
		if n := w.challenges(ada); n != 0 {
			t.Errorf("challenges = %d, want 0", n)
		}
		wantSources(t, rec.take(), "open_session")
	})
}

func TestGateFailsClosedWithoutVerifier(t *testing.T) {
	w := newWorld(t, factors)
	id, secret, _ := w.enrolTOTP(gateLogin)
	tok := w.challenge(gateLogin)
	link := w.mintLink(*w.requestReset(gateLogin).TokenID)
	h := w.StoredHash(id)
	n := w.sessions(id)
	e := w.Count("SELECT count(*) FROM auth_events WHERE principal_id = $1", id)
	w.offline(nil)
	results := []authkit.Result{
		w.Login("staff", gateLogin, pw),
		w.completeReset(link, gateNewPassword),
		w.verify("staff", tok, authkit.FactorTOTP, w.code(secret)),
		w.stepSend("staff", tok),
	}
	for i, res := range results {
		if !errors.Is(res.Refusal, authkit.ErrSecondFactorsOff) || res.SecondStep != nil || res.Session != nil || res.Tokens != nil || res.EmailCode != nil {
			t.Errorf("call %d: refusal %v, second step set %v, session set %v, tokens set %v, email code set %v",
				i, res.Refusal, res.SecondStep != nil, res.Session != nil, res.Tokens != nil, res.EmailCode != nil)
		}
	}
	if got := w.sessions(id); got != n {
		t.Errorf("sessions = %d, want %d", got, n)
	}
	if w.StoredHash(id) != h {
		t.Error("the credential changed without a verifier")
	}
	if got := w.challenges(id); got != 1 {
		t.Errorf("challenges = %d, want 1", got)
	}
	if got := w.Count(`SELECT count(*) FROM auth_second_step_challenges WHERE principal_id = $1 AND used_at IS NULL AND tries = 0`, id); got != 1 {
		t.Errorf("open untried challenges = %d, want 1", got)
	}
	if got := w.Count(`SELECT count(*) FROM auth_email_codes`); got != 0 {
		t.Errorf("email codes = %d, want 0", got)
	}
	if got := w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1`, id); got != e {
		t.Errorf("events = %d, want %d", got, e)
	}
}

func TestResetOrder(t *testing.T) {
	t.Run("no verifier", func(t *testing.T) {
		w := newWorld(t, factors)
		ada := w.User(gateLogin, pw)
		w.seedTOTP(ada)
		w.addStoredPasskey(ada, "key", false)
		w.badLogin()
		link := w.mintLink(*w.requestReset(gateLogin).TokenID)
		h := w.StoredHash(ada)
		w.offline(nil)
		res := w.completeReset(link, gateNewPassword)
		if !errors.Is(res.Refusal, authkit.ErrSecondFactorsOff) {
			t.Errorf("refusal = %v, want ErrSecondFactorsOff", res.Refusal)
		}
		if w.StoredHash(ada) != h {
			t.Error("the credential changed without a verifier")
		}
		if n := w.gatePasskeys(ada); n != 1 {
			t.Errorf("passkeys = %d, want 1", n)
		}
		if n := w.gateFailures(); n != 1 {
			t.Errorf("failures = %d, want 1", n)
		}
		if got := w.eventResults(ada, "complete_reset"); len(got) != 0 {
			t.Errorf("complete_reset events = %v, want none", got)
		}
		if n := w.sessions(ada); n != 0 {
			t.Errorf("sessions = %d, want 0", n)
		}
	})

	t.Run("admit refused", func(t *testing.T) {
		w := newWorld(t, factors)
		ada := w.User(gateLogin, pw)
		w.seedTOTP(ada)
		w.addStoredPasskey(ada, "key", false)
		w.badLogin()
		link := w.mintLink(*w.requestReset(gateLogin).TokenID)
		h := w.StoredHash(ada)
		w.P.Refuse(ada, errDeactivated)
		res := w.completeReset(link, gateNewPassword)
		if !errors.Is(res.Refusal, errDeactivated) {
			t.Errorf("refusal = %v, want the refusal from Admit", res.Refusal)
		}
		if n := w.sessions(ada); n != 0 {
			t.Errorf("sessions = %d, want 0", n)
		}
		if res.SecondStep != nil {
			t.Error("a second step was started for a refused reset")
		}
		if w.StoredHash(ada) != h {
			t.Error("the credential changed on a refused reset")
		}
		if n := w.gatePasskeys(ada); n != 1 {
			t.Errorf("passkeys = %d, want 1", n)
		}
		if n := w.gateFailures(); n != 1 {
			t.Errorf("failures = %d, want 1", n)
		}
		if n := w.challenges(ada); n != 0 {
			t.Errorf("challenges = %d, want 0", n)
		}
		if got := w.eventResults(ada, "complete_reset"); !slices.Equal(got, []string{"no_membership"}) {
			t.Errorf("complete_reset events = %v, want [no_membership]", got)
		}
	})

	t.Run("bearer no factor", func(t *testing.T) {
		w := newWorld(t, factors)
		rec := withSourceLog(w)
		ada := w.User(gateLogin, pw)
		w.addStoredPasskey(ada, "key", false)
		w.badLogin()
		link := w.mintLink(*w.requestReset(gateLogin).TokenID)
		h := w.StoredHash(ada)
		w.P.Refuse(ada, errDeactivated)
		rec.take()
		res := w.completeReset(link, gateNewPassword)
		if res.Refusal != nil || res.Principal.ID != ada {
			t.Errorf("refusal = %v, principal = %v, want nil and %v", res.Refusal, res.Principal.ID, ada)
		}
		gateNoSession(t, res)
		if n := w.sessions(ada); n != 0 {
			t.Errorf("sessions = %d, want 0", n)
		}
		if res.SecondStep != nil {
			t.Error("a second step was started for a reset without a factor")
		}
		if res.PasskeysRemoved != 1 {
			t.Errorf("PasskeysRemoved = %d, want 1", res.PasskeysRemoved)
		}
		if got := rec.take(); len(got) != 0 {
			t.Errorf("Admit was called with sources %v, want no call", got)
		}
		if w.StoredHash(ada) == h {
			t.Error("the credential is unchanged, want the new password set")
		}
		if n := w.gatePasskeys(ada); n != 0 {
			t.Errorf("passkeys = %d, want 0", n)
		}
		if n := w.gateFailures(); n != 0 {
			t.Errorf("failures = %d, want 0", n)
		}
		got := w.eventResults(ada, "complete_reset")
		slices.Sort(got)
		if !slices.Equal(got, []string{"passkeys_reset", "password_reset"}) {
			t.Errorf("complete_reset events = %v, want [passkeys_reset password_reset]", got)
		}
	})

	t.Run("session", func(t *testing.T) {
		w := sessionWorld(t, factors)
		ada := w.User(gateLogin, pw)
		w.addStoredPasskey(ada, "key", false)
		w.badLogin()
		link := w.mintLink(*w.requestReset(gateLogin).TokenID)
		h := w.StoredHash(ada)
		res := w.completeReset(link, gateNewPassword)
		if res.Refusal != nil || res.SessionToken == "" || res.SecondStep != nil {
			t.Fatalf("reset: refusal %v, session token set %v, second step %v", res.Refusal, res.SessionToken != "", res.SecondStep != nil)
		}
		if res.PasskeysRemoved != 1 {
			t.Errorf("PasskeysRemoved = %d, want 1", res.PasskeysRemoved)
		}
		if w.StoredHash(ada) == h {
			t.Error("the credential is unchanged, want the new password set")
		}
		if n := w.gatePasskeys(ada); n != 0 {
			t.Errorf("passkeys = %d, want 0", n)
		}
		if n := w.gateFailures(); n != 0 {
			t.Errorf("failures = %d, want 0", n)
		}
		if n := w.openSessions(ada); n != 1 {
			t.Errorf("open sessions = %d, want 1", n)
		}
		if n := countOf(w.eventResults(ada, "complete_reset"), "signed_in"); n != 1 {
			t.Errorf("complete_reset signed_in events = %d, want 1", n)
		}
	})

	t.Run("session refused", func(t *testing.T) {
		w := sessionWorld(t, factors)
		ada := w.User(gateLogin, pw)
		w.addStoredPasskey(ada, "key", false)
		w.badLogin()
		link := w.mintLink(*w.requestReset(gateLogin).TokenID)
		h := w.StoredHash(ada)
		w.P.Refuse(ada, errDeactivated)
		res := w.completeReset(link, gateNewPassword)
		if !errors.Is(res.Refusal, errDeactivated) {
			t.Errorf("refusal = %v, want the refusal from Admit", res.Refusal)
		}
		if n := w.sessions(ada); n != 0 {
			t.Errorf("sessions = %d, want 0", n)
		}
		if w.StoredHash(ada) != h {
			t.Error("the credential changed on a refused reset")
		}
		if n := w.gatePasskeys(ada); n != 1 {
			t.Errorf("passkeys = %d, want 1", n)
		}
		if n := w.gateFailures(); n != 1 {
			t.Errorf("failures = %d, want 1", n)
		}
		if n := countOf(w.eventResults(ada, "complete_reset"), "no_membership"); n != 1 {
			t.Errorf("complete_reset no_membership events = %d, want 1", n)
		}
	})
}

func TestThrottleCountsOnce(t *testing.T) {
	t.Run("bad password", func(t *testing.T) {
		w := newWorld(t, factors)
		ada := w.User(gateLogin, pw)
		res := w.Login("staff", gateLogin, "a wrong password")
		if !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
			t.Errorf("refusal = %v, want ErrInvalidCredentials", res.Refusal)
		}
		gateNoSession(t, res)
		if n := w.sessions(ada); n != 0 {
			t.Errorf("sessions = %d, want 0", n)
		}
		if n := w.gateFailures(); n != 1 {
			t.Errorf("failures = %d, want 1", n)
		}
	})

	t.Run("bad code", func(t *testing.T) {
		w := newWorld(t, factors)
		id, secret, _ := w.enrolTOTP(gateLogin)
		tok := w.challenge(gateLogin)
		if n := w.gateFailures(); n != 0 {
			t.Fatalf("failures before the code = %d, want 0", n)
		}
		n := w.openSessions(id)
		res := w.verify("staff", tok, authkit.FactorTOTP, wrong(w.code(secret)))
		if !errors.Is(res.Refusal, authkit.ErrBadCode) || res.Session != nil {
			t.Errorf("refusal = %v, session set %v, want ErrBadCode and no session", res.Refusal, res.Session != nil)
		}
		if got := w.openSessions(id); got != n {
			t.Errorf("open sessions = %d, want %d", got, n)
		}
		if got := w.gateFailures(); got != 1 {
			t.Errorf("failures = %d, want 1", got)
		}
		if got := w.tries(id); got != 1 {
			t.Errorf("challenge tries = %d, want 1", got)
		}
	})

	t.Run("admit refused at login", func(t *testing.T) {
		w := newWorld(t, factors)
		ada := w.User(gateLogin, pw)
		w.P.Refuse(ada, errDeactivated)
		res := w.Login("staff", gateLogin, pw)
		if !errors.Is(res.Refusal, errDeactivated) {
			t.Errorf("refusal = %v, want the refusal from Admit", res.Refusal)
		}
		gateNoSession(t, res)
		if n := w.sessions(ada); n != 0 {
			t.Errorf("sessions = %d, want 0", n)
		}
		if n := w.gateFailures(); n != 0 {
			t.Errorf("failures = %d, want 0", n)
		}
		if n := countOf(w.Results(ada), "no_membership"); n != 1 {
			t.Errorf("no_membership results = %d, want 1", n)
		}
	})

	t.Run("admit refused at second step", func(t *testing.T) {
		w := newWorld(t, factors)
		id, secret, _ := w.enrolTOTP(gateLogin)
		tok := w.challenge(gateLogin)
		n := w.openSessions(id)
		w.P.Refuse(id, errDeactivated)
		res := w.verify("staff", tok, authkit.FactorTOTP, w.code(secret))
		if !errors.Is(res.Refusal, errDeactivated) || res.Session != nil {
			t.Errorf("refusal = %v, session set %v, want the refusal from Admit and no session", res.Refusal, res.Session != nil)
		}
		if got := w.openSessions(id); got != n {
			t.Errorf("open sessions = %d, want %d", got, n)
		}
		if got := w.gateFailures(); got != 0 {
			t.Errorf("failures = %d, want 0", got)
		}
		if got := w.tries(id); got != 0 {
			t.Errorf("challenge tries = %d, want 0", got)
		}
	})

	t.Run("second step keeps the count", func(t *testing.T) {
		w := newWorld(t, factors)
		_, secret, _ := w.enrolTOTP(gateLogin)
		w.Login("staff", gateLogin, "a wrong password")
		tok := w.challenge(gateLogin)
		if n := w.gateFailures(); n != 1 {
			t.Fatalf("failures after the challenge = %d, want 1", n)
		}
		res := w.verify("staff", tok, authkit.FactorTOTP, w.code(secret))
		if res.Refusal != nil || res.Session == nil {
			t.Fatalf("second step: refusal %v, session set %v", res.Refusal, res.Session != nil)
		}
		if n := w.gateFailures(); n != 0 {
			t.Errorf("failures after the second step = %d, want 0", n)
		}
	})
}
