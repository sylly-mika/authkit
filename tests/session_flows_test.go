package tests

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/internal/kittest"
)

func (w *world) openSession(p authkit.Principal) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.OpenSession(w.Ctx, q, p, "staff", authkit.Meta{IP: "192.0.2.5", UserAgent: "authkit-test"})
	})
}

func TestOpenSessionSignsInWhomTheAppAuthenticated(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	p := authkit.Principal{ID: w.User("ada@example.invalid", ""), Login: "ada@example.invalid"}
	res := w.openSession(p)
	if res.Refusal != nil || res.SessionToken == "" || res.Tokens != nil || res.Admission == nil || res.Session.AbsoluteExpiresAt == nil ||
		!res.Session.AbsoluteExpiresAt.Equal(w.Clock.Now().Add(12*time.Hour)) {
		t.Fatalf("OpenSession = %+v", res)
	}
	if !slices.Equal(c.pairs, []string{"open_session/signed_in"}) || w.Count(`SELECT count(*) FROM auth_events WHERE session_id = $1 AND ip = '192.0.2.5'`, res.Session.ID) != 1 {
		t.Fatalf("events = %v; want one signed_in from open_session for the session", c.pairs)
	}
	if got := w.authenticateSession("staff", res.SessionToken); got.Refusal != nil {
		t.Fatalf("the opened session's token = %v", got.Refusal)
	}
	refused := authkit.Principal{ID: w.User("refused@example.invalid", ""), Login: "refused@example.invalid"}
	errDeactivated := errors.New("app: deactivated")
	w.P.Refuse(refused.ID, errDeactivated)
	if res := w.openSession(refused); res.Refusal != errDeactivated || res.Session != nil {
		t.Fatalf("OpenSession of a refused principal = %+v, want the app's refusal", res)
	}
	if !slices.Equal(c.pairs[1:], []string{"open_session/no_membership"}) || w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, refused.ID) != 0 {
		t.Fatalf("events = %v; want the refusal logged and no session", c.pairs)
	}
	bw := newWorld(t, kittest.DefaultRules)
	bp := authkit.Principal{ID: bw.User("ada@example.invalid", ""), Login: "ada@example.invalid"}
	if res := bw.openSession(bp); res.Refusal != nil || res.Tokens == nil || res.SessionToken != "" {
		t.Fatalf("Bearer-mode OpenSession = %+v, want a token pair", res)
	}
}

func TestRevokeAllSessionsEndsEveryOpenSessionAndLogsEach(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	id := w.User("ada@example.invalid", "the right password")
	w.User("bob@example.invalid", "the right password")
	open := []uuid.UUID{w.SignIn("ada@example.invalid", "the right password").Session.ID, w.SignIn("ada@example.invalid", "the right password").Session.ID}
	expired := w.SignIn("ada@example.invalid", "the right password").Session.ID
	revoked := w.SignIn("ada@example.invalid", "the right password").Session.ID
	bobs := w.SignIn("bob@example.invalid", "the right password").Session.ID
	w.D.Exec(t, `UPDATE auth_sessions SET expires_at = $2 WHERE id = $1`, expired, w.Clock.Now())
	w.D.Exec(t, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'logout' WHERE id = $1`, revoked, w.Clock.Now())
	c.pairs = nil
	w.Clock.Advance(time.Second)
	if res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.RevokeAllSessions(w.Ctx, q, id, authkit.ReasonAdmin, authkit.Meta{IP: "192.0.2.6"})
	}); res.Refusal != nil {
		t.Fatalf("RevokeAllSessions = %v", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id IN ($1, $2) AND revoke_reason = 'admin'`, open[0], open[1]) != 2 ||
		w.Count(`SELECT count(*) FROM auth_sessions WHERE revoke_reason = 'admin'`) != 2 {
		t.Fatal("want exactly the two open sessions revoked for admin")
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL`, bobs) != 1 {
		t.Fatal("bob's session was revoked")
	}
	if !slices.Equal(c.pairs, []string{"revoke_all/revoked", "revoke_all/revoked"}) ||
		w.Count(`SELECT count(*) FROM auth_events WHERE result = 'revoked' AND session_id IN ($1, $2) AND ip = '192.0.2.6'`, open[0], open[1]) != 2 {
		t.Fatalf("events = %v; want one revoked per open session", c.pairs)
	}
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		_, err := w.Svc.RevokeAllSessions(w.Ctx, q, id, "fired", authkit.Meta{})
		return err
	}); err == nil || !strings.Contains(err.Error(), `"fired" is not a revoke reason`) {
		t.Fatalf("a reason outside the CHECK = %v, want authkit's own refusal before any statement", err)
	}
}

func TestHasCredential(t *testing.T) {
	w := newWorld(t, kittest.DefaultRules)
	with, without := w.User("ada@example.invalid", "the right password"), w.User("invited@example.invalid", "")
	if has, err := w.Svc.HasCredential(w.Ctx, sqldb.Conn(w.Pinned(with)), with); err != nil || !has {
		t.Fatalf("HasCredential of a principal with a password, on its kittest.PinnedRules connection = %v, %v", has, err)
	}
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		has, err := w.Svc.HasCredential(w.Ctx, q, without)
		if err == nil && has {
			t.Error("HasCredential of a principal without a password = true")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCompleteResetSignsInInSessionMode(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	w.User("ada@example.invalid", "the old password")
	old := w.SignIn("ada@example.invalid", "the old password")
	raw := w.mintLink(*w.requestReset("ada@example.invalid").TokenID)
	c.pairs = nil
	res := w.completeReset(raw, "the new password")
	if res.Refusal != nil || res.SessionToken == "" || res.Session == nil || res.Session.ID == old.Session.ID {
		t.Fatalf("Session-mode CompleteReset = %+v; want a new session", res)
	}
	if !slices.Equal(c.pairs, []string{"complete_reset/password_reset", "complete_reset/signed_in"}) {
		t.Fatalf("events = %v; want password_reset, then signed_in", c.pairs)
	}
	if w.authenticateSession("staff", old.SessionToken).Refusal == nil || w.authenticateSession("staff", res.SessionToken).Refusal != nil {
		t.Fatal("want the old session ended and the new one open")
	}
}

func TestCompleteResetAsksAdmitBeforeItWrites(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	id := w.User("ada@example.invalid", "the old password")
	old := w.SignIn("ada@example.invalid", "the old password")
	hash := w.StoredHash(id)
	link := *w.requestReset("ada@example.invalid").TokenID
	raw := w.mintLink(link)
	errDeactivated := errors.New("app: deactivated")
	w.P.Refuse(id, errDeactivated)
	c.pairs = nil
	if res := w.completeReset(raw, "the new password"); res.Refusal != errDeactivated || res.Session != nil {
		t.Fatalf("CompleteReset of a refused principal = %+v, want the app's refusal", res)
	}
	if w.StoredHash(id) != hash || w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL`, old.Session.ID) != 1 {
		t.Fatal("a refused reset changed the password or ended a session")
	}
	if w.Count(`SELECT count(*) FROM auth_tokens WHERE id = $1 AND used_at IS NOT NULL`, link) != 1 || !slices.Equal(c.pairs, []string{"complete_reset/no_membership"}) {
		t.Fatalf("spend kept, events = %v; want the spend and the refusal logged", c.pairs)
	}
}

func TestMayCreateCredential(t *testing.T) {
	w := newWorld(t, kittest.DefaultRules)
	id := w.User("invited@example.invalid", "")
	if res := w.requestReset("invited@example.invalid"); res.TokenID != nil || res.Principal.ID != id || w.Count(`SELECT count(*) FROM auth_tokens`) != 0 {
		t.Fatalf("RequestReset without a credential = %+v; want no link and nothing written", res)
	}
	var link uuid.UUID
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		var err error
		link, err = w.Svc.OneTime().Create(w.Ctx, q, authkit.PurposeReset, id, time.Hour)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if res := w.completeReset(w.mintLink(link), "a first password"); !errors.Is(res.Refusal, authkit.ErrTokenUnknown) {
		t.Fatalf("CompleteReset without a credential = %v, want ErrTokenUnknown", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_credentials`)+w.Count(`SELECT count(*) FROM auth_events`) != 0 ||
		w.Count(`SELECT count(*) FROM auth_tokens WHERE id = $1 AND used_at IS NOT NULL`, link) != 1 {
		t.Fatal("want the spend kept and no credential or event written")
	}
}

func TestChangePasswordRevokeAllReopens(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent; cfg.RevokeOnPasswordChange = authkit.RevokeAll })
	id := w.User("ada@example.invalid", "the old password")
	other := w.SignIn("ada@example.invalid", "the old password")
	current := w.SignIn("ada@example.invalid", "the old password")
	w.Clock.Advance(10 * time.Minute)
	c.pairs = nil
	res := w.changePassword(w.Pinned(id), current.Claims(), "the old password", "the new password")
	now := w.Clock.Now()
	if res.Refusal != nil || res.SessionToken == "" || res.Session.ID == current.Session.ID || !res.Session.AbsoluteExpiresAt.Equal(now.Add(12*time.Hour)) {
		t.Fatalf("ChangePassword under RevokeAll = %+v; want a new session capped from now", res)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id IN ($1, $2) AND revoke_reason = 'password_changed'`, other.Session.ID, current.Session.ID) != 2 {
		t.Fatal("want both earlier sessions revoked for password_changed")
	}
	if !slices.Equal(c.pairs, []string{"change_password/password_changed", "change_password/signed_in"}) ||
		w.Count(`SELECT count(*) FROM auth_events WHERE result = 'password_changed' AND session_id = $1`, current.Session.ID) != 1 {
		t.Fatalf("events = %v; want password_changed against the caller's session, then signed_in", c.pairs)
	}
	if w.authenticateSession("staff", current.SessionToken).Refusal == nil || w.authenticateSession("staff", res.SessionToken).Refusal != nil {
		t.Fatal("want the old token ended and the new one open")
	}
	bw := newWorld(t, kittest.DefaultRules, func(cfg *authkit.Config) { cfg.RevokeOnPasswordChange = authkit.RevokeAll })
	bid := bw.User("ada@example.invalid", "the old password")
	if res := bw.changePassword(bw.Pinned(bid), bw.Claims(bw.SignIn("ada@example.invalid", "the old password")), "the old password", "the new password"); res.Tokens == nil {
		t.Fatalf("Bearer-mode ChangePassword under RevokeAll = %+v, want a new token pair", res)
	}
}

func TestChangePasswordRevokeAllAsksAdmitFirst(t *testing.T) {
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.RevokeOnPasswordChange = authkit.RevokeAll })
	id := w.User("ada@example.invalid", "the old password")
	current := w.SignIn("ada@example.invalid", "the old password")
	hash, events := w.StoredHash(id), w.Count(`SELECT count(*) FROM auth_events`)
	errDeactivated := errors.New("app: deactivated")
	w.P.Refuse(id, errDeactivated)
	if res := w.changePassword(w.Pinned(id), current.Claims(), "the old password", "the new password"); res.Refusal != errDeactivated {
		t.Fatalf("a refused change = %v, want the app's refusal", res.Refusal)
	}
	if w.StoredHash(id) != hash || w.Count(`SELECT count(*) FROM auth_events`) != events ||
		w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL`, current.Session.ID) != 1 {
		t.Fatal("a refused change wrote")
	}
}

func TestOpenSessionFromKeepsTheSignInTime(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	id := w.User("ada@example.invalid", "the right password")
	p := authkit.Principal{ID: id, Login: "ada@example.invalid"}
	t0 := w.Clock.Now()
	first := w.SignIn("ada@example.invalid", "the right password")
	w.Clock.Advance(3 * time.Minute)
	now := w.Clock.Now()
	res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.OpenSessionFrom(w.Ctx, q, first.Session.ID, p, "staff", authkit.Meta{IP: "192.0.2.7", UserAgent: "authkit-test"})
	})
	if res.Refusal != nil || res.SessionToken == "" || res.Session.ID == first.Session.ID || !res.Session.AuthenticatedAt.Equal(t0) {
		t.Fatalf("OpenSessionFrom = %+v; want a new session that keeps authenticated_at %v", res, t0)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND authenticated_at = $2 AND created_at = $3 AND absolute_expires_at = $4`,
		res.Session.ID, t0, now, now.Add(12*time.Hour)) != 1 {
		t.Fatal("the new row must keep the old authenticated_at and count its other times from now")
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL AND authenticated_at = $2`, first.Session.ID, t0) != 1 {
		t.Fatal("OpenSessionFrom must leave the session it copies from open and unchanged")
	}
	if c.pairs[len(c.pairs)-1] != "open_session/signed_in" || w.Count(`SELECT count(*) FROM auth_events WHERE session_id = $1 AND ip = '192.0.2.7'`, res.Session.ID) != 1 {
		t.Fatalf("events = %v; want the switch logged as open_session/signed_in", c.pairs)
	}
	if got := w.authenticateSession("staff", res.SessionToken); got.Refusal != nil {
		t.Fatalf("the switched session's token = %v", got.Refusal)
	}
}

func TestOpenSessionFromRefusesAnotherPrincipalsSession(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	adaID := w.User("ada@example.invalid", "the right password")
	ada := authkit.Principal{ID: adaID, Login: "ada@example.invalid"}
	w.SignIn("ada@example.invalid", "the right password")
	w.User("bob@example.invalid", "the right password")
	bobs := w.SignIn("bob@example.invalid", "the right password").Session.ID
	before := w.Count(`SELECT count(*) FROM auth_sessions`)
	ev := w.Count(`SELECT count(*) FROM auth_events`)
	c.pairs = nil
	for _, from := range []uuid.UUID{bobs, uuid.New()} {
		err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
			_, err := w.Svc.OpenSessionFrom(w.Ctx, q, from, ada, "staff", authkit.Meta{})
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "the session is not the principal's") {
			t.Fatalf("OpenSessionFrom(%v) = %v; want a refusal that the session is not the principal's", from, err)
		}
	}
	if w.Count(`SELECT count(*) FROM auth_sessions`) != before || w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, adaID) != 1 {
		t.Fatal("a refused OpenSessionFrom must open no session")
	}
	if w.Count(`SELECT count(*) FROM auth_events`) != ev || len(c.pairs) != 0 {
		t.Fatalf("a refused OpenSessionFrom must record no event; saw %v", c.pairs)
	}
}

func TestOpenSessionFromAsksAdmit(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	carolID := w.User("carol@example.invalid", "the right password")
	carol := authkit.Principal{ID: carolID, Login: "carol@example.invalid"}
	first := w.SignIn("carol@example.invalid", "the right password")
	errDeactivated := errors.New("app: deactivated")
	w.P.Refuse(carolID, errDeactivated)
	c.pairs = nil
	res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.OpenSessionFrom(w.Ctx, q, first.Session.ID, carol, "staff", authkit.Meta{})
	})
	if res.Refusal != errDeactivated || res.Session != nil || res.SessionToken != "" {
		t.Fatalf("OpenSessionFrom of a refused principal = %+v; want the app's refusal", res)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, carolID) != 1 {
		t.Fatal("a refused OpenSessionFrom must open no session")
	}
	if !slices.Equal(c.pairs, []string{"open_session/no_membership"}) {
		t.Fatalf("events = %v; want the refusal logged", c.pairs)
	}
}

func TestOpenSessionFromAcceptsAnEndedSession(t *testing.T) {
	w := sessionWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	p := authkit.Principal{ID: id, Login: "ada@example.invalid"}
	t0 := w.Clock.Now()
	first := w.SignIn("ada@example.invalid", "the right password")
	w.D.Exec(t, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'logout' WHERE id = $1`, first.Session.ID, t0)
	w.Clock.Advance(time.Minute)
	res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.OpenSessionFrom(w.Ctx, q, first.Session.ID, p, "staff", authkit.Meta{})
	})
	if res.Refusal != nil || res.SessionToken == "" {
		t.Fatalf("OpenSessionFrom of an ended session = %+v; want a session", res)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND authenticated_at = $2`, res.Session.ID, t0) != 1 {
		t.Fatal("the new session must keep the ended session's authenticated_at")
	}
	if got := w.authenticateSession("staff", res.SessionToken); got.Refusal != nil {
		t.Fatalf("the switched session's token = %v", got.Refusal)
	}
}

func TestRevokeAllSessionsTakesPasskeyRemoved(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	id := w.User("ada@example.invalid", "the right password")
	w.SignIn("ada@example.invalid", "the right password")
	w.SignIn("ada@example.invalid", "the right password")
	c.pairs = nil
	if res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.RevokeAllSessions(w.Ctx, q, id, authkit.ReasonPasskeyRemoved, authkit.Meta{})
	}); res.Refusal != nil {
		t.Fatalf("RevokeAllSessions = %v", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND revoke_reason = 'passkey_removed'`, id) != 2 {
		t.Fatal("want both open sessions revoked for passkey_removed")
	}
	if !slices.Equal(c.pairs, []string{"revoke_all/revoked", "revoke_all/revoked"}) {
		t.Fatalf("events = %v; want one revoked per session", c.pairs)
	}
}

func TestOpenSessionFromRefusesAnotherAudience(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	id := w.User("ada@example.invalid", "the right password")
	ada := authkit.Principal{ID: id, Login: "ada@example.invalid"}
	first := w.SignIn("ada@example.invalid", "the right password")
	before := w.Count(`SELECT count(*) FROM auth_sessions`)
	ev := w.Count(`SELECT count(*) FROM auth_events`)
	c.pairs = nil
	err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		_, err := w.Svc.OpenSessionFrom(w.Ctx, q, first.Session.ID, ada, "portal", authkit.Meta{})
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "the session is not the principal's") {
		t.Fatalf("OpenSessionFrom into another audience = %v; want a refusal", err)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions`) != before || w.Count(`SELECT count(*) FROM auth_events`) != ev || len(c.pairs) != 0 {
		t.Fatalf("a refused OpenSessionFrom must write nothing; events %v", c.pairs)
	}
}

func TestCompleteResetRemovesEveryPasskey(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	ada := w.User("ada@example.invalid", "the old password")
	bob := w.User("bob@example.invalid", "the right password")
	old := w.SignIn("ada@example.invalid", "the old password")
	w.addStoredPasskey(ada, "Laptop", false)
	w.addStoredPasskey(ada, "Phone", true)
	w.addStoredPasskey(bob, "Bob key", false)
	raw := w.mintLink(*w.requestReset("ada@example.invalid").TokenID)
	c.pairs = nil
	res := w.completeReset(raw, "the new password")
	if res.Refusal != nil || res.Session == nil || res.PasskeysRemoved != 2 {
		t.Fatalf("CompleteReset = %+v; want 2 passkeys removed and a session", res)
	}
	if w.Count(`SELECT count(*) FROM auth_passkeys WHERE principal_id = $1`, ada) != 0 || w.Count(`SELECT count(*) FROM auth_passkeys WHERE principal_id = $1`, bob) != 1 {
		t.Fatal("want none of ada's passkeys left and bob's kept")
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoke_reason = 'password_reset'`, old.Session.ID) != 1 {
		t.Fatal("want the old session revoked for password_reset")
	}
	if !slices.Equal(c.pairs, []string{"complete_reset/password_reset", "complete_reset/passkeys_reset", "complete_reset/signed_in"}) {
		t.Fatalf("events = %v; want password_reset, passkeys_reset, then signed_in", c.pairs)
	}
	if w.Count(`SELECT count(*) FROM auth_events WHERE result = 'passkeys_reset' AND principal_id = $1`, ada) != 1 {
		t.Fatal("want one passkeys_reset event for ada")
	}
}

func TestBearerCompleteResetReportsTheRemovedPasskeys(t *testing.T) {
	w := newWorld(t)
	ada := w.User("ada@example.invalid", "the old password")
	w.addStoredPasskey(ada, "Laptop", false)
	raw := w.mintLink(*w.requestReset("ada@example.invalid").TokenID)
	res := w.completeReset(raw, "the new password")
	if res.Refusal != nil || res.Tokens != nil || res.PasskeysRemoved != 1 {
		t.Fatalf("Bearer CompleteReset = %+v; want 1 passkey removed and no tokens", res)
	}
	if w.Count(`SELECT count(*) FROM auth_passkeys WHERE principal_id = $1`, ada) != 0 {
		t.Fatal("want ada's passkey removed")
	}
}

func TestCompleteResetWithoutPasskeysLogsNoPasskeyEvent(t *testing.T) {
	var c captured
	w := newWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	w.User("ada@example.invalid", "the old password")
	raw := w.mintLink(*w.requestReset("ada@example.invalid").TokenID)
	c.pairs = nil
	res := w.completeReset(raw, "the new password")
	if res.Refusal != nil || res.PasskeysRemoved != 0 {
		t.Fatalf("CompleteReset without passkeys = %+v; want none removed", res)
	}
	if !slices.Equal(c.pairs, []string{"complete_reset/password_reset"}) {
		t.Fatalf("events = %v; want password_reset only", c.pairs)
	}
	if w.Count(`SELECT count(*) FROM auth_events WHERE result = 'passkeys_reset'`) != 0 {
		t.Fatal("want no passkeys_reset event")
	}
}

func TestARefusedResetKeepsThePasskeys(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	id := w.User("ada@example.invalid", "the old password")
	w.addStoredPasskey(id, "Laptop", false)
	raw := w.mintLink(*w.requestReset("ada@example.invalid").TokenID)
	errDeactivated := errors.New("app: deactivated")
	w.P.Refuse(id, errDeactivated)
	c.pairs = nil
	res := w.completeReset(raw, "the new password")
	if res.Refusal != errDeactivated || res.PasskeysRemoved != 0 {
		t.Fatalf("refused CompleteReset = %+v; want the app's refusal and no passkey removed", res)
	}
	if w.Count(`SELECT count(*) FROM auth_passkeys WHERE principal_id = $1`, id) != 1 {
		t.Fatal("a refused reset must keep the passkey")
	}
	if slices.Contains(c.pairs, "complete_reset/passkeys_reset") {
		t.Fatalf("events = %v; a refused reset must not log passkeys_reset", c.pairs)
	}
}
