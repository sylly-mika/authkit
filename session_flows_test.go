package authkit_test

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
)

func (w *world) openSession(p authkit.Principal) authkit.Result {
	w.t.Helper()
	return w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.OpenSession(w.ctx, q, p, "staff", authkit.Meta{IP: "192.0.2.5", UserAgent: "authkit-test"})
	})
}

// TestOpenSessionSignsInWhomTheAppAuthenticated is spec §3.5: Admit, a
// capped session and signed_in from open_session.
func TestOpenSessionSignsInWhomTheAppAuthenticated(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	p := authkit.Principal{ID: w.user("ada@example.invalid", ""), Login: "ada@example.invalid"}
	res := w.openSession(p)
	if res.Refusal != nil || res.SessionToken == "" || res.Tokens != nil || res.Admission == nil || res.Session.AbsoluteExpiresAt == nil ||
		!res.Session.AbsoluteExpiresAt.Equal(w.clock.Now().Add(12*time.Hour)) {
		t.Fatalf("OpenSession = %+v", res)
	}
	if !slices.Equal(c.pairs, []string{"open_session/signed_in"}) || w.count(`SELECT count(*) FROM auth_events WHERE session_id = $1 AND ip = '192.0.2.5'`, res.Session.ID) != 1 {
		t.Fatalf("events = %v; want one signed_in from open_session for the session", c.pairs)
	}
	if got := w.authenticateSession("staff", res.SessionToken); got.Refusal != nil {
		t.Fatalf("the opened session's token = %v", got.Refusal)
	}
	refused := authkit.Principal{ID: w.user("refused@example.invalid", ""), Login: "refused@example.invalid"}
	errDeactivated := errors.New("app: deactivated")
	w.p.Refuse(refused.ID, errDeactivated)
	if res := w.openSession(refused); res.Refusal != errDeactivated || res.Session != nil {
		t.Fatalf("OpenSession of a refused principal = %+v, want the app's refusal", res)
	}
	if !slices.Equal(c.pairs[1:], []string{"open_session/no_membership"}) || w.count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, refused.ID) != 0 {
		t.Fatalf("events = %v; want the refusal logged and no session", c.pairs)
	}
	bw := newWorld(t, defaults)
	bp := authkit.Principal{ID: bw.user("ada@example.invalid", ""), Login: "ada@example.invalid"}
	if res := bw.openSession(bp); res.Refusal != nil || res.Tokens == nil || res.SessionToken != "" {
		t.Fatalf("Bearer-mode OpenSession = %+v, want a token pair", res)
	}
}

// TestRevokeAllSessionsEndsEveryOpenSessionAndLogsEach: the revoked,
// expired and another principal's sessions are left alone.
func TestRevokeAllSessionsEndsEveryOpenSessionAndLogsEach(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	id := w.user("ada@example.invalid", "the right password")
	w.user("bob@example.invalid", "the right password")
	open := []uuid.UUID{w.signIn("ada@example.invalid", "the right password").Session.ID, w.signIn("ada@example.invalid", "the right password").Session.ID}
	expired := w.signIn("ada@example.invalid", "the right password").Session.ID
	revoked := w.signIn("ada@example.invalid", "the right password").Session.ID
	bobs := w.signIn("bob@example.invalid", "the right password").Session.ID
	w.d.Exec(t, `UPDATE auth_sessions SET expires_at = $2 WHERE id = $1`, expired, w.clock.Now())
	w.d.Exec(t, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'logout' WHERE id = $1`, revoked, w.clock.Now())
	c.pairs = nil
	w.clock.Advance(time.Second)
	if res := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.RevokeAllSessions(w.ctx, q, id, authkit.ReasonAdmin, authkit.Meta{IP: "192.0.2.6"})
	}); res.Refusal != nil {
		t.Fatalf("RevokeAllSessions = %v", res.Refusal)
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id IN ($1, $2) AND revoke_reason = 'admin'`, open[0], open[1]) != 2 ||
		w.count(`SELECT count(*) FROM auth_sessions WHERE revoke_reason = 'admin'`) != 2 {
		t.Fatal("want exactly the two open sessions revoked for admin")
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL`, bobs) != 1 {
		t.Fatal("bob's session was revoked")
	}
	if !slices.Equal(c.pairs, []string{"revoke_all/revoked", "revoke_all/revoked"}) ||
		w.count(`SELECT count(*) FROM auth_events WHERE result = 'revoked' AND session_id IN ($1, $2) AND ip = '192.0.2.6'`, open[0], open[1]) != 2 {
		t.Fatalf("events = %v; want one revoked per open session", c.pairs)
	}
	if err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
		_, err := w.svc.RevokeAllSessions(w.ctx, q, id, "fired", authkit.Meta{})
		return err
	}); err == nil || !strings.Contains(err.Error(), `"fired" is not a revoke reason`) {
		t.Fatalf("a reason outside the CHECK = %v, want authkit's own refusal before any statement", err)
	}
}

func TestHasCredential(t *testing.T) {
	w := newWorld(t, defaults)
	with, without := w.user("ada@example.invalid", "the right password"), w.user("invited@example.invalid", "")
	if has, err := w.svc.HasCredential(w.ctx, sqldb.Conn(w.pinned(with)), with); err != nil || !has {
		t.Fatalf("HasCredential of a principal with a password, on its pinned connection = %v, %v", has, err)
	}
	if err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
		has, err := w.svc.HasCredential(w.ctx, q, without)
		if err == nil && has {
			t.Error("HasCredential of a principal without a password = true")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// TestCompleteResetSignsInInSessionMode is spec §3.5: every older session
// ends, and the reset opens a new one.
func TestCompleteResetSignsInInSessionMode(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	w.user("ada@example.invalid", "the old password")
	old := w.signIn("ada@example.invalid", "the old password")
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

// TestCompleteResetAsksAdmitBeforeItWrites: in Session mode a refused
// principal's link is spent, the refusal logged, and nothing else written.
func TestCompleteResetAsksAdmitBeforeItWrites(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	id := w.user("ada@example.invalid", "the old password")
	old := w.signIn("ada@example.invalid", "the old password")
	hash := w.storedHash(id)
	link := *w.requestReset("ada@example.invalid").TokenID
	raw := w.mintLink(link)
	errDeactivated := errors.New("app: deactivated")
	w.p.Refuse(id, errDeactivated)
	c.pairs = nil
	if res := w.completeReset(raw, "the new password"); res.Refusal != errDeactivated || res.Session != nil {
		t.Fatalf("CompleteReset of a refused principal = %+v, want the app's refusal", res)
	}
	if w.storedHash(id) != hash || w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL`, old.Session.ID) != 1 {
		t.Fatal("a refused reset changed the password or ended a session")
	}
	if w.count(`SELECT count(*) FROM auth_tokens WHERE id = $1 AND used_at IS NOT NULL`, link) != 1 || !slices.Equal(c.pairs, []string{"complete_reset/no_membership"}) {
		t.Fatalf("spend kept, events = %v; want the spend and the refusal logged", c.pairs)
	}
}

// TestMayCreateCredential is spec §3.1: by default a reset never gives a
// principal its first password, neither at the request nor at the spend.
func TestMayCreateCredential(t *testing.T) {
	w := newWorld(t, defaults)
	id := w.user("invited@example.invalid", "")
	if res := w.requestReset("invited@example.invalid"); res.TokenID != nil || res.Principal.ID != id || w.count(`SELECT count(*) FROM auth_tokens`) != 0 {
		t.Fatalf("RequestReset without a credential = %+v; want no link and nothing written", res)
	}
	var link uuid.UUID
	if err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
		var err error
		link, err = w.svc.OneTime().Create(w.ctx, q, authkit.PurposeReset, id, time.Hour)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if res := w.completeReset(w.mintLink(link), "a first password"); !errors.Is(res.Refusal, authkit.ErrTokenUnknown) {
		t.Fatalf("CompleteReset without a credential = %v, want ErrTokenUnknown", res.Refusal)
	}
	if w.count(`SELECT count(*) FROM auth_credentials`)+w.count(`SELECT count(*) FROM auth_events`) != 0 ||
		w.count(`SELECT count(*) FROM auth_tokens WHERE id = $1 AND used_at IS NOT NULL`, link) != 1 {
		t.Fatal("want the spend kept and no credential or event written")
	}
}

// TestChangePasswordRevokeAllReopens is spec §3.5's ChangePassword+All:
// every session ends, the change is logged against the caller's, and the
// caller gets a new session, its cap counted afresh.
func TestChangePasswordRevokeAllReopens(t *testing.T) {
	var c captured
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent; cfg.RevokeOnPasswordChange = authkit.RevokeAll })
	id := w.user("ada@example.invalid", "the old password")
	other := w.signIn("ada@example.invalid", "the old password")
	current := w.signIn("ada@example.invalid", "the old password")
	w.clock.Advance(10 * time.Minute)
	c.pairs = nil
	res := w.changePassword(w.pinned(id), current.Claims(), "the old password", "the new password")
	now := w.clock.Now()
	if res.Refusal != nil || res.SessionToken == "" || res.Session.ID == current.Session.ID || !res.Session.AbsoluteExpiresAt.Equal(now.Add(12*time.Hour)) {
		t.Fatalf("ChangePassword under RevokeAll = %+v; want a new session capped from now", res)
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id IN ($1, $2) AND revoke_reason = 'password_changed'`, other.Session.ID, current.Session.ID) != 2 {
		t.Fatal("want both earlier sessions revoked for password_changed")
	}
	if !slices.Equal(c.pairs, []string{"change_password/password_changed", "change_password/signed_in"}) ||
		w.count(`SELECT count(*) FROM auth_events WHERE result = 'password_changed' AND session_id = $1`, current.Session.ID) != 1 {
		t.Fatalf("events = %v; want password_changed against the caller's session, then signed_in", c.pairs)
	}
	if w.authenticateSession("staff", current.SessionToken).Refusal == nil || w.authenticateSession("staff", res.SessionToken).Refusal != nil {
		t.Fatal("want the old token ended and the new one open")
	}
	bw := newWorld(t, defaults, func(cfg *authkit.Config) { cfg.RevokeOnPasswordChange = authkit.RevokeAll })
	bid := bw.user("ada@example.invalid", "the old password")
	if res := bw.changePassword(bw.pinned(bid), bw.claims(bw.signIn("ada@example.invalid", "the old password")), "the old password", "the new password"); res.Tokens == nil {
		t.Fatalf("Bearer-mode ChangePassword under RevokeAll = %+v, want a new token pair", res)
	}
}

// TestChangePasswordRevokeAllAsksAdmitFirst: a refusal writes nothing.
func TestChangePasswordRevokeAllAsksAdmitFirst(t *testing.T) {
	w := sessionWorld(t, func(cfg *authkit.Config) { cfg.RevokeOnPasswordChange = authkit.RevokeAll })
	id := w.user("ada@example.invalid", "the old password")
	current := w.signIn("ada@example.invalid", "the old password")
	hash, events := w.storedHash(id), w.count(`SELECT count(*) FROM auth_events`)
	errDeactivated := errors.New("app: deactivated")
	w.p.Refuse(id, errDeactivated)
	if res := w.changePassword(w.pinned(id), current.Claims(), "the old password", "the new password"); res.Refusal != errDeactivated {
		t.Fatalf("a refused change = %v, want the app's refusal", res.Refusal)
	}
	if w.storedHash(id) != hash || w.count(`SELECT count(*) FROM auth_events`) != events ||
		w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL`, current.Session.ID) != 1 {
		t.Fatal("a refused change wrote")
	}
}
