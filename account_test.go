package authkit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/migrations"
)

func TestListSessionsPagesAndMarksTheCurrentOne(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	first := w.signIn("ada@example.invalid", "the right password")
	w.clock.Advance(time.Minute)
	second := w.signIn("ada@example.invalid", "the right password")
	w.clock.Advance(time.Minute)
	third := w.signIn("ada@example.invalid", "the right password")
	w.d.Exec(t, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'logout' WHERE id = $1`, first.Session.ID, w.clock.Now())
	q, c := sqldb.Conn(w.pinned(id)), w.claims(third)
	page, total, err := w.svc.ListSessions(w.ctx, q, c, 1, 0)
	if err != nil || total != 2 || len(page) != 1 || page[0].ID != third.Session.ID || !page[0].Current {
		t.Fatalf("page 1 = %+v, total %d (%v)", page, total, err)
	}
	page, _, err = w.svc.ListSessions(w.ctx, q, c, 1, 1)
	if err != nil || len(page) != 1 || page[0].ID != second.Session.ID || page[0].Current {
		t.Fatalf("page 2 = %+v (%v)", page, err)
	}
}

func TestRevokeSessionLogsRevokedAndReachesOnlyOwnSessions(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	bob := w.user("bob@example.invalid", "the right password")
	old := w.signIn("ada@example.invalid", "the right password")
	current := w.signIn("ada@example.invalid", "the right password")
	bobs := w.signIn("bob@example.invalid", "the right password")
	conn, c := w.pinned(id), w.claims(current)
	revoke := func(target authkit.Result) authkit.Result {
		return w.inConn(conn, func(q db.Querier) (authkit.Result, error) {
			return w.svc.RevokeSession(w.ctx, q, c, target.Session.ID, authkit.Meta{})
		})
	}
	if res := revoke(old); res.Refusal != nil {
		t.Fatalf("revoking an own session = %v", res.Refusal)
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoke_reason = 'user'`, old.Session.ID) != 1 ||
		w.count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'revoked' AND session_id = $2 AND scope_id = $3`, id, old.Session.ID, w.p.Scope) != 1 {
		t.Fatal("no revoke with reason user and revoked event")
	}
	for name, target := range map[string]authkit.Result{"again": old, "bob's": bobs} {
		if res := revoke(target); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
			t.Errorf("%s: %v, want ErrSessionEnded (ino-tasks 404)", name, res.Refusal)
		}
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND revoked_at IS NULL`, bob) != 1 {
		t.Fatal("ada revoked bob's session")
	}
}

// TestAccountMethodsCleanMeta: the account methods log the request's
// metadata, so a NUL or invalid UTF-8 in it must not turn their result into
// an error, as it does not Login's.
func TestAccountMethodsCleanMeta(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the old password")
	invited := w.user("invited@example.invalid", "")
	dirty := authkit.Meta{IP: "192.0.2.3\x00", UserAgent: "authkit-\xfftest\x00"}
	old := w.signIn("ada@example.invalid", "the old password")
	current := w.signIn("ada@example.invalid", "the old password")
	conn, c := w.pinned(id), w.claims(current)
	if res := w.inConn(conn, func(q db.Querier) (authkit.Result, error) {
		return w.svc.RevokeSession(w.ctx, q, c, old.Session.ID, dirty)
	}); res.Refusal != nil {
		t.Fatalf("RevokeSession with a NUL in its metadata = %v", res.Refusal)
	}
	if res := w.inConn(conn, func(q db.Querier) (authkit.Result, error) {
		return w.svc.ChangePassword(w.ctx, q, c, "the old password", "the new password", dirty)
	}); res.Refusal != nil {
		t.Fatalf("ChangePassword with a NUL in its metadata = %v", res.Refusal)
	}
	raw := w.mintLink(*w.requestReset("ada@example.invalid").TokenID)
	if res := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.CompleteReset(w.ctx, q, "staff", raw, "the reset password", dirty)
	}); res.Refusal != nil {
		t.Fatalf("CompleteReset with a NUL in its metadata = %v", res.Refusal)
	}
	p := authkit.Principal{ID: invited, Login: "invited@example.invalid"}
	if res := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.SetPassword(w.ctx, q, p, "staff", "a first password", dirty)
	}); res.Refusal != nil {
		t.Fatalf("SetPassword with a NUL in its metadata = %v", res.Refusal)
	}
	if res := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.VerifyPassword(w.ctx, q, p, "staff", "a wrong password", dirty)
	}); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("VerifyPassword with a NUL in its metadata = %v, want ErrInvalidCredentials", res.Refusal)
	}
	cleaned := `SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = $2 AND ip = '192.0.2.3' AND user_agent = 'authkit-test'`
	for _, tc := range []struct {
		principal uuid.UUID
		result    string
		n         int
	}{
		{id, "revoked", 1},
		{id, "password_reset", 2},
		{invited, "password_set", 1},
		{invited, "bad_password", 1},
	} {
		if got := w.count(cleaned, tc.principal, tc.result); got != tc.n {
			t.Errorf("%s: %d events with the cleaned IP and user agent, want %d", tc.result, got, tc.n)
		}
	}
}

func TestListEventsExcludesResults(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	w.login("staff", "ada@example.invalid", "a wrong password")
	w.clock.Advance(time.Second)
	w.signIn("ada@example.invalid", "the right password")
	for _, r := range []string{"locked", "reuse_detected"} {
		w.d.Exec(t, `INSERT INTO auth_events (id, at, principal_id, audience, result) VALUES (gen_random_uuid(), $2, $1, 'staff', $3)`, id, w.clock.Now(), r)
	}
	q := sqldb.Conn(w.pinned(id))
	page, total, err := w.svc.ListEvents(w.ctx, q, id, []string{authkit.ResultLocked, authkit.ResultReuseDetected}, 10, 0)
	if err != nil || total != 2 || len(page) != 2 || page[0].Result != "signed_in" || page[1].Result != "bad_password" {
		t.Fatalf("filtered = %+v, total %d (%v)", page, total, err)
	}
	if _, total, _ := w.svc.ListEvents(w.ctx, q, id, nil, 10, 0); total != 4 {
		t.Fatalf("unfiltered total = %d, want 4", total)
	}
	if _, _, err := w.svc.ListEvents(w.ctx, q, id, []string{"a,b"}, 10, 0); err == nil {
		t.Fatal("ListEvents accepted a result name with a comma")
	}
}

func TestPruneDeletesOnlyWhatIsPastRetention(t *testing.T) {
	w := newWorld(t)
	w.user("ada@example.invalid", "the right password")
	old := w.signIn("ada@example.invalid", "the right password")
	w.d.Exec(t, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'logout' WHERE id = $1`, old.Session.ID, w.clock.Now())
	w.clock.Advance(31 * 24 * time.Hour)
	fresh := w.signIn("ada@example.invalid", "the right password")
	w.login("staff", "ada@example.invalid", "a wrong password")
	w.d.Exec(t, `INSERT INTO auth_throttle (login, audience, failures, window_start) VALUES ('stale@example.invalid', 'staff', 3, $1)`, w.clock.Now().Add(-20*time.Minute))
	if err := w.d.InGlobalSystemTx(w.ctx, func(q db.Querier) error { return w.svc.Prune(w.ctx, q) }); err != nil {
		t.Fatal(err)
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1`, old.Session.ID) != 0 || w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1`, fresh.Session.ID) != 1 {
		t.Fatal("Prune kept the 31-day-old session or deleted the fresh one")
	}
	if w.count(`SELECT count(*) FROM auth_throttle WHERE login = 'stale@example.invalid'`) != 0 || w.count(`SELECT count(*) FROM auth_throttle WHERE login = 'ada@example.invalid'`) != 1 {
		t.Fatal("Prune kept a stale counter or dropped a live one")
	}
}

func TestCheckSchema(t *testing.T) {
	w := newWorld(t)
	if err := w.d.InAuthTx(w.ctx, func(q db.Querier) error { return authkit.CheckSchema(w.ctx, q) }); err != nil {
		t.Fatalf("a current schema = %v", err)
	}
	w.d.Exec(t, `UPDATE auth_schema SET version = 0`)
	if err := w.d.InAuthTx(w.ctx, func(q db.Querier) error { return authkit.CheckSchema(w.ctx, q) }); !errors.Is(err, authkit.ErrSchemaBehind) {
		t.Fatalf("an older schema = %v, want ErrSchemaBehind", err)
	}
}

// TestDeletingAPrincipalCascades is spec §8.10.
func TestDeletingAPrincipalCascades(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	w.signIn("ada@example.invalid", "the right password")
	w.d.Exec(t, `DELETE FROM users WHERE id = $1`, id)
	if w.count(`SELECT count(*) FROM auth_sessions`)+w.count(`SELECT count(*) FROM auth_credentials`) != 0 {
		t.Fatal("the principal's sessions or credential survived it")
	}
	if w.count(`SELECT count(*) FROM auth_events WHERE principal_id IS NULL AND login = 'ada@example.invalid'`) != 1 {
		t.Fatal("the sign-in log lost its row instead of forgetting the principal")
	}
}

// TestAccountMethodsReachOnlyTheirPrincipal runs the account methods with no
// workspace bound, where the _auth policies admit every row, so only the
// library's own principal predicates keep ada's calls off bob's rows. On the
// pinned connection the self policies would hide a missing predicate.
func TestAccountMethodsReachOnlyTheirPrincipal(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the old password")
	w.user("bob@example.invalid", "bob's password")
	w.login("staff", "bob@example.invalid", "a wrong password")
	bobs := w.signIn("bob@example.invalid", "bob's password")
	keep := w.signIn("ada@example.invalid", "the old password")
	c := w.claims(keep)
	bobOpen := func() bool {
		return w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL`, bobs.Session.ID) == 1
	}

	var sessions []authkit.Session
	var events []authkit.Event
	var nSessions, nEvents int
	if err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
		var err error
		if sessions, nSessions, err = w.svc.ListSessions(w.ctx, q, c, 10, 0); err != nil {
			return err
		}
		events, nEvents, err = w.svc.ListEvents(w.ctx, q, id, nil, 10, 0)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if nSessions != 1 || len(sessions) != 1 || sessions[0].ID != keep.Session.ID {
		t.Errorf("ListSessions = %d sessions, total %d; want ada's one", len(sessions), nSessions)
	}
	if nEvents != 1 || len(events) != 1 || events[0].Result != authkit.ResultSignedIn {
		t.Errorf("ListEvents = %d events, total %d; want ada's signed_in", len(events), nEvents)
	}

	if res := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.RevokeSession(w.ctx, q, c, bobs.Session.ID, authkit.Meta{})
	}); !errors.Is(res.Refusal, authkit.ErrSessionEnded) || !bobOpen() {
		t.Fatalf("ada revoking bob's session = %v, want ErrSessionEnded with bob's session open", res.Refusal)
	}
	if w.count(`SELECT count(*) FROM auth_events WHERE result = 'revoked'`) != 0 {
		t.Fatal("a refused revoke logged revoked")
	}

	if res := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.ChangePassword(w.ctx, q, c, "the old password", "the new password", authkit.Meta{})
	}); res.Refusal != nil || !bobOpen() {
		t.Fatalf("ada's change = %v; bob's session open: %v", res.Refusal, bobOpen())
	}

	if res := w.completeReset(w.mintLink(*w.requestReset("ada@example.invalid").TokenID), "the reset password"); res.Refusal != nil || !bobOpen() {
		t.Fatalf("ada's reset = %v; bob's session open: %v", res.Refusal, bobOpen())
	}
	if w.count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND revoked_at IS NULL`, id) != 0 {
		t.Fatal("ada's reset left one of her sessions open")
	}
}

// TestPruneKeepsEachTableUntilItsRetentionPasses pins the 30-day cut-off on
// sessions and one-time links: what died 29 days ago stays, what died 31 days
// ago goes, and a live link stays.
func TestPruneKeepsEachTableUntilItsRetentionPasses(t *testing.T) {
	w := newWorld(t)
	id := w.user("ada@example.invalid", "the right password")
	now, day := w.clock.Now(), 24*time.Hour
	sessions := map[string]uuid.UUID{}
	for _, name := range []string{"revoked 31", "revoked 29", "expired 31", "expired 29"} {
		sessions[name] = w.signIn("ada@example.invalid", "the right password").Session.ID
	}
	w.d.Exec(t, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'logout' WHERE id = $1`, sessions["revoked 31"], now.Add(-31*day))
	w.d.Exec(t, `UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'logout' WHERE id = $1`, sessions["revoked 29"], now.Add(-29*day))
	w.d.Exec(t, `UPDATE auth_sessions SET expires_at = $2 WHERE id = $1`, sessions["expired 31"], now.Add(-31*day))
	w.d.Exec(t, `UPDATE auth_sessions SET expires_at = $2 WHERE id = $1`, sessions["expired 29"], now.Add(-29*day))
	links := map[string]uuid.UUID{"used 31": uuid.New(), "used 29": uuid.New()}
	for name, ago := range map[string]time.Duration{"used 31": 31 * day, "used 29": 29 * day} {
		w.d.Exec(t, `INSERT INTO auth_tokens (id, purpose, owner_id, ttl, expires_at, used_at, created_at) VALUES ($1, 'reset', $2, interval '1 hour', $3, $3, $3)`,
			links[name], id, now.Add(-ago))
	}
	links["live"] = *w.requestReset("ada@example.invalid").TokenID
	if err := w.d.InGlobalSystemTx(w.ctx, func(q db.Querier) error { return w.svc.Prune(w.ctx, q) }); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]int{"revoked 31": 0, "revoked 29": 1, "expired 31": 0, "expired 29": 1} {
		if got := w.count(`SELECT count(*) FROM auth_sessions WHERE id = $1`, sessions[name]); got != want {
			t.Errorf("the session %s days ago: %d rows after Prune, want %d", name, got, want)
		}
	}
	for name, want := range map[string]int{"used 31": 0, "used 29": 1, "live": 1} {
		if got := w.count(`SELECT count(*) FROM auth_tokens WHERE id = $1`, links[name]); got != want {
			t.Errorf("the link %s: %d rows after Prune, want %d", name, got, want)
		}
	}
}

// TestCheckSchemaAcceptsANewerSchemaAndRefusesAMissingOne: an app rolled back
// past a library upgrade still starts; a database without the row or the
// table does not.
func TestCheckSchemaAcceptsANewerSchemaAndRefusesAMissingOne(t *testing.T) {
	w := newWorld(t)
	check := func() error {
		return w.d.InAuthTx(w.ctx, func(q db.Querier) error { return authkit.CheckSchema(w.ctx, q) })
	}
	w.d.Exec(t, `UPDATE auth_schema SET version = $1`, migrations.Version+1)
	if err := check(); err != nil {
		t.Fatalf("a newer schema = %v, want nil", err)
	}
	w.d.Exec(t, `DELETE FROM auth_schema`)
	if err := check(); !errors.Is(err, authkit.ErrSchemaBehind) {
		t.Fatalf("no auth_schema row = %v, want ErrSchemaBehind", err)
	}
	w.d.Exec(t, `DROP TABLE auth_schema`)
	if err := check(); !errors.Is(err, authkit.ErrSchemaBehind) {
		t.Fatalf("no auth_schema table = %v, want ErrSchemaBehind", err)
	}
}
