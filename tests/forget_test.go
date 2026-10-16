package tests

import (
	"cmp"
	"crypto/sha256"
	"errors"
	"maps"
	"reflect"
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

type forgetIDs struct {
	principal, session, invite, event uuid.UUID
	login, key                        string
}

type forgetCheck struct {
	table, where string
	arg          func(forgetIDs) any
	n            int
}

var (
	forgetByPrincipal = func(f forgetIDs) any { return f.principal }
	forgetBySession   = func(f forgetIDs) any { return f.session }
	forgetByInvite    = func(f forgetIDs) any { return f.invite }
	forgetByKey       = func(f forgetIDs) any { return f.key }
	forgetByLogin     = func(f forgetIDs) any { return f.login }
)

var forgetChecks = []forgetCheck{
	{"auth_sessions", "principal_id = $1", forgetByPrincipal, 2},
	{"auth_credentials", "principal_id = $1", forgetByPrincipal, 1},
	{"auth_tokens", "owner_id = $1", forgetByPrincipal, 2},
	{"auth_tokens", "owner_id = $1", forgetByInvite, 1},
	{"auth_events", "principal_id = $1", forgetByPrincipal, 1},
	{"auth_events", "session_id = $1", forgetBySession, 1},
	{"auth_throttle", "login = $1", forgetByKey, 2},
	{"auth_passkeys", "principal_id = $1", forgetByPrincipal, 1},
	{"auth_passkey_ceremonies", "principal_id = $1", forgetByPrincipal, 1},
	{"auth_second_factors", "principal_id = $1", forgetByPrincipal, 1},
	{"auth_recovery_codes", "principal_id = $1", forgetByPrincipal, 1},
	{"auth_second_step_challenges", "principal_id = $1", forgetByPrincipal, 1},
	{"auth_email_codes", "principal_id = $1", forgetByPrincipal, 1},
	{"auth_ceremonies", "principal_id = $1", forgetByPrincipal, 1},
	{"auth_identities", "principal_id = $1", forgetByPrincipal, 1},
	{"auth_email_changes", "principal_id = $1", forgetByPrincipal, 1},
	{"auth_registrations", "email = $1", forgetByLogin, 1},
	{"auth_invites", "email = $1", forgetByLogin, 1},
}

func (w *world) forget(p authkit.Principal) authkit.Forgotten {
	w.T.Helper()
	var f authkit.Forgotten
	w.InAuth(func(q db.Querier) (authkit.Result, error) {
		var err error
		f, err = w.Svc.Forget(w.Ctx, q, p)
		return authkit.Result{}, err
	})
	return f
}

func (w *world) seedForget(login string) forgetIDs {
	w.T.Helper()
	f := forgetIDs{principal: w.User(login, ""), session: uuid.New(), invite: uuid.New(), event: uuid.New(), login: authkit.Normalize(login)}
	f.key = kittest.HashedKey(f.login)
	now := w.Clock.Now()
	hash := func(s string) []byte { h := sha256.Sum256([]byte(f.login + " " + s)); return h[:] }
	w.D.Exec(w.T, `INSERT INTO auth_sessions (id, principal_id, audience, token_hash, authenticated_at, created_at, expires_at) VALUES ($1, $2, 'staff', $3, $4, $4, $5), ($6, $2, 'client', $7, $4, $4, $5)`, f.session, f.principal, hash("session"), now, now.Add(time.Hour), uuid.New(), hash("session 2"))
	w.D.Exec(w.T, `INSERT INTO auth_credentials (principal_id, password_hash, changed_at) VALUES ($1, 'not a hash', $2)`, f.principal, now)
	w.D.Exec(w.T, `INSERT INTO auth_tokens (id, purpose, owner_id, ttl, expires_at, created_at) VALUES ($1, 'reset', $2, interval '1 hour', $3, $4), ($5, 'email_change', $2, interval '1 hour', $3, $4), ($6, 'invite', $7, interval '1 hour', $3, $4)`, uuid.New(), f.principal, now.Add(time.Hour), now, uuid.New(), uuid.New(), f.invite)
	w.D.Exec(w.T, `INSERT INTO auth_events (id, at, principal_id, session_id, audience, login, result, ip) VALUES ($1, $2, $3, $4, 'staff', $5, 'signed_in', '192.0.2.1')`, f.event, now, f.principal, f.session, f.login)
	w.D.Exec(w.T, `INSERT INTO auth_throttle (login, audience, failures, window_start) VALUES ($1, 'staff', 1, $2), ($1, 'client', 1, $2)`, f.key, now)
	w.D.Exec(w.T, `INSERT INTO auth_passkeys (id, principal_id, credential_id, label, data, created_at) VALUES ($1, $2, $3, 'key', '{}', $4)`, uuid.New(), f.principal, hash("credential"), now)
	w.D.Exec(w.T, `INSERT INTO auth_passkey_ceremonies (id, ceremony_hash, kind, audience, principal_id, session_id, data, expires_at) VALUES ($1, $2, 'register', 'staff', $3, $4, '{}', $5)`, uuid.New(), hash("ceremony"), f.principal, f.session, now.Add(time.Hour))
	w.D.Exec(w.T, `INSERT INTO auth_second_factors (principal_id, kind, created_at) VALUES ($1, 'email', $2)`, f.principal, now)
	w.D.Exec(w.T, `INSERT INTO auth_recovery_codes (id, principal_id, code_hash, created_at) VALUES ($1, $2, $3, $4)`, uuid.New(), f.principal, hash("recovery"), now)
	w.D.Exec(w.T, `INSERT INTO auth_second_step_challenges (id, challenge_hash, principal_id, audience, origin, throttle_key, created_at, expires_at) VALUES ($1, $2, $3, 'staff', 'login', $4, $5, $6)`, uuid.New(), hash("challenge"), f.principal, f.key, now, now.Add(time.Hour))
	w.D.Exec(w.T, `INSERT INTO auth_email_codes (id, principal_id, purpose, last_sent_at, expires_at) VALUES ($1, $2, 'sign_in', $3, $4)`, uuid.New(), f.principal, now, now.Add(time.Hour))
	w.D.Exec(w.T, `INSERT INTO auth_ceremonies (id, kind, provider, audience, state_hash, principal_id, created_at, expires_at) VALUES ($1, 'link', 'google', 'staff', $2, $3, $4, $5)`, uuid.New(), hash("state"), f.principal, now, now.Add(time.Hour))
	w.seedIdentity(f.principal, "google", f.login+"-google")
	w.D.Exec(w.T, `INSERT INTO auth_registrations (id, audience, email, created_at, expires_at) VALUES ($1, 'staff', $2, $3, $4)`, uuid.New(), f.login, now, now.Add(time.Hour))
	w.D.Exec(w.T, `INSERT INTO auth_invites (id, audience, email, created_at, expires_at) VALUES ($1, 'staff', $2, $3, $4)`, f.invite, f.login, now, now.Add(72*time.Hour))
	w.D.Exec(w.T, `INSERT INTO auth_email_changes (principal_id, audience, old_email, new_email, session_id, created_at, expires_at) VALUES ($1, 'staff', $2, $3, $4, $5, $6)`, f.principal, f.login, "new-"+f.login, f.session, now, now.Add(24*time.Hour))
	return f
}

func (w *world) countFor(c forgetCheck, f forgetIDs) int {
	w.T.Helper()
	return w.Count("SELECT count(*) FROM "+c.table+" WHERE "+c.where, c.arg(f))
}

func (w *world) seedPasskey(id uuid.UUID) {
	w.T.Helper()
	cred := uuid.New()
	w.D.Exec(w.T, `INSERT INTO auth_passkeys (id, principal_id, credential_id, label, data, created_at) VALUES ($1, $2, $3, 'key', '{}', $4)`, uuid.New(), id, cred[:], w.Clock.Now())
}

func TestForgetLeavesNoRow(t *testing.T) {
	w := newWorld(t, func(c *kittest.Rules) {
		c.Throttle.PlainLoginKey = false
		c.EventRetention = 90 * 24 * time.Hour
	})
	ada := w.seedForget("Ada@Example.invalid")
	bob := w.seedForget("bob@example.invalid")
	tables := map[string]bool{"auth_mail_counts": true, "auth_schema": true}
	for _, c := range forgetChecks {
		tables[c.table] = true
	}
	var got string
	if err := w.D.Row(t, `SELECT string_agg(tablename, ' ' ORDER BY tablename) FROM pg_tables WHERE schemaname = $1 AND tablename LIKE 'auth\_%'`,
		cmp.Or(w.Cfg.Config.Schema, "public")).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if want := strings.Join(slices.Sorted(maps.Keys(tables)), " "); got != want {
		t.Fatalf("auth_ tables = %q, want %q: a table Forget does not know about, or a fixture for one it does not", got, want)
	}
	for _, c := range forgetChecks {
		if n := w.countFor(c, ada); n != c.n {
			t.Fatalf("before Forget, %s WHERE %s for ada = %d, want the %d the fixture wrote", c.table, c.where, n, c.n)
		}
	}
	w.forget(authkit.Principal{ID: ada.principal, Login: "Ada@Example.invalid"})
	for _, c := range forgetChecks {
		if n := w.countFor(c, ada); n != 0 {
			t.Errorf("after Forget, %s WHERE %s for ada = %d, want 0", c.table, c.where, n)
		}
		if n := w.countFor(c, bob); n != c.n {
			t.Errorf("after Forget, %s WHERE %s for bob = %d, want %d", c.table, c.where, n, c.n)
		}
	}
	if n := w.Count("SELECT count(*) FROM auth_events WHERE id = $1", ada.event); n != 1 {
		t.Errorf("ada's sign-in event rows = %d, want 1 (kept, unlinked)", n)
	}
}

func TestForgetCounts(t *testing.T) {
	w := newWorld(t)
	ada := w.User("ada@example.invalid", "the right password")
	res1 := w.SignIn("ada@example.invalid", "the right password")
	w.logout(w.Pinned(ada), w.Claims(res1))
	w.SignIn("ada@example.invalid", "the right password")
	for range 3 {
		w.seedPasskey(ada)
	}
	w.seedIdentity(ada, "google", "ada-google")
	w.seedIdentity(ada, "apple", "ada-apple")
	bob := w.User("bob@example.invalid", "the right password")
	w.SignIn("bob@example.invalid", "the right password")
	w.seedPasskey(bob)

	got := w.forget(authkit.Principal{ID: ada, Login: "ada@example.invalid"})
	if got.Sessions != 2 || got.Passkeys != 3 || got.Identities != 2 {
		t.Errorf("Forget = %+v, want 2 sessions, 3 passkeys, 2 identities", got)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", ada); n != 0 {
		t.Errorf("ada's sessions after Forget = %d, want 0", n)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", bob); n != 1 {
		t.Errorf("bob's sessions after Forget = %d, want 1", n)
	}
	if n := w.Count("SELECT count(*) FROM auth_passkeys WHERE principal_id = $1", bob); n != 1 {
		t.Errorf("bob's passkeys after Forget = %d, want 1", n)
	}
}

func TestForgetProviders(t *testing.T) {
	w := newWorld(t)
	ada := w.User("ada@example.invalid", "")
	w.seedIdentity(ada, "google", "ada-google")
	w.seedIdentity(ada, "apple", "ada-apple")
	carol := w.User("carol@example.invalid", "")

	got := w.forget(authkit.Principal{ID: ada, Login: "ada@example.invalid"})
	if !slices.Equal(got.Providers, []string{"apple", "google"}) {
		t.Errorf("ada's Providers = %v, want [apple google]", got.Providers)
	}
	none := w.forget(authkit.Principal{ID: carol, Login: "carol@example.invalid"})
	if len(none.Providers) != 0 || none.Identities != 0 {
		t.Errorf("carol's Providers = %v, Identities = %d; want none", none.Providers, none.Identities)
	}
}

func TestForgetInvitesByLogin(t *testing.T) {
	w := newWorld(t)
	ada := w.User("Ada@Example.invalid", "")
	bob := w.User("bob@example.invalid", "")
	i1, i2, i3, i4 := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := w.Clock.Now()
	invite := func(id uuid.UUID, aud, email string, by uuid.NullUUID) {
		w.D.Exec(w.T, `INSERT INTO auth_invites (id, audience, email, invited_by, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6)`,
			id, aud, email, by, now, now.Add(72*time.Hour))
		w.D.Exec(w.T, `INSERT INTO auth_tokens (id, purpose, owner_id, ttl, expires_at, created_at) VALUES ($1, 'invite', $2, interval '1 hour', $3, $4)`,
			uuid.New(), id, now.Add(time.Hour), now)
	}
	invite(i1, "staff", "ada@example.invalid", uuid.NullUUID{})
	invite(i2, "client", "ada@example.invalid", uuid.NullUUID{})
	invite(i3, "staff", "carol@example.invalid", uuid.NullUUID{UUID: ada, Valid: true})
	invite(i4, "staff", "dave@example.invalid", uuid.NullUUID{UUID: bob, Valid: true})
	tokensOf := func(id uuid.UUID) int {
		return w.Count("SELECT count(*) FROM auth_tokens WHERE owner_id = $1", id)
	}

	w.forget(authkit.Principal{ID: ada, Login: "Ada@Example.invalid"})
	if n := w.Count("SELECT count(*) FROM auth_invites WHERE id IN ($1, $2)", i1, i2); n != 0 {
		t.Errorf("ada's invites left = %d, want 0", n)
	}
	if n := w.Count("SELECT count(*) FROM auth_tokens WHERE owner_id IN ($1, $2)", i1, i2); n != 0 {
		t.Errorf("tokens of ada's invites left = %d, want 0", n)
	}
	if n := w.Count("SELECT count(*) FROM auth_invites WHERE id = $1 AND invited_by = $2", i3, ada); n != 1 {
		t.Errorf("the invite ada sent to carol has invited_by = ada %d times, want 1", n)
	}
	if n := tokensOf(i3); n != 1 {
		t.Errorf("tokens of the invite ada sent = %d, want 1", n)
	}
	if n := w.Count("SELECT count(*) FROM auth_invites WHERE id = $1 AND invited_by = $2", i4, bob); n != 1 {
		t.Errorf("bob's invite to dave changed: %d rows, want 1", n)
	}
	if n := tokensOf(i4); n != 1 {
		t.Errorf("tokens of bob's invite = %d, want 1", n)
	}

	w.D.Exec(w.T, "DELETE FROM users WHERE id = $1", ada)
	if n := w.Count("SELECT count(*) FROM auth_invites WHERE id = $1 AND invited_by IS NULL", i3); n != 1 {
		t.Errorf("after ada's user row is deleted, the invite she sent has invited_by set %d times, want 1 (NULL)", n)
	}
}

func TestForgetEventsKept(t *testing.T) {
	w := newWorld(t, func(c *kittest.Rules) { c.EventRetention = 90 * 24 * time.Hour })
	ada := w.User("ada@example.invalid", "the right password")
	w.SignIn("ada@example.invalid", "the right password")
	w.SignIn("ada@example.invalid", "the right password")
	n := w.Count("SELECT count(*) FROM auth_events WHERE principal_id = $1", ada)
	if n == 0 {
		t.Fatal("no sign-in event was written for ada")
	}

	w.forget(authkit.Principal{ID: ada, Login: "ada@example.invalid"})
	if left := w.Count("SELECT count(*) FROM auth_events WHERE principal_id = $1", ada); left != 0 {
		t.Errorf("events still linked to ada = %d, want 0", left)
	}
	if kept := w.Count("SELECT count(*) FROM auth_events WHERE login = 'ada@example.invalid' AND principal_id IS NULL AND session_id IS NULL AND ip = '192.0.2.1'"); kept != n {
		t.Errorf("unlinked events kept for ada = %d, want %d", kept, n)
	}
}

func TestForgetEventsForever(t *testing.T) {
	w := newWorld(t)
	ada := w.User("ada@example.invalid", "the right password")
	bob := w.User("bob@example.invalid", "the right password")
	w.SignIn("ada@example.invalid", "the right password")
	w.SignIn("bob@example.invalid", "the right password")
	b := w.Count("SELECT count(*) FROM auth_events WHERE principal_id = $1", bob)
	if b == 0 {
		t.Fatal("no sign-in event was written for bob")
	}

	w.forget(authkit.Principal{ID: ada, Login: "ada@example.invalid"})
	if n := w.Count("SELECT count(*) FROM auth_events WHERE login = 'ada@example.invalid'"); n != 0 {
		t.Errorf("ada's events after Forget = %d, want 0 (EventRetention is negative, so they go)", n)
	}
	if n := w.Count("SELECT count(*) FROM auth_events WHERE principal_id = $1", bob); n != b {
		t.Errorf("bob's events after Forget = %d, want %d", n, b)
	}
}

func TestForgetSessionEnded(t *testing.T) {
	w := newWorld(t)
	ada := w.User("ada@example.invalid", "the right password")
	res := w.SignIn("ada@example.invalid", "the right password")
	c := w.Claims(res)

	w.forget(authkit.Principal{ID: ada, Login: "ada@example.invalid"})
	if r := w.authenticate(w.Pinned(ada), c); !errors.Is(r.Refusal, authkit.ErrSessionEnded) {
		t.Errorf("Authenticate after Forget = %v, want ErrSessionEnded", r.Refusal)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", ada); n != 0 {
		t.Errorf("ada's sessions after Forget = %d, want 0", n)
	}
	if n := w.Count("SELECT count(*) FROM users WHERE id = $1", ada); n != 1 {
		t.Errorf("ada's users row after Forget = %d, want 1 (Forget leaves the principal)", n)
	}
}

func TestForgetNeedsTx(t *testing.T) {
	w := newWorld(t)
	ada := w.User("ada@example.invalid", "the right password")
	w.SignIn("ada@example.invalid", "the right password")

	f, err := w.Svc.Forget(w.Ctx, sqldb.Conn(w.Pinned(ada)), authkit.Principal{ID: ada, Login: "ada@example.invalid"})
	if !errors.Is(err, db.ErrTxRequired) {
		t.Fatalf("Forget on a bare connection = %v, want db.ErrTxRequired", err)
	}
	if !reflect.ValueOf(f).IsZero() {
		t.Errorf("Forget on a bare connection returned %+v, want the zero Forgotten", f)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", ada); n != 1 {
		t.Errorf("ada's sessions = %d, want 1", n)
	}
	if n := w.Count("SELECT count(*) FROM auth_credentials WHERE principal_id = $1", ada); n != 1 {
		t.Errorf("ada's credentials = %d, want 1", n)
	}
}
