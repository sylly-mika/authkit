package authkit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// expiries is a session's expires_at and absolute_expires_at as stored.
func (w *world) expiries(id uuid.UUID) (time.Time, *time.Time) {
	w.t.Helper()
	var exp time.Time
	var abs *time.Time
	if err := w.d.Row(w.t, `SELECT expires_at, absolute_expires_at FROM auth_sessions WHERE id = $1`, id).Scan(&exp, &abs); err != nil {
		w.t.Fatal(err)
	}
	return exp, abs
}

// TestASignInIsCappedByDefault is spec §3.1: 30 minutes idle and a 12-hour
// cap, set at sign-in.
func TestASignInIsCappedByDefault(t *testing.T) {
	w := newWorld(t, defaults)
	w.user("ada@example.invalid", "the right password")
	res := w.signIn("ada@example.invalid", "the right password")
	now := w.clock.Now()
	if s := res.Session; !s.ExpiresAt.Equal(now.Add(30*time.Minute)) || s.AbsoluteExpiresAt == nil || !s.AbsoluteExpiresAt.Equal(now.Add(12*time.Hour)) {
		t.Fatalf("session = %+v; want expiry now+30m and cap now+12h", s)
	}
	if exp, abs := w.expiries(res.Session.ID); !exp.Equal(now.Add(30*time.Minute)) || abs == nil || !abs.Equal(now.Add(12*time.Hour)) {
		t.Fatalf("stored expiry %v, cap %v", exp, abs)
	}
}

func TestANegativeAbsoluteTTLStoresNoCap(t *testing.T) {
	w := newWorld(t)
	w.user("ada@example.invalid", "the right password")
	res := w.signIn("ada@example.invalid", "the right password")
	if exp, abs := w.expiries(res.Session.ID); abs != nil || res.Session.AbsoluteExpiresAt != nil || !exp.Equal(w.clock.Now().Add(7*24*time.Hour)) {
		t.Fatalf("stored expiry %v, cap %v; want now+7d and no cap (ino-tasks' pins)", exp, abs)
	}
}

// TestRefreshClampsToTheCap: a refresh slides the idle expiry, never past
// the cap, and the cap never moves, so the session ends at it however busy.
func TestRefreshClampsToTheCap(t *testing.T) {
	w := newWorld(t, defaults, func(c *authkit.Config) {
		c.Session = authkit.SessionRules{IdleTTL: time.Hour, AbsoluteTTL: 2 * time.Hour}
	})
	w.user("ada@example.invalid", "the right password")
	first := w.signIn("ada@example.invalid", "the right password")
	t0 := w.clock.Now()
	w.clock.Advance(50 * time.Minute)
	second := w.refresh("staff", first.Tokens.RefreshToken)
	if exp, abs := w.expiries(first.Session.ID); second.Refusal != nil || !exp.Equal(t0.Add(110*time.Minute)) || !abs.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("after a refresh at 50m: %v, expiry %v, cap %v; want t0+1h50m and t0+2h", second.Refusal, exp, abs)
	}
	w.clock.Advance(50 * time.Minute)
	third := w.refresh("staff", second.Tokens.RefreshToken)
	if exp, abs := w.expiries(first.Session.ID); third.Refusal != nil || !exp.Equal(t0.Add(2*time.Hour)) || !abs.Equal(t0.Add(2*time.Hour)) ||
		!third.Session.ExpiresAt.Equal(exp) {
		t.Fatalf("after a refresh at 1h40m: %v, expiry %v (result %v), cap %v; want both at the cap t0+2h", third.Refusal, exp, third.Session.ExpiresAt, abs)
	}
	w.clock.Advance(20 * time.Minute)
	if res := w.refresh("staff", third.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a refresh at the cap = %v, want ErrSessionEnded", res.Refusal)
	}
}

// TestAnAudiencesIdleTimeoutIsClampedToo: RefreshTTLFor is a per-audience
// IdleTTL, under the same cap.
func TestAnAudiencesIdleTimeoutIsClampedToo(t *testing.T) {
	w := newWorld(t, defaults, func(c *authkit.Config) {
		c.Session.AbsoluteTTL = 3 * time.Hour
		c.RefreshTTLFor = map[authkit.Audience]time.Duration{"client": 2 * time.Hour}
	})
	w.user("ada@example.invalid", "the right password")
	res := w.login("client", "ada@example.invalid", "the right password")
	t0 := w.clock.Now()
	w.clock.Advance(90 * time.Minute)
	next := w.refresh("client", res.Tokens.RefreshToken)
	if exp, _ := w.expiries(res.Session.ID); next.Refusal != nil || !exp.Equal(t0.Add(3*time.Hour)) {
		t.Fatalf("client refresh at 1h30m: %v, expiry %v; want the cap t0+3h, not t0+3h30m", next.Refusal, exp)
	}
}

func (w *world) prune() {
	w.t.Helper()
	if err := w.d.InGlobalSystemTx(w.ctx, func(q db.Querier) error { return w.svc.Prune(w.ctx, q) }); err != nil {
		w.t.Fatal(err)
	}
}

// TestPruneKeepsEventsForTheRetention is spec §3.1's EventRetention: 90 days
// by default, forever when negative (ino-tasks' pin), or what the app sets.
func TestPruneKeepsEventsForTheRetention(t *testing.T) {
	day := 24 * time.Hour
	for name, tc := range map[string]struct {
		tweak func(*authkit.Config)
		kept  map[time.Duration]bool
	}{
		"the default":  {defaults, map[time.Duration]bool{91 * day: false, 89 * day: true, 29 * day: true}},
		"negative":     {func(*authkit.Config) {}, map[time.Duration]bool{91 * day: true, 89 * day: true, 29 * day: true}},
		"30 days, set": {func(c *authkit.Config) { defaults(c); c.EventRetention = 30 * day }, map[time.Duration]bool{91 * day: false, 89 * day: false, 29 * day: true}},
	} {
		w := newWorld(t, tc.tweak)
		id := w.user("ada@example.invalid", "the right password")
		now := w.clock.Now()
		for age := range tc.kept {
			w.d.Exec(t, `INSERT INTO auth_events (id, at, principal_id, audience, result) VALUES (gen_random_uuid(), $2, $1, 'staff', 'signed_in')`, id, now.Add(-age))
		}
		w.prune()
		for age, want := range tc.kept {
			if kept := w.count(`SELECT count(*) FROM auth_events WHERE at = $1`, now.Add(-age)) == 1; kept != want {
				t.Errorf("%s: an event %v old kept = %v, want %v", name, age, kept, want)
			}
		}
	}
}

func TestCheckSchemaRefusesVersionOne(t *testing.T) {
	w := newWorld(t)
	w.d.Exec(t, `UPDATE auth_schema SET version = 1`)
	if err := w.d.InAuthTx(w.ctx, func(q db.Querier) error { return authkit.CheckSchema(w.ctx, q) }); !errors.Is(err, authkit.ErrSchemaBehind) {
		t.Fatalf("a v0.1 schema = %v, want ErrSchemaBehind: v0.2 needs 0002's absolute_expires_at", err)
	}
}
