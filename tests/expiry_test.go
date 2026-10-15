package tests

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
)

func (w *world) expiries(id uuid.UUID) (time.Time, *time.Time) {
	w.T.Helper()
	var exp time.Time
	var abs *time.Time
	if err := w.D.Row(w.T, `SELECT expires_at, absolute_expires_at FROM auth_sessions WHERE id = $1`, id).Scan(&exp, &abs); err != nil {
		w.T.Fatal(err)
	}
	return exp, abs
}

func TestASignInIsCappedByDefault(t *testing.T) {
	w := newWorld(t, kittest.DefaultRules)
	w.User("ada@example.invalid", "the right password")
	res := w.SignIn("ada@example.invalid", "the right password")
	now := w.Clock.Now()
	if s := res.Session; !s.ExpiresAt.Equal(now.Add(30*time.Minute)) || s.AbsoluteExpiresAt == nil || !s.AbsoluteExpiresAt.Equal(now.Add(12*time.Hour)) {
		t.Fatalf("session = %+v; want expiry now+30m and cap now+12h", s)
	}
	if exp, abs := w.expiries(res.Session.ID); !exp.Equal(now.Add(30*time.Minute)) || abs == nil || !abs.Equal(now.Add(12*time.Hour)) {
		t.Fatalf("stored expiry %v, cap %v", exp, abs)
	}
}

func TestANegativeAbsoluteTTLStoresNoCap(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the right password")
	res := w.SignIn("ada@example.invalid", "the right password")
	if exp, abs := w.expiries(res.Session.ID); abs != nil || res.Session.AbsoluteExpiresAt != nil || !exp.Equal(w.Clock.Now().Add(7*24*time.Hour)) {
		t.Fatalf("stored expiry %v, cap %v; want now+7d and no cap (ino-tasks' pins)", exp, abs)
	}
}

func TestRefreshClampsToTheCap(t *testing.T) {
	w := newWorld(t, kittest.DefaultRules, func(c *kittest.Rules) {
		c.Session = authkit.SessionRules{IdleTTL: time.Hour, AbsoluteTTL: 2 * time.Hour}
	})
	w.User("ada@example.invalid", "the right password")
	first := w.SignIn("ada@example.invalid", "the right password")
	t0 := w.Clock.Now()
	w.Clock.Advance(50 * time.Minute)
	second := w.refresh("staff", first.Tokens.RefreshToken)
	if exp, abs := w.expiries(first.Session.ID); second.Refusal != nil || !exp.Equal(t0.Add(110*time.Minute)) || !abs.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("after a refresh at 50m: %v, expiry %v, cap %v; want t0+1h50m and t0+2h", second.Refusal, exp, abs)
	}
	w.Clock.Advance(50 * time.Minute)
	third := w.refresh("staff", second.Tokens.RefreshToken)
	if exp, abs := w.expiries(first.Session.ID); third.Refusal != nil || !exp.Equal(t0.Add(2*time.Hour)) || !abs.Equal(t0.Add(2*time.Hour)) ||
		!third.Session.ExpiresAt.Equal(exp) {
		t.Fatalf("after a refresh at 1h40m: %v, expiry %v (result %v), cap %v; want both at the cap t0+2h", third.Refusal, exp, third.Session.ExpiresAt, abs)
	}
	w.Clock.Advance(20 * time.Minute)
	if res := w.refresh("staff", third.Tokens.RefreshToken); !errors.Is(res.Refusal, authkit.ErrSessionEnded) {
		t.Fatalf("a refresh at the cap = %v, want ErrSessionEnded", res.Refusal)
	}
}

func TestAnAudiencesIdleTimeoutIsClampedToo(t *testing.T) {
	w := newWorld(t, kittest.DefaultRules, func(c *kittest.Rules) {
		c.Session.AbsoluteTTL = 3 * time.Hour
		c.RefreshTTLFor = map[authkit.Audience]time.Duration{"client": 2 * time.Hour}
	})
	w.User("ada@example.invalid", "the right password")
	res := w.Login("client", "ada@example.invalid", "the right password")
	t0 := w.Clock.Now()
	w.Clock.Advance(90 * time.Minute)
	next := w.refresh("client", res.Tokens.RefreshToken)
	if exp, _ := w.expiries(res.Session.ID); next.Refusal != nil || !exp.Equal(t0.Add(3*time.Hour)) {
		t.Fatalf("client refresh at 1h30m: %v, expiry %v; want the cap t0+3h, not t0+3h30m", next.Refusal, exp)
	}
}

func (w *world) prune() {
	w.T.Helper()
	if err := w.D.InGlobalSystemTx(w.Ctx, func(q db.Querier) error { return w.Svc.Prune(w.Ctx, q) }); err != nil {
		w.T.Fatal(err)
	}
}

func TestPruneKeepsEventsForTheRetention(t *testing.T) {
	day := 24 * time.Hour
	for name, tc := range map[string]struct {
		tweak func(*kittest.Rules)
		kept  map[time.Duration]bool
	}{
		"the default":  {kittest.DefaultRules, map[time.Duration]bool{91 * day: false, 89 * day: true, 29 * day: true}},
		"negative":     {func(*kittest.Rules) {}, map[time.Duration]bool{91 * day: true, 89 * day: true, 29 * day: true}},
		"30 days, set": {func(c *kittest.Rules) { kittest.DefaultRules(c); c.EventRetention = 30 * day }, map[time.Duration]bool{91 * day: false, 89 * day: false, 29 * day: true}},
	} {
		w := newWorld(t, tc.tweak)
		id := w.User("ada@example.invalid", "the right password")
		now := w.Clock.Now()
		for age := range tc.kept {
			w.D.Exec(t, `INSERT INTO auth_events (id, at, principal_id, audience, result) VALUES (gen_random_uuid(), $2, $1, 'staff', 'signed_in')`, id, now.Add(-age))
		}
		w.prune()
		for age, want := range tc.kept {
			if kept := w.Count(`SELECT count(*) FROM auth_events WHERE at = $1`, now.Add(-age)) == 1; kept != want {
				t.Errorf("%s: an event %v old kept = %v, want %v", name, age, kept, want)
			}
		}
	}
}

func TestCheckSchemaRefusesVersionOne(t *testing.T) {
	w := newWorld(t)
	w.D.Exec(t, `UPDATE auth_schema SET version = 1`)
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error { return w.Svc.CheckSchema(w.Ctx, q) }); !errors.Is(err, authkit.ErrSchemaBehind) {
		t.Fatalf("a v0.1 schema = %v, want ErrSchemaBehind: v0.2 needs 0002's absolute_expires_at", err)
	}
}
