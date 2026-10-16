package tests

import (
	"crypto/sha256"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

func (w *world) seedOIDCCeremony(aud string, expires time.Time, spent any) {
	w.T.Helper()
	state, other := sha256.Sum256([]byte("state "+aud)), sha256.Sum256([]byte(aud))
	w.D.Exec(w.T, `INSERT INTO auth_ceremonies (id, kind, provider, state_hash, binding_hash, nonce_hash, verifier, audience, created_at, expires_at, spent_at) VALUES ($1, 'signin', 'google', $2, $3, $3, 'v', $4, $5, $6, $7)`,
		uuid.New(), state[:], other[:], aud, w.Clock.Now().Add(-2*time.Hour), expires, spent)
}

func (w *world) seedIdentity(id uuid.UUID, provider, subject string) {
	w.T.Helper()
	w.D.Exec(w.T, `INSERT INTO auth_identities (id, principal_id, provider, subject, email, created_at, last_used_at) VALUES ($1, $2, $3, $4, $5, $6, $6)`,
		uuid.New(), id, provider, subject, subject+"@example.invalid", w.Clock.Now())
}

func TestRevokeAllSessionsTakesIdentityRemoved(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the right password")
	w.SignIn("ada@example.invalid", "the right password")
	w.SignIn("ada@example.invalid", "the right password")
	res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.RevokeAllSessions(w.Ctx, q, id, authkit.ReasonIdentityRemoved, authkit.Meta{})
	})
	if res.Refusal != nil {
		t.Fatalf("refusal %v", res.Refusal)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND revoke_reason = 'identity_removed'", id); n != 2 {
		t.Errorf("identity_removed sessions = %d, want 2", n)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND revoked_at IS NULL", id); n != 0 {
		t.Errorf("open sessions = %d, want 0", n)
	}
}

func TestPruneV06Tables(t *testing.T) {
	w := newWorld(t)
	now := w.Clock.Now()
	w.seedOIDCCeremony("old", now.Add(-61*time.Minute), nil)
	w.seedOIDCCeremony("spent-old", now.Add(-59*time.Minute), now.Add(-61*time.Minute))
	w.seedOIDCCeremony("edge", now.Add(-59*time.Minute), nil)
	w.seedOIDCCeremony("spent-edge", now.Add(time.Minute), now.Add(-59*time.Minute))
	w.seedOIDCCeremony("live", now.Add(10*time.Minute), nil)
	w.D.Exec(t, "INSERT INTO auth_registrations (id, audience, email, created_at, expires_at) VALUES ($1, 'staff', $2, $3, $4)", uuid.New(), "gone@example.invalid", now.Add(-48*time.Hour), now.Add(-time.Second))
	w.D.Exec(t, "INSERT INTO auth_registrations (id, audience, email, created_at, expires_at) VALUES ($1, 'staff', $2, $3, $4)", uuid.New(), "live@example.invalid", now.Add(-48*time.Hour), now.Add(time.Second))
	for _, c := range []struct {
		email string
		start time.Time
	}{
		{"old@example.invalid", now.Add(-48*time.Hour - time.Second)},
		{"recent@example.invalid", now.Add(-47*time.Hour - 59*time.Minute)},
	} {
		key := sha256.Sum256([]byte(c.email))
		w.D.Exec(t, "INSERT INTO auth_mail_counts (audience, email_key, window_started_at, sent) VALUES ('staff', $1, $2, 1)", key[:], c.start)
	}
	if err := w.D.InGlobalSystemTx(w.Ctx, func(q db.Querier) error { return w.Svc.Prune(w.Ctx, q) }); err != nil {
		t.Fatal(err)
	}

	t.Run("ceremonies", func(t *testing.T) {
		for _, c := range []struct {
			aud  string
			want int
		}{{"old", 0}, {"spent-old", 0}, {"edge", 1}, {"spent-edge", 1}, {"live", 1}} {
			if n := w.Count("SELECT count(*) FROM auth_ceremonies WHERE audience = $1", c.aud); n != c.want {
				t.Errorf("ceremonies %q = %d, want %d", c.aud, n, c.want)
			}
		}
	})

	t.Run("registrations", func(t *testing.T) {
		if n := w.Count("SELECT count(*) FROM auth_registrations WHERE email = 'gone@example.invalid'"); n != 0 {
			t.Errorf("expired registration = %d rows, want 0", n)
		}
		if n := w.Count("SELECT count(*) FROM auth_registrations WHERE email = 'live@example.invalid'"); n != 1 {
			t.Errorf("live registration = %d rows, want 1", n)
		}
	})

	t.Run("mail counts", func(t *testing.T) {
		old, recent := sha256.Sum256([]byte("old@example.invalid")), sha256.Sum256([]byte("recent@example.invalid"))
		if n := w.Count("SELECT count(*) FROM auth_mail_counts WHERE email_key = $1", old[:]); n != 0 {
			t.Errorf("old mail count = %d rows, want 0", n)
		}
		if n := w.Count("SELECT count(*) FROM auth_mail_counts WHERE email_key = $1", recent[:]); n != 1 {
			t.Errorf("recent mail count = %d rows, want 1", n)
		}
	})
}

func TestResetCredentialsRemovesIdentities(t *testing.T) {
	w := newWorld(t)
	ada := w.User("ada@example.invalid", "the right password")
	bob := w.User("bob@example.invalid", "the right password")
	w.seedIdentity(ada, "google", "ada-google")
	w.seedIdentity(ada, "apple", "ada-apple")
	w.seedIdentity(bob, "google", "bob-google")
	link := w.mintLink(*w.requestReset("ada@example.invalid").TokenID)
	res := w.completeReset(link, "a brand new password")
	if res.Refusal != nil {
		t.Fatalf("reset refusal %v", res.Refusal)
	}
	if n := w.Count("SELECT count(*) FROM auth_identities WHERE principal_id = $1", ada); n != 0 {
		t.Errorf("ada's identities = %d, want 0", n)
	}
	if n := w.Count("SELECT count(*) FROM auth_identities WHERE principal_id = $1", bob); n != 1 {
		t.Errorf("bob's identities = %d, want 1", n)
	}
	results := w.Results(ada)
	if !slices.Contains(results, "password_reset") || slices.Contains(results, "passkeys_reset") {
		t.Errorf("results = %v, want password_reset and no passkeys_reset", results)
	}
}
