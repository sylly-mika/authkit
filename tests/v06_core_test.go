package tests

import (
	"testing"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

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
