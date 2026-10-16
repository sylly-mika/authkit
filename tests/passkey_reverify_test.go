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

func prvEvents(w *world, id uuid.UUID, result string) int {
	w.T.Helper()
	return w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = $2 AND source = 'reverify'`, id, result)
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
