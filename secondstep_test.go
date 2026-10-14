package authkit_test

import (
	"testing"

	"github.com/sylly-mika/authkit/authkittest"
)

func TestAPasskeySignInRecordsPasskey(t *testing.T) {
	w := newWorld(t, passkeys)
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	res := w.passkeySignIn("staff", a)
	if res.Refusal != nil || res.Session == nil {
		t.Fatalf("sign-in refused: %v", res.Refusal)
	}
	if res.Session.SecondFactor != "passkey" {
		t.Errorf("session second factor %q, want passkey", res.Session.SecondFactor)
	}
	var stored string
	if err := w.d.Row(w.t, `SELECT second_factor FROM auth_sessions WHERE id = $1`, res.Session.ID).Scan(&stored); err != nil {
		w.t.Fatal(err)
	}
	if stored != "passkey" {
		t.Errorf("stored session second factor %q, want passkey", stored)
	}
	var event string
	if err := w.d.Row(w.t, `SELECT second_factor FROM auth_events WHERE principal_id = $1 AND source = 'passkey_login' AND result = 'signed_in'`, id).Scan(&event); err != nil {
		w.t.Fatal(err)
	}
	if event != "passkey" {
		t.Errorf("signed_in event second factor %q, want passkey", event)
	}
}
