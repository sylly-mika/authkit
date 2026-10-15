package tests

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/ceremony"
)

func TestPruneDeletesCeremoniesAnHourPastExpiry(t *testing.T) {
	w := newWorld(t)
	now := w.Clock.Now()
	rnd := authkittest.Rand(3)
	err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		for _, aud := range []string{"old", "spent-old", "edge", "live"} {
			if _, _, err := ceremony.Create(w.Ctx, q, rnd, ceremony.KindLogin, aud, nil, nil, webauthn.SessionData{Challenge: "c"}, now, 2*time.Minute); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	w.D.Exec(t, `UPDATE auth_passkey_ceremonies SET expires_at = $1 WHERE audience = 'old'`, now.Add(-61*time.Minute))
	w.D.Exec(t, `UPDATE auth_passkey_ceremonies SET expires_at = $1, used_at = $2 WHERE audience = 'spent-old'`, now.Add(-61*time.Minute), now.Add(-62*time.Minute))
	w.D.Exec(t, `UPDATE auth_passkey_ceremonies SET expires_at = $1 WHERE audience = 'edge'`, now.Add(-59*time.Minute))
	if err := w.D.InGlobalSystemTx(w.Ctx, func(q db.Querier) error {
		return w.Svc.Prune(w.Ctx, q)
	}); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"old": 0, "spent-old": 0, "edge": 1, "live": 1}
	for aud, n := range want {
		var got int
		if err := w.D.Row(t, `SELECT count(*) FROM auth_passkey_ceremonies WHERE audience = $1`, aud).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != n {
			t.Errorf("%s: %d ceremonies left, want %d", aud, got, n)
		}
	}
}
