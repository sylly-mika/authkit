package authkit_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
)

// captured is every event OnEvent was handed, as "source/result".
type captured struct{ pairs []string }

func (c *captured) onEvent(_ context.Context, _ db.Querier, e authkit.Event) error {
	c.pairs = append(c.pairs, e.Source+"/"+e.Result)
	return nil
}

// TestEveryEventNamesItsSource is spec §3.7 over Bearer mode: each method's
// events reach OnEvent with its Source, the pairs lane B's mapping lists.
// The Source is not stored.
func TestEveryEventNamesItsSource(t *testing.T) {
	var c captured
	w := newWorld(t, defaults, func(cfg *authkit.Config) { cfg.OnEvent = c.onEvent })
	id := w.user("ada@example.invalid", "the old password")
	invited := authkit.Principal{ID: w.user("invited@example.invalid", ""), Login: "invited@example.invalid"}
	refused := w.user("refused@example.invalid", "the right password")
	w.p.Refuse(refused, errors.New("app: deactivated"))

	w.login("staff", "ada@example.invalid", "a wrong password")
	w.login("staff", "nobody@example.invalid", "a wrong password")
	w.login("staff", "invited@example.invalid", "a wrong password")
	w.login("staff", "refused@example.invalid", "the right password")
	for range 6 {
		w.login("staff", "locked@example.invalid", "a wrong password")
	}
	first := w.signIn("ada@example.invalid", "the old password")
	second := w.signIn("ada@example.invalid", "the old password")
	conn := w.pinned(id)
	w.inConn(conn, func(q db.Querier) (authkit.Result, error) {
		return w.svc.RevokeSession(w.ctx, q, w.claims(first), second.Session.ID, authkit.Meta{})
	})
	w.changePassword(conn, w.claims(first), "the old password", "the new password")
	w.logout(conn, w.claims(first))
	w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.SetPassword(w.ctx, q, invited, "staff", "a first password", authkit.Meta{})
	})
	w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.VerifyPassword(w.ctx, q, invited, "staff", "a wrong password", authkit.Meta{})
	})
	w.completeReset(w.mintLink(*w.requestReset("ada@example.invalid").TokenID), "the reset password")
	third := w.signIn("ada@example.invalid", "the reset password")
	w.refresh("staff", third.Tokens.RefreshToken)
	w.clock.Advance(31 * time.Second)
	w.refresh("staff", third.Tokens.RefreshToken)

	want := []string{
		"login/bad_password", "login/unknown_login", "login/no_password", "login/no_membership",
		"login/unknown_login", "login/unknown_login", "login/unknown_login", "login/unknown_login", "login/unknown_login", "login/locked",
		"login/signed_in", "login/signed_in", "revoke_session/revoked", "change_password/password_changed", "logout/signed_out",
		"set_password/password_set", "verify_password/bad_password", "complete_reset/password_reset",
		"login/signed_in", "refresh/reuse_detected",
	}
	if !slices.Equal(c.pairs, want) {
		t.Fatalf("OnEvent saw\n%v\nwant\n%v", c.pairs, want)
	}
	if w.count(`SELECT count(*) FROM auth_events`) != len(want) {
		t.Fatalf("auth_events holds %d rows, want one per OnEvent call", w.count(`SELECT count(*) FROM auth_events`))
	}
	list, _, err := w.svc.ListEvents(w.ctx, sqldb.Conn(conn), id, nil, 50, 0)
	if err != nil || len(list) == 0 || list[0].Source != "" {
		t.Fatalf("ListEvents = %+v (%v); want events without a Source: it is not stored", list, err)
	}
}

// TestOnEventRunsInTheCallersTransaction is spec §3.7: OnEvent sees its
// event on the method's own transaction, and its writes commit or roll back
// with authkit's.
func TestOnEventRunsInTheCallersTransaction(t *testing.T) {
	var seen []bool
	w := newWorld(t, defaults, func(c *authkit.Config) {
		c.OnEvent = func(ctx context.Context, q db.Querier, e authkit.Event) error {
			var n int
			if err := q.QueryRow(ctx, `SELECT count(*) FROM auth_events WHERE id = $1`, e.ID).Scan(&n); err != nil {
				return err
			}
			seen = append(seen, n == 1 && q.InTx())
			_, err := q.Exec(ctx, `INSERT INTO event_mirror (id, source, result) VALUES ($1, $2, $3)`, e.ID, e.Source, e.Result)
			return err
		}
	})
	w.d.Exec(t, `CREATE TABLE event_mirror (id uuid PRIMARY KEY, source text NOT NULL, result text NOT NULL)`)
	w.d.Exec(t, `GRANT SELECT, INSERT ON event_mirror TO authkit_app`)
	w.user("ada@example.invalid", "the right password")
	w.signIn("ada@example.invalid", "the right password")
	if !slices.Equal(seen, []bool{true}) || w.count(`SELECT count(*) FROM event_mirror WHERE source = 'login' AND result = 'signed_in'`) != 1 {
		t.Fatalf("OnEvent saw its event on the method's transaction: %v; want [true] and one mirror row", seen)
	}
	rollback := errors.New("the handler failed")
	err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
		if _, err := w.svc.Login(w.ctx, q, "staff", "ada@example.invalid", "the right password", authkit.Meta{}); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) || w.count(`SELECT count(*) FROM auth_events`) != 1 || w.count(`SELECT count(*) FROM event_mirror`) != 1 {
		t.Fatalf("a rolled-back sign-in (%v) left %d events and %d mirror rows, want 1 and 1", err,
			w.count(`SELECT count(*) FROM auth_events`), w.count(`SELECT count(*) FROM event_mirror`))
	}
}

// TestAnOnEventErrorFailsTheMethod: the host's mirror and authkit's event
// commit together or not at all, refusals included.
func TestAnOnEventErrorFailsTheMethod(t *testing.T) {
	down := errors.New("app: the mirror is down")
	w := newWorld(t, defaults, func(c *authkit.Config) {
		c.OnEvent = func(context.Context, db.Querier, authkit.Event) error { return down }
	})
	w.user("ada@example.invalid", "the right password")
	for _, pw := range []string{"the right password", "a wrong password"} {
		err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
			_, err := w.svc.Login(w.ctx, q, "staff", "ada@example.invalid", pw, authkit.Meta{})
			return err
		})
		if !errors.Is(err, down) {
			t.Fatalf("Login with %q = %v, want OnEvent's error", pw, err)
		}
	}
	if w.count(`SELECT count(*) FROM auth_events`)+w.count(`SELECT count(*) FROM auth_sessions`)+w.count(`SELECT count(*) FROM auth_throttle`) != 0 {
		t.Fatal("a failed method's writes survived its rollback")
	}
}

// TestChangePasswordLogsPasswordChanged is spec §3.6; ChangeLogsReset keeps
// v0.1's password_reset (P1's TestChangePasswordRevokesTheOtherSessions).
func TestChangePasswordLogsPasswordChanged(t *testing.T) {
	w := newWorld(t, defaults)
	id := w.user("ada@example.invalid", "the old password")
	keep := w.signIn("ada@example.invalid", "the old password")
	w.clock.Advance(time.Minute)
	if res := w.changePassword(w.pinned(id), w.claims(keep), "the old password", "the new password"); res.Refusal != nil {
		t.Fatalf("ChangePassword = %v", res.Refusal)
	}
	if got := w.results(id); !slices.Equal(got, []string{"signed_in", "password_changed"}) {
		t.Fatalf("log = %v, want signed_in, then password_changed", got)
	}
}
