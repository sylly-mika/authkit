package tests

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/internal/kittest"
)

type captured struct{ pairs []string }

func (c *captured) onEvent(_ context.Context, _ db.Querier, e authkit.Event) error {
	c.pairs = append(c.pairs, e.Source+"/"+e.Result)
	return nil
}

func TestEveryEventNamesItsSource(t *testing.T) {
	var c captured
	w := newWorld(t, kittest.DefaultRules, func(cfg *kittest.Rules) { cfg.OnEvent = c.onEvent })
	id := w.User("ada@example.invalid", "the old password")
	invited := authkit.Principal{ID: w.User("invited@example.invalid", ""), Login: "invited@example.invalid"}
	refused := w.User("refused@example.invalid", "the right password")
	w.P.Refuse(refused, errors.New("app: deactivated"))

	w.Login("staff", "ada@example.invalid", "a wrong password")
	w.Login("staff", "nobody@example.invalid", "a wrong password")
	w.Login("staff", "invited@example.invalid", "a wrong password")
	w.Login("staff", "refused@example.invalid", "the right password")
	for range 6 {
		w.Login("staff", "locked@example.invalid", "a wrong password")
	}
	first := w.SignIn("ada@example.invalid", "the old password")
	second := w.SignIn("ada@example.invalid", "the old password")
	conn := w.Pinned(id)
	w.InConn(conn, func(q db.Querier) (authkit.Result, error) {
		return w.Svc.RevokeSession(w.Ctx, q, w.Claims(first), second.Session.ID, authkit.Meta{})
	})
	w.changePassword(conn, w.Claims(first), "the old password", "the new password")
	w.logout(conn, w.Claims(first))
	w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Password.SetPassword(w.Ctx, q, invited, "staff", "a first password", authkit.Meta{})
	})
	w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Password.VerifyPassword(w.Ctx, q, invited, "staff", "a wrong password", authkit.Meta{})
	})
	w.completeReset(w.mintLink(*w.requestReset("ada@example.invalid").TokenID), "the reset password")
	third := w.SignIn("ada@example.invalid", "the reset password")
	w.refresh("staff", third.Tokens.RefreshToken)
	w.Clock.Advance(31 * time.Second)
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
	if w.Count(`SELECT count(*) FROM auth_events`) != len(want) {
		t.Fatalf("auth_events holds %d rows, want one per OnEvent call", w.Count(`SELECT count(*) FROM auth_events`))
	}
	rows, err := w.D.Owner.Query(`SELECT source || '/' || result FROM auth_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var stored []string
	for rows.Next() {
		var pair string
		if err := rows.Scan(&pair); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, pair)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(stored)
	wantSorted := slices.Clone(want)
	slices.Sort(wantSorted)
	if !slices.Equal(stored, wantSorted) {
		t.Fatalf("auth_events stores source/result\n%v\nwant\n%v", stored, wantSorted)
	}
	list, _, err := w.Svc.ListEvents(w.Ctx, sqldb.Conn(conn), id, nil, 50, 0)
	if err != nil || len(list) == 0 || list[0].Source != "refresh" || list[0].Result != "reuse_detected" {
		t.Fatalf("ListEvents = %+v (%v); want the newest event to read Source refresh", list, err)
	}
	for _, e := range list {
		if e.Source == "" {
			t.Fatalf("ListEvents returned an event without a Source: %+v", e)
		}
	}
}

func TestListEventsReadsTheStoredSource(t *testing.T) {
	w := newWorld(t, kittest.DefaultRules)
	id := w.User("ada@example.invalid", "the old password")
	t0 := w.Clock.Now()
	w.SignIn("ada@example.invalid", "the old password")
	w.D.Exec(t, "INSERT INTO auth_events (id, at, principal_id, audience, result) VALUES ($1, $2, $3, 'staff', 'signed_in')", uuid.New(), t0.Add(-time.Hour), id)
	list, total, err := w.Svc.ListEvents(w.Ctx, sqldb.Conn(w.Pinned(id)), id, nil, 50, 0)
	if err != nil || total != 2 || len(list) != 2 {
		t.Fatalf("ListEvents = %d events, total %d (%v); want 2 and 2", len(list), total, err)
	}
	if list[0].Source != "login" || list[1].Source != "" {
		t.Fatalf("ListEvents sources = %q, %q; want \"login\" for the sign-in and \"\" for the row written before 0003", list[0].Source, list[1].Source)
	}
}

func TestOnEventRunsInTheCallersTransaction(t *testing.T) {
	var seen []bool
	w := newWorld(t, kittest.DefaultRules, func(c *kittest.Rules) {
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
	w.D.Exec(t, `CREATE TABLE event_mirror (id uuid PRIMARY KEY, source text NOT NULL, result text NOT NULL)`)
	w.D.Exec(t, `GRANT SELECT, INSERT ON event_mirror TO authkit_app`)
	w.User("ada@example.invalid", "the right password")
	w.SignIn("ada@example.invalid", "the right password")
	if !slices.Equal(seen, []bool{true}) || w.Count(`SELECT count(*) FROM event_mirror WHERE source = 'login' AND result = 'signed_in'`) != 1 {
		t.Fatalf("OnEvent saw its event on the method's transaction: %v; want [true] and one mirror row", seen)
	}
	rollback := errors.New("the handler failed")
	err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		if _, err := w.Svc.Password.Login(w.Ctx, q, "staff", "ada@example.invalid", "the right password", authkit.Meta{}); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) || w.Count(`SELECT count(*) FROM auth_events`) != 1 || w.Count(`SELECT count(*) FROM event_mirror`) != 1 {
		t.Fatalf("a rolled-back sign-in (%v) left %d events and %d mirror rows, want 1 and 1", err,
			w.Count(`SELECT count(*) FROM auth_events`), w.Count(`SELECT count(*) FROM event_mirror`))
	}
}

func TestAnOnEventErrorFailsTheMethod(t *testing.T) {
	down := errors.New("app: the mirror is down")
	w := newWorld(t, kittest.DefaultRules, func(c *kittest.Rules) {
		c.OnEvent = func(context.Context, db.Querier, authkit.Event) error { return down }
	})
	w.User("ada@example.invalid", "the right password")
	for _, pw := range []string{"the right password", "a wrong password"} {
		err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
			_, err := w.Svc.Password.Login(w.Ctx, q, "staff", "ada@example.invalid", pw, authkit.Meta{})
			return err
		})
		if !errors.Is(err, down) {
			t.Fatalf("Login with %q = %v, want OnEvent's error", pw, err)
		}
	}
	if w.Count(`SELECT count(*) FROM auth_events`)+w.Count(`SELECT count(*) FROM auth_sessions`)+w.Count(`SELECT count(*) FROM auth_throttle`) != 0 {
		t.Fatal("a failed method's writes survived its rollback")
	}
}

func TestChangePasswordLogsPasswordChanged(t *testing.T) {
	w := newWorld(t, kittest.DefaultRules)
	id := w.User("ada@example.invalid", "the old password")
	keep := w.SignIn("ada@example.invalid", "the old password")
	w.Clock.Advance(time.Minute)
	if res := w.changePassword(w.Pinned(id), w.Claims(keep), "the old password", "the new password"); res.Refusal != nil {
		t.Fatalf("ChangePassword = %v", res.Refusal)
	}
	if got := w.Results(id); !slices.Equal(got, []string{"signed_in", "password_changed"}) {
		t.Fatalf("log = %v, want signed_in, then password_changed", got)
	}
}
