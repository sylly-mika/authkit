// Package throttle is authkit's per-login failure counter, auth_throttle
// (spec §8.9), keyed by the normalised login and the audience. authkit.Service
// calls it inside the caller's transaction; apps call the Service.
package throttle

import (
	"context"
	"errors"
	"time"

	"github.com/sylly-mika/authkit/db"
)

// Rules: Failures within Window lock the login for Lockout. When Lockout is
// shorter than Window, a lock that lapses inside its window re-arms on the
// next failure in it. The two switches are read by authkit's Login.
type Rules struct {
	Failures int
	Window   time.Duration
	Lockout  time.Duration
	// CountAfterVerify is v0.1's order: check the lock, verify, count a
	// failure. False (the default) counts every attempt before its verify.
	CountAfterVerify bool
	// PlainLoginKey keys auth_throttle on the normalised login, as v0.1 did.
	// False (the default) keys it on hex(sha256(normalised login)).
	PlainLoginKey bool
}

// Locked reports whether the login is locked at now, and until when.
func Locked(ctx context.Context, q db.Querier, login, aud string, now time.Time) (time.Time, bool, error) {
	var until *time.Time
	err := q.QueryRow(ctx, `SELECT locked_until FROM auth_throttle WHERE login = $1 AND audience = $2`, login, aud).Scan(&until)
	switch {
	case errors.Is(err, db.ErrNoRows):
		return time.Time{}, false, nil
	case err != nil:
		return time.Time{}, false, err
	case until == nil || !until.After(now):
		return time.Time{}, false, nil
	}
	return *until, true, nil
}

// Count counts one attempt before its verification (spec §3.2) and reports
// whether the login is now locked, and until when. Its upsert locks the
// login's row for the caller's transaction, so attempts on one login queue
// here. The attempt past r.Failures within the window starts a lockout; a
// running lockout is kept as it is; a lapsed one starts a fresh window.
func Count(ctx context.Context, q db.Querier, login, aud string, now time.Time, r Rules) (time.Time, bool, error) {
	if err := db.RequireTx(q); err != nil {
		return time.Time{}, false, err
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO auth_throttle AS t (login, audience, failures, window_start)
		VALUES ($1, $2, 1, $3)
		ON CONFLICT (login, audience) DO UPDATE SET
		    failures     = CASE WHEN t.locked_until > $3 THEN t.failures
		                        WHEN t.locked_until IS NOT NULL OR t.window_start <= $4 THEN 1
		                        ELSE t.failures + 1 END,
		    window_start = CASE WHEN t.locked_until > $3 THEN t.window_start
		                        WHEN t.locked_until IS NOT NULL OR t.window_start <= $4 THEN $3
		                        ELSE t.window_start END,
		    locked_until = CASE WHEN t.locked_until > $3 THEN t.locked_until
		                        WHEN t.locked_until IS NOT NULL OR t.window_start <= $4 THEN NULL
		                        WHEN t.failures + 1 > $5 THEN $6::timestamptz
		                        END`,
		login, aud, now, now.Add(-r.Window), r.Failures, now.Add(r.Lockout)); err != nil {
		return time.Time{}, false, err
	}
	return Locked(ctx, q, login, aud, now)
}

// Fail counts one failed verification. A window that has passed starts over;
// the failure that reaches the limit locks the login from now.
func Fail(ctx context.Context, q db.Querier, login, aud string, now time.Time, r Rules) error {
	if err := db.RequireTx(q); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `
		INSERT INTO auth_throttle AS t (login, audience, failures, window_start, locked_until)
		VALUES ($1, $2, 1, $3, CASE WHEN $4 <= 1 THEN $6::timestamptz END)
		ON CONFLICT (login, audience) DO UPDATE SET
		    failures     = CASE WHEN t.window_start <= $5 THEN 1 ELSE t.failures + 1 END,
		    window_start = CASE WHEN t.window_start <= $5 THEN $3 ELSE t.window_start END,
		    locked_until = CASE WHEN (CASE WHEN t.window_start <= $5 THEN 1 ELSE t.failures + 1 END) >= $4
		                        THEN $6::timestamptz ELSE t.locked_until END`,
		login, aud, now, r.Failures, now.Add(-r.Window), now.Add(r.Lockout))
	return err
}

// Clear drops the login's counter after a sign-in.
func Clear(ctx context.Context, q db.Querier, login, aud string) error {
	_, err := q.Exec(ctx, `DELETE FROM auth_throttle WHERE login = $1 AND audience = $2`, login, aud)
	return err
}

// Prune deletes counters whose window and lock have both passed at now.
func Prune(ctx context.Context, q db.Querier, now time.Time, r Rules) (int64, error) {
	return q.Exec(ctx, `DELETE FROM auth_throttle WHERE window_start <= $1 AND (locked_until IS NULL OR locked_until <= $2)`,
		now.Add(-r.Window), now)
}
