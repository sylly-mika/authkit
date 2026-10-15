package authkit

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/throttle"
	"github.com/sylly-mika/authkit/session"
)

// Core is a module's handle on the Service: sessions, the login throttle, Admit and the sign-in log. Its API is unstable until v1.0.0.
type Core struct {
	s    *Service
	name string
}

// Config returns the Service's Config, with the defaults applied.
func (c *Core) Config() Config { return c.s.cfg }

// Now returns the Service's clock reading.
func (c *Core) Now() time.Time { return c.s.now() }

// Rand returns the randomness source the Service draws from.
func (c *Core) Rand() io.Reader { return c.s.cfg.Rand }

// Principals returns the app's Principals the Service was built with.
func (c *Core) Principals() Principals { return c.s.principals }

// Fresh returns the caller's open session and whether it authenticated within window.
func (c *Core) Fresh(ctx context.Context, q db.Querier, cl *Claims, window time.Duration, now time.Time) (Session, bool, error) {
	sess, err := session.LockOpen(ctx, q, cl.SessionID, cl.Subject, now)
	if errors.Is(err, db.ErrNoRows) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}
	if now.Sub(sess.AuthenticatedAt) > window {
		return Session{}, false, nil
	}
	return sess, true, nil
}

// LockSession locks the caller's open session for the transaction and returns it; an ended session is db.ErrNoRows.
func (c *Core) LockSession(ctx context.Context, q db.Querier, cl *Claims, now time.Time) (Session, error) {
	return session.LockOpen(ctx, q, cl.SessionID, cl.Subject, now)
}

// MarkAuthenticated stamps sess as authenticated now.
func (c *Core) MarkAuthenticated(ctx context.Context, q db.Querier, sess uuid.UUID, now time.Time) error {
	return session.SetAuthenticated(ctx, q, sess, now)
}

// RevokeAll ends every session of principal, recording reason.
func (c *Core) RevokeAll(ctx context.Context, q db.Querier, principal uuid.UUID, reason string, now time.Time) error {
	return session.RevokeAll(ctx, q, principal, reason, now)
}

// RevokeOthers ends every session of principal except keep, recording reason.
func (c *Core) RevokeOthers(ctx context.Context, q db.Querier, principal, keep uuid.UUID, reason string, now time.Time) error {
	return session.RevokeOthers(ctx, q, principal, keep, reason, now)
}

// ResetCredentials deletes every passkey of p and clears its login throttle under aud, and returns how many passkeys it deleted.
func (c *Core) ResetCredentials(ctx context.Context, q db.Querier, p Principal, aud Audience) (passkeys int, err error) {
	passkeys, err = deleteAllPasskeys(ctx, q, p.ID)
	if err != nil {
		return 0, err
	}
	if err = throttle.Clear(ctx, q, c.s.throttleKey(Normalize(p.Login)), string(aud)); err != nil {
		return 0, err
	}
	return passkeys, nil
}

// Record writes a sign-in log row for src and runs OnEvent on q. A zero e.At takes the Service's clock.
func (c *Core) Record(ctx context.Context, q db.Querier, src string, e Event) error {
	at := e.At
	if at.IsZero() {
		at = c.s.now()
	}
	return c.s.record(ctx, q, at, src, e)
}

// Throttle returns the login throttle for login under aud, as of now.
func (c *Core) Throttle(login string, aud Audience, now time.Time) LoginThrottle {
	return LoginThrottle{s: c.s, key: c.s.throttleKey(Normalize(login)), aud: string(aud), now: now}
}

// MarkSessionFactor records f as the second factor of sess, if sess has none.
func (c *Core) MarkSessionFactor(ctx context.Context, q db.Querier, sess uuid.UUID, f FactorKind) error {
	return c.s.markSessionFactor(ctx, q, sess, f)
}

// LoginThrottle is one login's throttle under one audience, as of one instant.
type LoginThrottle struct {
	s        *Service
	key, aud string
	now      time.Time
}

// Locked reports whether the login is locked, and until when.
func (t LoginThrottle) Locked(ctx context.Context, q db.Querier) (until time.Time, locked bool, err error) {
	return throttle.Locked(ctx, q, t.key, t.aud, t.now)
}

// Fail counts one failed attempt against the login.
func (t LoginThrottle) Fail(ctx context.Context, q db.Querier) error {
	return throttle.Fail(ctx, q, t.key, t.aud, t.now, t.s.cfg.Throttle)
}

// Clear forgets the failed attempts counted against the login.
func (t LoginThrottle) Clear(ctx context.Context, q db.Querier) error {
	return throttle.Clear(ctx, q, t.key, t.aud)
}
