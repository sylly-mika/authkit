package authkit

import (
	"context"
	"errors"
	"time"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/events"
	"github.com/sylly-mika/authkit/session"
	"github.com/sylly-mika/authkit/transport/bearer"
)

const touchEvery = time.Minute

// Authenticate is Guard's check of one request (spec §7 Guard, §8.5), on the
// querier the app binds for the request; a bare pinned connection is fine. A
// missing, revoked or expired session is ErrSessionEnded. An Admit refusal,
// or claims that differ from what Admit grants now, is ErrStale. It stamps
// last_seen_at at most once a minute.
func (s *Service) Authenticate(ctx context.Context, q db.Querier, c *Claims) (Result, error) {
	now := s.now()
	sess, err := session.Load(ctx, q, c.SessionID, c.Subject)
	if errors.Is(err, db.ErrNoRows) {
		return Result{Refusal: ErrSessionEnded}, nil
	}
	if err != nil {
		return Result{}, err
	}
	if sess.RevokedAt != nil || !sess.ExpiresAt.After(now) || sess.Audience != c.Audience {
		return Result{Refusal: ErrSessionEnded}, nil
	}
	p := Principal{ID: c.Subject}
	adm, refusal, err := s.admit(ctx, q, Proposal{Principal: p, Audience: Audience(c.Audience), ScopeID: sess.ScopeID})
	if err != nil {
		return Result{}, err
	}
	if refusal != nil {
		return Result{Refusal: ErrStale}, nil
	}
	same, err := bearer.SameClaims(adm.Claims, c.App)
	if err != nil {
		return Result{}, err
	}
	if !same {
		return Result{Refusal: ErrStale}, nil
	}
	if sess.LastSeenAt == nil || now.Sub(*sess.LastSeenAt) >= touchEvery {
		if err := session.Touch(ctx, q, sess.ID, now, now.Add(-touchEvery)); err != nil {
			return Result{}, err
		}
	}
	return Result{Principal: p, Session: &sess, Admission: &adm}, nil
}

// Logout ends the session the token names (spec §7 Logout) and logs
// signed_out. A session already revoked or expired is left alone and logs
// nothing, so a repeated logout succeeds.
func (s *Service) Logout(ctx context.Context, q db.Querier, c *Claims, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	m = m.clean()
	now := s.now()
	sess, err := session.LockOpen(ctx, q, c.SessionID, c.Subject, now)
	if errors.Is(err, db.ErrNoRows) {
		return Result{}, nil
	}
	if err != nil {
		return Result{}, err
	}
	if err := session.Revoke(ctx, q, sess.ID, ReasonLogout, now); err != nil {
		return Result{}, err
	}
	return Result{Session: &sess}, s.record(ctx, q, now, SourceLogout, events.Event{PrincipalID: &sess.PrincipalID, SessionID: &sess.ID,
		ScopeID: sess.ScopeID, Audience: sess.Audience, Result: ResultSignedOut, IP: m.IP, UserAgent: m.UserAgent})
}
