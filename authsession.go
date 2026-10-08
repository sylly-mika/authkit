package authkit

import (
	"context"
	"errors"
	"time"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/events"
	"github.com/sylly-mika/authkit/internal/token"
	"github.com/sylly-mika/authkit/session"
)

// AuthenticateSession is Session mode's check of one request (spec §3.5); it
// needs a transaction. The current token of an open session of aud whose
// principal Admit still admits is accepted: last_seen_at and the idle expiry
// slide at most once a minute, and a token older than RotateEvery is swapped
// for a new one, returned in Result.SessionToken. The token a session rotated
// away within ReuseGrace is accepted for this request alone (no slide, no
// rotation, nothing written). Every refusal is ErrSessionEnded; a previous
// token past the grace first revokes its session (reuse_detected) and logs
// it, for the caller to commit. The Result carries Principal (ID only),
// Session and Admission.
func (s *Service) AuthenticateSession(ctx context.Context, q db.Querier, aud Audience, raw string, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if s.cfg.Transport != TransportSession {
		return Result{}, errors.New("authkit: AuthenticateSession needs Config.Transport TransportSession")
	}
	m = m.clean()
	now := s.now()
	hash := token.Hash(raw)
	sess, err := session.ByToken(ctx, q, hash, string(aud))
	if errors.Is(err, db.ErrNoRows) {
		return s.previousToken(ctx, q, aud, hash, m, now)
	}
	if err != nil {
		return Result{}, err
	}
	res, err := s.admitSession(ctx, q, sess, now)
	if err != nil || res.Refusal != nil {
		return res, err
	}
	return s.keepAlive(ctx, q, res, hash, now)
}

// previousToken answers a token that is no session's current one (spec §3.5
// rules 2 and 3). The token a session rotated away within ReuseGrace comes
// from a request that started before the rotation: admitted for this request
// alone, nothing written. One rotated away earlier is a replay: the session
// is revoked and the event logged, for the caller to commit. Only the
// immediately previous token is recognised.
func (s *Service) previousToken(ctx context.Context, q db.Querier, aud Audience, hash []byte, m Meta, now time.Time) (Result, error) {
	prev, err := session.LockByPrevious(ctx, q, hash)
	if errors.Is(err, db.ErrNoRows) {
		return Result{Refusal: ErrSessionEnded}, nil
	}
	if err != nil {
		return Result{}, err
	}
	if prev.RotatedAt == nil || now.Sub(*prev.RotatedAt) <= s.cfg.ReuseGrace {
		if prev.Audience != string(aud) {
			return Result{Refusal: ErrSessionEnded}, nil
		}
		return s.admitSession(ctx, q, prev, now)
	}
	if err := session.Revoke(ctx, q, prev.ID, ReasonReuseDetected, now); err != nil {
		return Result{}, err
	}
	if err := s.record(ctx, q, now, SourceAuthenticateSession, events.Event{PrincipalID: &prev.PrincipalID, SessionID: &prev.ID,
		ScopeID: prev.ScopeID, Audience: prev.Audience, Result: ResultReuseDetected, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return Result{}, err
	}
	return Result{Refusal: ErrSessionEnded}, nil
}

// admitSession refuses a revoked or expired session and one whose principal
// Admit no longer admits (spec §3.5 rules 4 and 5): cookie mode has no
// refresh-and-retry, so each is ErrSessionEnded.
func (s *Service) admitSession(ctx context.Context, q db.Querier, sess Session, now time.Time) (Result, error) {
	if sess.RevokedAt != nil || !sess.ExpiresAt.After(now) {
		return Result{Refusal: ErrSessionEnded}, nil
	}
	p := Principal{ID: sess.PrincipalID}
	adm, refusal, err := s.admit(ctx, q, Proposal{Principal: p, Audience: Audience(sess.Audience), ScopeID: sess.ScopeID})
	if err != nil {
		return Result{}, err
	}
	if refusal != nil {
		return Result{Refusal: ErrSessionEnded}, nil
	}
	return Result{Principal: p, Session: &sess, Admission: &adm}, nil
}

// keepAlive rotates a token older than RotateEvery by compare-and-swap,
// sliding with it, or else slides the idle expiry and stamps last_seen_at at
// most once a minute (spec §3.5 rules 6 and 7). A request that loses the
// swap to a concurrent one keeps its token for this request, as rule 2 does.
func (s *Service) keepAlive(ctx context.Context, q db.Querier, res Result, hash []byte, now time.Time) (Result, error) {
	sess := res.Session
	born := sess.CreatedAt
	if sess.RotatedAt != nil {
		born = *sess.RotatedAt
	}
	exp := s.expiry(now, Audience(sess.Audience), sess.AbsoluteExpiresAt)
	if every := s.cfg.Session.RotateEvery; every > 0 && now.Sub(born) >= every {
		next, nextHash, err := token.New(s.cfg.Rand)
		if err != nil {
			return Result{}, err
		}
		swapped, err := session.Swap(ctx, q, sess.ID, hash, nextHash, now, exp)
		if err != nil {
			return Result{}, err
		}
		if swapped {
			sess.RotatedAt, sess.LastSeenAt, sess.ExpiresAt = &now, &now, exp
			res.SessionToken = next
		}
		return res, nil
	}
	if sess.LastSeenAt == nil || now.Sub(*sess.LastSeenAt) >= touchEvery {
		if err := session.Slide(ctx, q, sess.ID, now, now.Add(-touchEvery), exp); err != nil {
			return Result{}, err
		}
		sess.LastSeenAt, sess.ExpiresAt = &now, exp
	}
	return res, nil
}
