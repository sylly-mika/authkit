package authkit

import (
	"context"
	"errors"
	"time"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/events"
	"github.com/sylly-mika/authkit/internal/token"
	"github.com/sylly-mika/authkit/session"
)

// Refresh rotates a refresh token. It locks the open
// session of aud that carries the token, asks Admit with the session's scope
// and only then writes: a refusal leaves the token valid. The pair is minted
// with the claims Admit grants now. Bearer mode only.
func (s *Service) Refresh(ctx context.Context, q db.Querier, aud Audience, raw string, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if s.cfg.Transport != TransportBearer {
		return Result{}, errors.New("authkit: Refresh needs Config.Transport TransportBearer")
	}
	m = m.clean()
	now := s.now()
	old := token.Hash(raw)
	sess, err := session.LockForRefresh(ctx, q, old, string(aud), now)
	if errors.Is(err, db.ErrNoRows) {
		return s.reuseOrEnded(ctx, q, old, now, m)
	}
	if err != nil {
		return Result{}, err
	}
	p := Principal{ID: sess.PrincipalID}
	adm, refusal, err := s.admit(ctx, q, Proposal{Principal: p, Audience: aud, ScopeID: sess.ScopeID, SecondFactor: FactorKind(sess.SecondFactor), Source: SourceRefresh})
	if err != nil {
		return Result{}, err
	}
	if refusal != nil {
		return Result{Refusal: refusal.Err}, nil
	}
	next, nextHash, err := token.New(s.cfg.Rand)
	if err != nil {
		return Result{}, err
	}
	sess.ExpiresAt, sess.RotatedAt = s.expiry(now, aud, sess.AbsoluteExpiresAt), &now
	if err := session.Rotate(ctx, q, sess.ID, old, nextHash, now, sess.ExpiresAt); err != nil {
		return Result{}, err
	}
	access, exp, err := s.codec.MintAt(now, sess.PrincipalID, sess.ID, string(aud), adm.Claims)
	if err != nil {
		return Result{}, err
	}
	return Result{Principal: p, Session: &sess, Tokens: &TokenPair{AccessToken: access, RefreshToken: next, ExpiresAt: exp}, Admission: &adm}, nil
}

// WHY: a token rotated away within ReuseGrace may be the loser of a concurrent refresh, so it is refused without revoking the session.
func (s *Service) reuseOrEnded(ctx context.Context, q db.Querier, old []byte, now time.Time, m Meta) (Result, error) {
	prev, err := session.LockByPrevious(ctx, q, old)
	if errors.Is(err, db.ErrNoRows) {
		return Result{Refusal: ErrSessionEnded}, nil
	}
	if err != nil {
		return Result{}, err
	}
	if prev.RotatedAt == nil || now.Sub(*prev.RotatedAt) <= s.cfg.ReuseGrace {
		return Result{Refusal: ErrSessionEnded}, nil
	}
	if err := session.Revoke(ctx, q, prev.ID, ReasonReuseDetected, now); err != nil {
		return Result{}, err
	}
	if err := s.record(ctx, q, now, SourceRefresh, events.Event{PrincipalID: &prev.PrincipalID, SessionID: &prev.ID, ScopeID: prev.ScopeID,
		Audience: prev.Audience, Result: ResultReuseDetected, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return Result{}, err
	}
	return Result{Refusal: ErrSessionEnded}, nil
}
