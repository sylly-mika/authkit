package secondfactor

import (
	"context"
	"errors"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/factor"
)

// Reverify checks a TOTP code of the signed-in principal and marks the session as just authenticated.
func (s *Module) Reverify(ctx context.Context, q db.Querier, c *authkit.Claims, code string, m authkit.Meta) (authkit.Result, error) {
	q = s.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	if len(s.r.Key) == 0 {
		return authkit.Result{Refusal: authkit.ErrSecondFactorsOff}, nil
	}
	m = m.Clean()
	now := s.core.Now()
	if err := factor.Lock(ctx, q, c.Subject); err != nil {
		return authkit.Result{}, err
	}
	sess, err := s.core.LockSession(ctx, q, c, now)
	if errors.Is(err, db.ErrNoRows) {
		return authkit.Result{Refusal: authkit.ErrSessionEnded}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	aud := authkit.Audience(sess.Audience)
	p, err := s.core.Principals().ByID(ctx, q, c.Subject, aud)
	if err != nil {
		return authkit.Result{}, err
	}
	lt := s.core.Throttle(p.Login, aud, now)
	until, locked, err := lt.Locked(ctx, q)
	if err != nil {
		return authkit.Result{}, err
	}
	event := authkit.Event{At: now, PrincipalID: &p.ID, SessionID: &sess.ID, ScopeID: sess.ScopeID, Audience: sess.Audience, Login: p.Login, SecondFactor: string(authkit.FactorTOTP), IP: m.IP, UserAgent: m.UserAgent}
	if locked {
		event.Result = authkit.ResultLocked
		if err := s.core.Record(ctx, q, authkit.SourceReverify, event); err != nil {
			return authkit.Result{}, err
		}
		return authkit.Result{Refusal: authkit.ErrLocked{RetryAfter: until.Sub(now)}}, nil
	}
	ok, err := s.checkFactor(ctx, q, c.Subject, authkit.FactorTOTP, code, now)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		if err := lt.Fail(ctx, q); err != nil {
			return authkit.Result{}, err
		}
		event.Result = authkit.ResultBadCode
		if err := s.core.Record(ctx, q, authkit.SourceReverify, event); err != nil {
			return authkit.Result{}, err
		}
		return authkit.Result{Refusal: authkit.ErrBadCode}, nil
	}
	if err := s.core.MarkAuthenticated(ctx, q, sess.ID, now); err != nil {
		return authkit.Result{}, err
	}
	event.Result = authkit.ResultReverified
	if err := s.core.Record(ctx, q, authkit.SourceReverify, event); err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{Principal: p}, nil
}
