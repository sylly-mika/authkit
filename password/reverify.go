package password

import (
	"context"
	"errors"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// Reverify checks the signed-in principal's password and marks the session as just authenticated.
func (s *Module) Reverify(ctx context.Context, q db.Querier, c *authkit.Claims, pw string, m authkit.Meta) (authkit.Result, error) {
	q = s.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	m = m.Clean()
	if !s.core.Config().Throttle.CountAfterVerify {
		held, release, err := s.hasher.Hold(ctx)
		if errors.Is(err, ErrBusy) {
			return authkit.Result{Refusal: ErrBusy}, nil
		}
		if err != nil {
			return authkit.Result{}, err
		}
		defer release()
		ctx = held
	}
	sess, err := s.core.LockSession(ctx, q, c, s.now())
	if errors.Is(err, db.ErrNoRows) {
		return authkit.Result{Refusal: authkit.ErrSessionEnded}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	aud := authkit.Audience(sess.Audience)
	p, err := s.principals.ByID(ctx, q, c.Subject, aud)
	if err != nil {
		return authkit.Result{}, err
	}
	a, res, err := s.core.Begin(ctx, q, authkit.SourceReverify, aud, p.Login, m)
	if err != nil || a == nil {
		return res, err
	}
	a.SetPrincipal(&p)
	hash, has, err := credentialOf(ctx, q, p.ID)
	if err != nil {
		return authkit.Result{}, err
	}
	ok, err := s.verify(ctx, hash, has, pw)
	if errors.Is(err, ErrBusy) {
		return authkit.Result{Refusal: ErrBusy}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		result := authkit.ResultBadPassword
		if !has {
			result = authkit.ResultNoPassword
		}
		return a.Refuse(ctx, q, result, authkit.ErrInvalidCredentials)
	}
	if a.Counted() {
		if err := s.core.Throttle(p.Login, aud, a.Now()).Clear(ctx, q); err != nil {
			return authkit.Result{}, err
		}
	}
	if err := s.core.MarkAuthenticated(ctx, q, sess.ID, a.Now()); err != nil {
		return authkit.Result{}, err
	}
	if err := s.core.Record(ctx, q, authkit.SourceReverify, authkit.Event{At: a.Now(), PrincipalID: &p.ID, SessionID: &sess.ID, ScopeID: sess.ScopeID, Audience: sess.Audience, Login: p.Login, Result: authkit.ResultReverified, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{Principal: p}, nil
}
