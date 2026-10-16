package password

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// Login signs a principal in with its password. By
// default every attempt is counted before its verification: the hash slot
// first (from ctx, or taken here), so a Busy refusal counts nothing; then the
// login's throttle row, locked until the caller commits, is counted, and an
// attempt past the limit is refused ErrLocked without a verification. Then
// the lookup, exactly one verification, Admit, the session, the
// counter cleared and signed_in. Throttle.CountAfterVerify is v0.1's order:
// check the lock, verify, count a failure. Its refusals return normally after
// writing their throttle count and event. A principal holding a confirmed
// second factor gets Result.SecondStep instead of a session; VerifySecondStep
// completes the sign-in.
func (s *Module) Login(ctx context.Context, q db.Querier, aud authkit.Audience, login, pw string, m authkit.Meta) (authkit.Result, error) {
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
	c := s.core
	a, res, err := c.Begin(ctx, q, authkit.SourceLogin, aud, login, m)
	if err != nil || a == nil {
		return res, err
	}

	var p authkit.Principal
	err = authkit.ErrUnknownLogin
	if a.Counted() {
		p, err = s.principals.Lookup(ctx, q, a.Login(), aud)
	}
	known := err == nil
	if err != nil && !errors.Is(err, authkit.ErrUnknownLogin) {
		return authkit.Result{}, err
	}
	var hash string
	var hasCredential bool
	if known {
		a.SetPrincipal(&p)
		if hash, hasCredential, err = credentialOf(ctx, q, p.ID); err != nil {
			return authkit.Result{}, err
		}
	}
	ok, err := s.verify(ctx, hash, hasCredential, pw)
	if errors.Is(err, ErrBusy) {
		return authkit.Result{Refusal: ErrBusy}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		var result string
		switch {
		case !known:
			result = authkit.ResultUnknownLogin
		case !hasCredential:
			result = authkit.ResultNoPassword
		default:
			result = authkit.ResultBadPassword
		}
		return a.Refuse(ctx, q, result, authkit.ErrInvalidCredentials)
	}
	if s.hasher.NeedsRehash(hash) {
		a.Commit(func(ctx context.Context, q db.Querier) error { return s.rehash(ctx, q, p.ID, hash, pw) })
	}
	return c.SignIn(ctx, q, a, p, authkit.FactorPassword)
}

// WHY: every login spends one verification, against the dummy when there is no hash, so unknown logins take as long as known ones.
func (s *Module) verify(ctx context.Context, hash string, has bool, pw string) (bool, error) {
	if s.onVerify != nil {
		s.onVerify()
	}
	if !has {
		return false, s.hasher.VerifyDummy(ctx, pw)
	}
	return s.hasher.Verify(ctx, hash, pw)
}

// WHY: the rehash is skipped unless the stored hash is still the one Login read, so a change committed since the read wins.
func (s *Module) rehash(ctx context.Context, q db.Querier, id uuid.UUID, old, pw string) error {
	hash, err := s.hasher.Hash(ctx, pw)
	if errors.Is(err, ErrBusy) {
		return nil
	}
	if err != nil {
		return err
	}
	return rehashCredential(ctx, q, id, old, hash)
}
