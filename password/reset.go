package password

import (
	"context"
	"errors"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/events"
)

const (
	resetCap       = 3
	resetCapWindow = time.Hour
)

// RequestReset creates a reset link for a known login; the app enqueues its
// email with Result.TokenID in the same
// transaction. An unknown or capped login, or one without a credential unless
// Reset.MayCreateCredential, writes nothing and has no TokenID.
// The app's handler answers alike either way and pads with PadSince after
// its transaction commits.
func (s *Module) RequestReset(ctx context.Context, q db.Querier, aud authkit.Audience, login string) (authkit.Result, error) {
	q = s.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	p, err := s.principals.Lookup(ctx, q, authkit.Normalize(login), aud)
	if errors.Is(err, authkit.ErrUnknownLogin) {
		return authkit.Result{}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	if !s.cfg.Reset.MayCreateCredential {
		_, has, err := credentialOf(ctx, q, p.ID)
		if err != nil {
			return authkit.Result{}, err
		}
		if !has {
			return authkit.Result{Principal: p}, nil
		}
	}
	if err := s.links.Lock(ctx, q, authkit.PurposeReset, p.ID); err != nil {
		return authkit.Result{}, err
	}
	n, err := s.links.CreatedSince(ctx, q, authkit.PurposeReset, p.ID, s.now().Add(-resetCapWindow))
	if err != nil {
		return authkit.Result{}, err
	}
	if n >= resetCap {
		return authkit.Result{Principal: p}, nil
	}
	id, err := s.links.Create(ctx, q, authkit.PurposeReset, p.ID, s.cfg.ResetTTL)
	if err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{Principal: p, TokenID: &id}, nil
}

// CompleteReset spends a reset link and sets the password it was sent for
// the policy first, then the spend. A
// principal without a credential is refused as an unknown link unless
// Reset.MayCreateCredential. Session mode then asks Admit: a refusal keeps
// the spend and logs its result, nothing more. Then the credential, every
// session revoked (password_reset), the login's throttle cleared, and
// password_set or password_reset logged. Session mode then signs the
// principal in (Result.SessionToken); Bearer mode signs nobody in. A
// principal holding a confirmed second factor gets Result.SecondStep in both
// transports instead of a session; the factors and recovery codes stay.
// It also deletes every passkey of the principal, reports the count in
// Result.PasskeysRemoved and logs passkeys_reset when there were any.
func (s *Module) CompleteReset(ctx context.Context, q db.Querier, aud authkit.Audience, raw, pw string, m authkit.Meta) (authkit.Result, error) {
	q = s.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	m = m.Clean()
	if err := s.cfg.Password.Check(pw); err != nil {
		return authkit.Result{Refusal: err}, nil
	}
	hash, err := s.hasher.Hash(ctx, pw)
	if errors.Is(err, ErrBusy) {
		return authkit.Result{Refusal: ErrBusy}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	tok, err := s.links.Spend(ctx, q, raw, authkit.PurposeReset)
	var gone authkit.ErrTokenGone
	switch {
	case errors.Is(err, authkit.ErrTokenUnknown):
		return authkit.Result{Refusal: authkit.ErrTokenUnknown}, nil
	case errors.As(err, &gone):
		return authkit.Result{Refusal: gone}, nil
	case err != nil:
		return authkit.Result{}, err
	}
	p, err := s.principals.ByID(ctx, q, tok.Owner, aud)
	if errors.Is(err, authkit.ErrUnknownLogin) {
		return authkit.Result{Refusal: authkit.ErrTokenUnknown}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	a := s.core.BeginVerified(authkit.SourceCompleteReset, aud, m)
	a.SetPrincipal(&p)
	now := a.Now()
	_, had, err := credentialOf(ctx, q, p.ID)
	if err != nil {
		return authkit.Result{}, err
	}
	if !had && !s.cfg.Reset.MayCreateCredential {
		return authkit.Result{Refusal: authkit.ErrTokenUnknown}, nil
	}
	var removed int
	a.Commit(func(ctx context.Context, q db.Querier) error {
		if err := setCredential(ctx, q, p.ID, hash, now); err != nil {
			return err
		}
		if err := s.core.RevokeAll(ctx, q, p.ID, authkit.ReasonPasswordReset, now); err != nil {
			return err
		}
		n, err := s.core.ResetCredentials(ctx, q, p, aud)
		if err != nil {
			return err
		}
		removed = n
		result := authkit.ResultPasswordSet
		if had {
			result = authkit.ResultPasswordReset
		}
		if err := s.record(ctx, q, now, authkit.SourceCompleteReset, events.Event{PrincipalID: &p.ID, Audience: string(aud), Login: p.Login,
			Result: result, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
			return err
		}
		if removed > 0 {
			if err := s.record(ctx, q, now, authkit.SourceCompleteReset, events.Event{PrincipalID: &p.ID, Audience: string(aud), Login: p.Login,
				Result: authkit.ResultPasskeysReset, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
				return err
			}
		}
		return nil
	})
	res, err := s.core.SignIn(ctx, q, a, p, authkit.FactorPassword)
	if err != nil || res.Refusal != nil {
		return res, err
	}
	res.PasskeysRemoved = removed
	return res, nil
}
