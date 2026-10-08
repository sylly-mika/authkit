package authkit

import (
	"context"
	"errors"
	"time"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/events"
	"github.com/sylly-mika/authkit/session"
	"github.com/sylly-mika/authkit/throttle"
)

const (
	resetCap       = 3
	resetCapWindow = time.Hour
)

// RequestReset creates a reset link for a known login (spec §7 Request
// reset); the app enqueues its email with Result.TokenID in the same
// transaction. An unknown or capped login writes nothing and has no TokenID.
// The app's handler answers alike either way and pads with PadSince after
// its transaction commits.
func (s *Service) RequestReset(ctx context.Context, q db.Querier, aud Audience, login string) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	p, err := s.principals.Lookup(ctx, q, Normalize(login), aud)
	if errors.Is(err, ErrUnknownLogin) {
		return Result{}, nil
	}
	if err != nil {
		return Result{}, err
	}
	if err := s.links.Lock(ctx, q, PurposeReset, p.ID); err != nil {
		return Result{}, err
	}
	n, err := s.links.CreatedSince(ctx, q, PurposeReset, p.ID, s.now().Add(-resetCapWindow))
	if err != nil {
		return Result{}, err
	}
	if n >= resetCap {
		return Result{Principal: p}, nil
	}
	id, err := s.links.Create(ctx, q, PurposeReset, p.ID, s.cfg.ResetTTL)
	if err != nil {
		return Result{}, err
	}
	return Result{Principal: p, TokenID: &id}, nil
}

// CompleteReset spends a reset link and sets the password it was sent for
// (spec §7 Complete reset): the policy first, then the spend, then the
// credential, every session revoked (password_reset), the login's throttle
// cleared, and password_set or password_reset logged. Nobody is signed in.
func (s *Service) CompleteReset(ctx context.Context, q db.Querier, aud Audience, raw, pw string, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	m = m.clean()
	if err := s.cfg.Password.Check(pw); err != nil {
		return Result{Refusal: err}, nil
	}
	hash, err := s.hasher.Hash(ctx, pw)
	if errors.Is(err, ErrBusy) {
		return Result{Refusal: ErrBusy}, nil
	}
	if err != nil {
		return Result{}, err
	}
	tok, err := s.links.Spend(ctx, q, raw, PurposeReset)
	var gone ErrTokenGone
	switch {
	case errors.Is(err, ErrTokenUnknown):
		return Result{Refusal: ErrTokenUnknown}, nil
	case errors.As(err, &gone):
		return Result{Refusal: gone}, nil
	case err != nil:
		return Result{}, err
	}
	p, err := s.principals.ByID(ctx, q, tok.Owner, aud)
	if errors.Is(err, ErrUnknownLogin) {
		return Result{Refusal: ErrTokenUnknown}, nil
	}
	if err != nil {
		return Result{}, err
	}
	now := s.now()
	_, had, err := credentialOf(ctx, q, p.ID)
	if err != nil {
		return Result{}, err
	}
	if err := setCredential(ctx, q, p.ID, hash, now); err != nil {
		return Result{}, err
	}
	if err := session.RevokeAll(ctx, q, p.ID, ReasonPasswordReset, now); err != nil {
		return Result{}, err
	}
	if err := throttle.Clear(ctx, q, s.throttleKey(Normalize(p.Login)), string(aud)); err != nil {
		return Result{}, err
	}
	result := ResultPasswordSet
	if had {
		result = ResultPasswordReset
	}
	return Result{Principal: p}, s.record(ctx, q, now, events.Event{PrincipalID: &p.ID, Audience: string(aud), Login: p.Login,
		Result: result, IP: m.IP, UserAgent: m.UserAgent})
}

// PadSince sleeps until floor has passed since start (spec §8.6). The app's
// reset-request handler calls it after its transaction commits, so a known
// and an unknown email take as long.
func PadSince(start time.Time, floor time.Duration) {
	if d := floor - time.Since(start); d > 0 {
		time.Sleep(d)
	}
}
