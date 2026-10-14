package authkit

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/events"
	"github.com/sylly-mika/authkit/internal/factor"
)

// BeginEmailCodeSetup starts turning on the email code factor: it stores a code row for the caller and returns its ID for the app to mail; MintEmailCode makes the code at send time. A second request replaces the code, at most once per SecondFactors.ResendEvery and SecondFactors.MaxSends times. Needs a recent sign-in and a transaction.
func (s *Service) BeginEmailCodeSetup(ctx context.Context, q db.Querier, c *Claims, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if len(s.cfg.SecondFactors.Key) == 0 {
		return Result{Refusal: ErrSecondFactorsOff}, nil
	}
	now := s.now()
	if err := factor.Lock(ctx, q, c.Subject); err != nil {
		return Result{}, err
	}
	_, ok, err := s.factorSession(ctx, q, c, now)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrReauthRequired}, nil
	}
	confirmed, err := factor.ConfirmedKinds(ctx, q, c.Subject)
	if err != nil {
		return Result{}, err
	}
	if slices.Contains(confirmed, string(FactorEmail)) {
		return Result{Refusal: ErrFactorExists}, nil
	}
	id, exp, retryAfter, err := factor.RequestEmailCode(ctx, q, s.cfg.Rand, c.Subject, factor.PurposeEnable, now, s.emailRules())
	if err != nil {
		return Result{}, err
	}
	if retryAfter > 0 {
		return Result{Refusal: ErrResendTooSoon{RetryAfter: retryAfter}}, nil
	}
	return Result{EmailCode: &EmailCodeRequest{ID: id, ExpiresAt: exp}}, nil
}

// ConfirmEmailCode turns on the email code factor with the mailed code. When it is the caller's first factor the Result carries ten recovery codes, shown once. Needs a recent sign-in and a transaction.
func (s *Service) ConfirmEmailCode(ctx context.Context, q db.Querier, c *Claims, code string, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if len(s.cfg.SecondFactors.Key) == 0 {
		return Result{Refusal: ErrSecondFactorsOff}, nil
	}
	m = m.clean()
	now := s.now()
	keys := factor.DeriveKeys(s.cfg.SecondFactors.Key)
	if err := factor.Lock(ctx, q, c.Subject); err != nil {
		return Result{}, err
	}
	sess, ok, err := s.factorSession(ctx, q, c, now)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrReauthRequired}, nil
	}
	confirmed, err := factor.ConfirmedKinds(ctx, q, c.Subject)
	if err != nil {
		return Result{}, err
	}
	if slices.Contains(confirmed, string(FactorEmail)) {
		return Result{Refusal: ErrFactorExists}, nil
	}
	check, err := factor.CheckEmailCode(ctx, q, keys.EmailKey, c.Subject, factor.PurposeEnable, code, now, s.cfg.SecondFactors.MaxTries)
	if err != nil {
		return Result{}, err
	}
	switch check {
	case factor.CodeEnded:
		return Result{Refusal: ErrCodeEnded}, nil
	case factor.CodeBad:
		if err := s.record(ctx, q, now, SourceSecondFactor, events.Event{PrincipalID: &c.Subject, SessionID: &c.SessionID, ScopeID: sess.ScopeID, Audience: c.Audience, Result: ResultBadCode, SecondFactor: string(FactorEmail), IP: m.IP, UserAgent: m.UserAgent}); err != nil {
			return Result{}, err
		}
		return Result{Refusal: ErrBadCode}, nil
	}
	if _, err := q.Exec(ctx, `INSERT INTO auth_second_factors (principal_id, kind, secret, last_step, created_at, confirmed_at) VALUES ($1, 'email', NULL, NULL, $2, $2)`, c.Subject, now); err != nil {
		return Result{}, err
	}
	var codes []string
	if len(confirmed) == 0 {
		codes, err = s.issueRecoveryCodes(ctx, q, keys, c.Subject, now)
		if err != nil {
			return Result{}, err
		}
		if err := s.markSessionFactor(ctx, q, c.SessionID, FactorEmail); err != nil {
			return Result{}, err
		}
	}
	if err := s.record(ctx, q, now, SourceSecondFactor, events.Event{PrincipalID: &c.Subject, SessionID: &c.SessionID, ScopeID: sess.ScopeID, Audience: c.Audience, Result: ResultFactorAdded, SecondFactor: string(FactorEmail), IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return Result{}, err
	}
	return Result{RecoveryCodes: codes}, nil
}

// RequestEmailProof stores an email code the caller can give as proof to DisableSecondFactor; the app mails it as for BeginEmailCodeSetup. Needs the email factor, a recent sign-in and a transaction.
func (s *Service) RequestEmailProof(ctx context.Context, q db.Querier, c *Claims, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if len(s.cfg.SecondFactors.Key) == 0 {
		return Result{Refusal: ErrSecondFactorsOff}, nil
	}
	now := s.now()
	if err := factor.Lock(ctx, q, c.Subject); err != nil {
		return Result{}, err
	}
	_, ok, err := s.factorSession(ctx, q, c, now)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrReauthRequired}, nil
	}
	confirmed, err := factor.ConfirmedKinds(ctx, q, c.Subject)
	if err != nil {
		return Result{}, err
	}
	if !slices.Contains(confirmed, string(FactorEmail)) {
		return Result{Refusal: ErrFactorNotFound}, nil
	}
	id, exp, retryAfter, err := factor.RequestEmailCode(ctx, q, s.cfg.Rand, c.Subject, factor.PurposeProof, now, s.emailRules())
	if err != nil {
		return Result{}, err
	}
	if retryAfter > 0 {
		return Result{Refusal: ErrResendTooSoon{RetryAfter: retryAfter}}, nil
	}
	return Result{EmailCode: &EmailCodeRequest{ID: id, ExpiresAt: exp}}, nil
}

// MintEmailCode makes the 6-digit code for a stored code row at send time and returns it with its principal and purpose; minting again replaces the code. ErrCodeEnded when the row was replaced, expired or used up. Needs a transaction.
func (s *Service) MintEmailCode(ctx context.Context, q db.Querier, id uuid.UUID) (EmailCodeMail, error) {
	if err := db.RequireTx(q); err != nil {
		return EmailCodeMail{}, err
	}
	if len(s.cfg.SecondFactors.Key) == 0 {
		return EmailCodeMail{}, ErrSecondFactorsOff
	}
	keys := factor.DeriveKeys(s.cfg.SecondFactors.Key)
	principal, purpose, code, exp, ok, err := factor.MintEmailCode(ctx, q, s.cfg.Rand, keys.EmailKey, id, s.now(), s.cfg.SecondFactors.MaxTries)
	if err != nil {
		return EmailCodeMail{}, err
	}
	if !ok {
		return EmailCodeMail{}, ErrCodeEnded
	}
	return EmailCodeMail{PrincipalID: principal, Purpose: purpose, Code: code, ExpiresAt: exp}, nil
}

func (s *Service) emailRules() factor.EmailRules {
	r := s.cfg.SecondFactors
	return factor.EmailRules{TTL: r.EmailCodeTTL, ResendEvery: r.ResendEvery, MaxSends: r.MaxSends, MaxTries: r.MaxTries}
}
