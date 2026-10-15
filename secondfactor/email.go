package secondfactor

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/factor"
)

// BeginEmailCodeSetup starts turning on the email code factor: it stores a code row for the caller and returns its ID for the app to mail; MintEmailCode makes the code at send time. A second request replaces the code, at most once per Rules.ResendEvery and Rules.MaxSends times. Needs a recent sign-in and a transaction.
func (s *Module) BeginEmailCodeSetup(ctx context.Context, q db.Querier, c *authkit.Claims, m authkit.Meta) (authkit.Result, error) {
	q = s.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	if len(s.r.Key) == 0 {
		return authkit.Result{Refusal: authkit.ErrSecondFactorsOff}, nil
	}
	now := s.core.Now()
	if err := factor.Lock(ctx, q, c.Subject); err != nil {
		return authkit.Result{}, err
	}
	_, ok, err := s.core.Fresh(ctx, q, c, s.r.Reauth, now)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrReauthRequired}, nil
	}
	confirmed, err := factor.ConfirmedKinds(ctx, q, c.Subject)
	if err != nil {
		return authkit.Result{}, err
	}
	if slices.Contains(confirmed, string(authkit.FactorEmail)) {
		return authkit.Result{Refusal: authkit.ErrFactorExists}, nil
	}
	id, exp, retryAfter, err := factor.RequestEmailCode(ctx, q, s.core.Rand(), c.Subject, factor.PurposeEnable, now, s.emailRules())
	if err != nil {
		return authkit.Result{}, err
	}
	if retryAfter > 0 {
		return authkit.Result{Refusal: authkit.ErrResendTooSoon{RetryAfter: retryAfter}}, nil
	}
	return authkit.Result{EmailCode: &authkit.EmailCodeRequest{ID: id, ExpiresAt: exp}}, nil
}

// ConfirmEmailCode turns on the email code factor with the mailed code. When it is the caller's first factor the authkit.Result carries ten recovery codes, shown once. Needs a recent sign-in and a transaction.
func (s *Module) ConfirmEmailCode(ctx context.Context, q db.Querier, c *authkit.Claims, code string, m authkit.Meta) (authkit.Result, error) {
	q = s.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	if len(s.r.Key) == 0 {
		return authkit.Result{Refusal: authkit.ErrSecondFactorsOff}, nil
	}
	m = m.Clean()
	now := s.core.Now()
	keys := factor.DeriveKeys(s.r.Key)
	if err := factor.Lock(ctx, q, c.Subject); err != nil {
		return authkit.Result{}, err
	}
	sess, ok, err := s.core.Fresh(ctx, q, c, s.r.Reauth, now)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrReauthRequired}, nil
	}
	confirmed, err := factor.ConfirmedKinds(ctx, q, c.Subject)
	if err != nil {
		return authkit.Result{}, err
	}
	if slices.Contains(confirmed, string(authkit.FactorEmail)) {
		return authkit.Result{Refusal: authkit.ErrFactorExists}, nil
	}
	check, err := factor.CheckEmailCode(ctx, q, keys.EmailKey, c.Subject, factor.PurposeEnable, code, now, s.r.MaxTries)
	if err != nil {
		return authkit.Result{}, err
	}
	switch check {
	case factor.CodeEnded:
		return authkit.Result{Refusal: authkit.ErrCodeEnded}, nil
	case factor.CodeBad:
		if err := s.core.Record(ctx, q, authkit.SourceSecondFactor, authkit.Event{At: now, PrincipalID: &c.Subject, SessionID: &c.SessionID, ScopeID: sess.ScopeID, Audience: c.Audience, Result: authkit.ResultBadCode, SecondFactor: string(authkit.FactorEmail), IP: m.IP, UserAgent: m.UserAgent}); err != nil {
			return authkit.Result{}, err
		}
		return authkit.Result{Refusal: authkit.ErrBadCode}, nil
	}
	if _, err := q.Exec(ctx, `INSERT INTO auth_second_factors (principal_id, kind, secret, last_step, created_at, confirmed_at) VALUES ($1, 'email', NULL, NULL, $2, $2)`, c.Subject, now); err != nil {
		return authkit.Result{}, err
	}
	var codes []string
	if len(confirmed) == 0 {
		codes, err = s.issueRecoveryCodes(ctx, q, keys, c.Subject, now)
		if err != nil {
			return authkit.Result{}, err
		}
		if err := s.core.MarkSessionFactor(ctx, q, c.SessionID, authkit.FactorEmail); err != nil {
			return authkit.Result{}, err
		}
	}
	if err := s.core.Record(ctx, q, authkit.SourceSecondFactor, authkit.Event{At: now, PrincipalID: &c.Subject, SessionID: &c.SessionID, ScopeID: sess.ScopeID, Audience: c.Audience, Result: authkit.ResultFactorAdded, SecondFactor: string(authkit.FactorEmail), IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{RecoveryCodes: codes}, nil
}

// RequestEmailProof stores an email code the caller can give as proof to DisableSecondFactor; the app mails it as for BeginEmailCodeSetup. Needs the email factor, a recent sign-in and a transaction.
func (s *Module) RequestEmailProof(ctx context.Context, q db.Querier, c *authkit.Claims, m authkit.Meta) (authkit.Result, error) {
	q = s.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	if len(s.r.Key) == 0 {
		return authkit.Result{Refusal: authkit.ErrSecondFactorsOff}, nil
	}
	now := s.core.Now()
	if err := factor.Lock(ctx, q, c.Subject); err != nil {
		return authkit.Result{}, err
	}
	_, ok, err := s.core.Fresh(ctx, q, c, s.r.Reauth, now)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrReauthRequired}, nil
	}
	confirmed, err := factor.ConfirmedKinds(ctx, q, c.Subject)
	if err != nil {
		return authkit.Result{}, err
	}
	if !slices.Contains(confirmed, string(authkit.FactorEmail)) {
		return authkit.Result{Refusal: authkit.ErrFactorNotFound}, nil
	}
	id, exp, retryAfter, err := factor.RequestEmailCode(ctx, q, s.core.Rand(), c.Subject, factor.PurposeProof, now, s.emailRules())
	if err != nil {
		return authkit.Result{}, err
	}
	if retryAfter > 0 {
		return authkit.Result{Refusal: authkit.ErrResendTooSoon{RetryAfter: retryAfter}}, nil
	}
	return authkit.Result{EmailCode: &authkit.EmailCodeRequest{ID: id, ExpiresAt: exp}}, nil
}

// MintEmailCode makes the 6-digit code for a stored code row at send time and returns it with its principal and purpose; minting again replaces the code. authkit.ErrCodeEnded when the row was replaced, expired or used up. Needs a transaction.
func (s *Module) MintEmailCode(ctx context.Context, q db.Querier, id uuid.UUID) (authkit.EmailCodeMail, error) {
	q = s.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.EmailCodeMail{}, err
	}
	if len(s.r.Key) == 0 {
		return authkit.EmailCodeMail{}, authkit.ErrSecondFactorsOff
	}
	keys := factor.DeriveKeys(s.r.Key)
	principal, purpose, code, exp, ok, err := factor.MintEmailCode(ctx, q, s.core.Rand(), keys.EmailKey, id, s.core.Now(), s.r.MaxTries)
	if err != nil {
		return authkit.EmailCodeMail{}, err
	}
	if !ok {
		return authkit.EmailCodeMail{}, authkit.ErrCodeEnded
	}
	return authkit.EmailCodeMail{PrincipalID: principal, Purpose: purpose, Code: code, ExpiresAt: exp}, nil
}

func (s *Module) emailRules() factor.EmailRules {
	r := s.r
	return factor.EmailRules{TTL: r.EmailCodeTTL, ResendEvery: r.ResendEvery, MaxSends: r.MaxSends, MaxTries: r.MaxTries}
}
