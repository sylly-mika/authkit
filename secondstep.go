package authkit

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/events"
	"github.com/sylly-mika/authkit/internal/factor"
	"github.com/sylly-mika/authkit/internal/throttle"
	"github.com/sylly-mika/authkit/internal/token"
)

// VerifySecondStep completes a sign-in that returned Result.SecondStep, with an authenticator code, an emailed code or a recovery code. A wrong code counts on the challenge and on the login's throttle; the refusal's writes must be committed.
func (s *Service) VerifySecondStep(ctx context.Context, q db.Querier, aud Audience, token string, method FactorKind, code string, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if len(s.cfg.SecondFactors.Key) == 0 {
		return Result{Refusal: ErrSecondFactorsOff}, nil
	}
	m = m.clean()
	now := s.now()
	ch, ok, err := factor.LockChallenge(ctx, q, token, string(aud), now, s.cfg.SecondFactors.MaxTries)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrChallengeEnded}, nil
	}
	p, err := s.principals.ByID(ctx, q, ch.PrincipalID, aud)
	if errors.Is(err, ErrUnknownLogin) {
		return Result{Refusal: ErrChallengeEnded}, nil
	}
	if err != nil {
		return Result{}, err
	}
	ev := events.Event{PrincipalID: &p.ID, Audience: string(aud), Login: p.Login, IP: m.IP, UserAgent: m.UserAgent}
	until, locked, err := throttle.Locked(ctx, q, ch.ThrottleKey, string(aud), now)
	if err != nil {
		return Result{}, err
	}
	if locked {
		ev.Result = ResultLocked
		if err := s.record(ctx, q, now, SourceSecondStep, ev); err != nil {
			return Result{}, err
		}
		return Result{Refusal: ErrLocked{RetryAfter: until.Sub(now)}}, nil
	}
	if method != FactorTOTP && method != FactorEmail && method != FactorRecovery {
		return s.failSecondStep(ctx, q, ch, aud, now, ev)
	}
	adm, refusal, err := s.admit(ctx, q, Proposal{Principal: p, Audience: aud, SecondFactor: method})
	if err != nil {
		return Result{}, err
	}
	if refusal != nil {
		ev.Result = refusal.Result
		if err := s.record(ctx, q, now, SourceSecondStep, ev); err != nil {
			return Result{}, err
		}
		return Result{Refusal: refusal.Err}, nil
	}
	ok, err = s.checkFactor(ctx, q, p.ID, method, code, now)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return s.failSecondStep(ctx, q, ch, aud, now, ev)
	}
	if err := factor.SpendChallenge(ctx, q, ch.ID, now); err != nil {
		return Result{}, err
	}
	if err := throttle.Clear(ctx, q, ch.ThrottleKey, string(aud)); err != nil {
		return Result{}, err
	}
	res, err := s.openSignedIn(ctx, q, SourceSecondStep, grant{p: p, aud: aud, adm: adm, m: m, now: now, factor: method})
	if err != nil {
		return Result{}, err
	}
	if method == FactorRecovery {
		left, err := factor.RecoveryCodesLeft(ctx, q, p.ID)
		if err != nil {
			return Result{}, err
		}
		res.RecoveryCodesLeft = &left
	}
	return res, nil
}

func (s *Service) failSecondStep(ctx context.Context, q db.Querier, ch factor.Challenge, aud Audience, now time.Time, ev events.Event) (Result, error) {
	if err := factor.FailChallenge(ctx, q, ch.ID); err != nil {
		return Result{}, err
	}
	if err := throttle.Fail(ctx, q, ch.ThrottleKey, string(aud), now, s.cfg.Throttle); err != nil {
		return Result{}, err
	}
	ev.Result = ResultBadCode
	if err := s.record(ctx, q, now, SourceSecondStep, ev); err != nil {
		return Result{}, err
	}
	if ch.Tries+1 >= s.cfg.SecondFactors.MaxTries {
		return Result{Refusal: ErrChallengeEnded}, nil
	}
	return Result{Refusal: ErrBadCode}, nil
}

func (s *Service) secondFactorMethods(ctx context.Context, q db.Querier, id uuid.UUID) ([]FactorKind, error) {
	kinds, err := factor.ConfirmedKinds(ctx, q, id)
	if err != nil {
		return nil, err
	}
	held := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		held[k] = true
	}
	var methods []FactorKind
	if held[string(FactorTOTP)] {
		methods = append(methods, FactorTOTP)
	}
	if held[string(FactorEmail)] {
		methods = append(methods, FactorEmail)
	}
	if len(kinds) > 0 {
		left, err := factor.RecoveryCodesLeft(ctx, q, id)
		if err != nil {
			return nil, err
		}
		if left > 0 {
			methods = append(methods, FactorRecovery)
		}
	}
	return methods, nil
}

func (s *Service) issueSecondStep(ctx context.Context, q db.Querier, source string, p Principal, aud Audience, origin, throttleKey string, methods []FactorKind, scope *uuid.UUID, m Meta, now time.Time) (Result, error) {
	raw, exp, err := factor.CreateChallenge(ctx, q, s.cfg.Rand, p.ID, string(aud), origin, throttleKey, now, s.cfg.SecondFactors.ChallengeTTL)
	if err != nil {
		return Result{}, err
	}
	ev := events.Event{PrincipalID: &p.ID, Audience: string(aud), ScopeID: scope, Login: p.Login, Result: ResultSecondStepRequired, IP: m.IP, UserAgent: m.UserAgent}
	if err := s.record(ctx, q, now, source, ev); err != nil {
		return Result{}, err
	}
	return Result{Principal: p, SecondStep: &SecondStep{Token: raw, ExpiresAt: exp, Methods: methods}}, nil
}

// SendSecondStepEmail issues an emailed sign-in code for a live second-step challenge. The code is minted later by MintEmailCode and never returned here. Needs a transaction.
func (s *Service) SendSecondStepEmail(ctx context.Context, q db.Querier, aud Audience, raw string, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if len(s.cfg.SecondFactors.Key) == 0 {
		return Result{Refusal: ErrSecondFactorsOff}, nil
	}
	m = m.clean()
	now := s.now()
	var principalID uuid.UUID
	var throttleKey string
	err := q.QueryRow(ctx, `SELECT principal_id, throttle_key FROM auth_second_step_challenges
		WHERE challenge_hash = $1 AND audience = $2 AND used_at IS NULL AND expires_at > $3 AND tries < $4`,
		token.Hash(raw), string(aud), now, s.cfg.SecondFactors.MaxTries).Scan(&principalID, &throttleKey)
	if errors.Is(err, db.ErrNoRows) {
		return Result{Refusal: ErrChallengeEnded}, nil
	}
	if err != nil {
		return Result{}, err
	}
	until, locked, err := throttle.Locked(ctx, q, throttleKey, string(aud), now)
	if err != nil {
		return Result{}, err
	}
	if locked {
		return Result{Refusal: ErrLocked{RetryAfter: until.Sub(now)}}, nil
	}
	confirmed, err := factor.ConfirmedKinds(ctx, q, principalID)
	if err != nil {
		return Result{}, err
	}
	if !slices.Contains(confirmed, string(FactorEmail)) {
		return Result{Refusal: ErrFactorNotFound}, nil
	}
	id, exp, retryAfter, err := factor.RequestEmailCode(ctx, q, s.cfg.Rand, principalID, factor.PurposeSignIn, now, s.emailRules())
	if err != nil {
		return Result{}, err
	}
	if retryAfter > 0 {
		return Result{Refusal: ErrResendTooSoon{RetryAfter: retryAfter}}, nil
	}
	p, err := s.principals.ByID(ctx, q, principalID, aud)
	if err != nil {
		return Result{}, err
	}
	return Result{Principal: p, EmailCode: &EmailCodeRequest{ID: id, ExpiresAt: exp}}, nil
}

func (s *Service) checkEmailStep(ctx context.Context, q db.Querier, principalID uuid.UUID, code string, now time.Time) (bool, error) {
	keys := factor.DeriveKeys(s.cfg.SecondFactors.Key)
	confirmed, err := factor.ConfirmedKinds(ctx, q, principalID)
	if err != nil {
		return false, err
	}
	if !slices.Contains(confirmed, string(FactorEmail)) {
		return false, nil
	}
	c, err := factor.CheckEmailCode(ctx, q, keys.EmailKey, principalID, factor.PurposeSignIn, code, now, s.cfg.SecondFactors.MaxTries)
	if err != nil {
		return false, err
	}
	return c == factor.CodeOK, nil
}

func (s *Service) checkFactor(ctx context.Context, q db.Querier, id uuid.UUID, method FactorKind, code string, now time.Time) (bool, error) {
	keys := factor.DeriveKeys(s.cfg.SecondFactors.Key)
	switch method {
	case FactorTOTP:
		f, found, err := factor.Load(ctx, q, id, string(FactorTOTP))
		if err != nil {
			return false, err
		}
		if !found || f.ConfirmedAt == nil {
			return false, nil
		}
		secret, err := keys.Open(f.Secret, id)
		if err != nil {
			return false, fmt.Errorf("authkit: open the authenticator secret: %w", err)
		}
		step, ok := factor.VerifyTOTP(secret, code, now, f.LastStep)
		if !ok {
			return false, nil
		}
		return factor.AcceptStep(ctx, q, id, step)
	case FactorEmail:
		return s.checkEmailStep(ctx, q, id, code, now)
	case FactorRecovery:
		hash := factor.HashCode(keys.RecoveryKey, id, "recovery", factor.NormalizeCode(code))
		return factor.SpendRecoveryCode(ctx, q, id, hash, now)
	}
	return false, nil
}
