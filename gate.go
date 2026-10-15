package authkit

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/factor"
)

// FactorPassword is the first factor of a password sign-in or reset; sessions, events and proposals store it as "".
const FactorPassword FactorKind = "password"

// SecondStepVerifier checks second-step codes for the core; the secondfactor module supplies it.
type SecondStepVerifier interface {
	Verify(ctx context.Context, q db.Querier, principal uuid.UUID, method FactorKind, code string) (ok bool, err error)
	RecoveryCodesLeft(ctx context.Context, q db.Querier, principal uuid.UUID) (int, error)
	SendCode(ctx context.Context, q db.Querier, principal uuid.UUID) (req EmailCodeRequest, retryAfter time.Duration, err error)
	ChallengeRules() (ttl time.Duration, maxTries int)
}

// SetVerifier gives the core its second-step verifier, once, before the Service serves requests.
func (c *Core) SetVerifier(v SecondStepVerifier) error {
	s := c.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if v == nil {
		return errors.New("authkit: SetVerifier needs a verifier")
	}
	if s.verifier != nil {
		return ErrAttached
	}
	s.verifier = v
	return nil
}

func sessionFactor(f FactorKind) FactorKind {
	if f == FactorPassword {
		return ""
	}
	return f
}

func (s *Service) core() *Core {
	return &Core{s: s}
}

type factorVerifier struct{ s *Service }

func (v factorVerifier) Verify(ctx context.Context, q db.Querier, principal uuid.UUID, method FactorKind, code string) (bool, error) {
	return v.s.checkFactor(ctx, q, principal, method, code, v.s.now())
}

func (v factorVerifier) RecoveryCodesLeft(ctx context.Context, q db.Querier, principal uuid.UUID) (int, error) {
	return factor.RecoveryCodesLeft(ctx, q, principal)
}

func (v factorVerifier) SendCode(ctx context.Context, q db.Querier, principal uuid.UUID) (EmailCodeRequest, time.Duration, error) {
	id, exp, retryAfter, err := factor.RequestEmailCode(ctx, q, v.s.cfg.Rand, principal, factor.PurposeSignIn, v.s.now(), v.s.emailRules())
	return EmailCodeRequest{ID: id, ExpiresAt: exp}, retryAfter, err
}

func (v factorVerifier) ChallengeRules() (time.Duration, int) {
	return v.s.cfg.SecondFactors.ChallengeTTL, v.s.cfg.SecondFactors.MaxTries
}

func (s *Service) gateMethods(ctx context.Context, q db.Querier, id uuid.UUID, f FactorKind) ([]FactorKind, bool, error) {
	if f == FactorPasskey {
		return nil, false, nil
	}
	kinds, err := factor.ConfirmedKinds(ctx, q, id)
	if err != nil {
		return nil, false, err
	}
	// WHY: the verifier is checked before secondFactorMethods, which calls it.
	if len(kinds) > 0 && s.verifier == nil {
		return nil, true, nil
	}
	methods, err := s.secondFactorMethods(ctx, q, id, kinds)
	return methods, false, err
}
