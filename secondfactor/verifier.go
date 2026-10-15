package secondfactor

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/factor"
	"github.com/sylly-mika/authkit/internal/totp"
)

func (s *Module) checkEmailStep(ctx context.Context, q db.Querier, principalID uuid.UUID, code string, now time.Time) (bool, error) {
	keys := factor.DeriveKeys(s.r.Key)
	confirmed, err := factor.ConfirmedKinds(ctx, q, principalID)
	if err != nil {
		return false, err
	}
	if !slices.Contains(confirmed, string(authkit.FactorEmail)) {
		return false, nil
	}
	c, err := factor.CheckEmailCode(ctx, q, keys.EmailKey, principalID, factor.PurposeSignIn, code, now, s.r.MaxTries)
	if err != nil {
		return false, err
	}
	return c == factor.CodeOK, nil
}

func (s *Module) checkFactor(ctx context.Context, q db.Querier, id uuid.UUID, method authkit.FactorKind, code string, now time.Time) (bool, error) {
	keys := factor.DeriveKeys(s.r.Key)
	switch method {
	case authkit.FactorTOTP:
		f, found, err := factor.Load(ctx, q, id, string(authkit.FactorTOTP))
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
		step, ok := totp.VerifyTOTP(secret, code, now, f.LastStep)
		if !ok {
			return false, nil
		}
		return factor.AcceptStep(ctx, q, id, step)
	case authkit.FactorEmail:
		return s.checkEmailStep(ctx, q, id, code, now)
	case authkit.FactorRecovery:
		hash := factor.HashCode(keys.RecoveryKey, id, "recovery", factor.NormalizeCode(code))
		return factor.SpendRecoveryCode(ctx, q, id, hash, now)
	}
	return false, nil
}

type verifier struct{ m *Module }

func (v verifier) Verify(ctx context.Context, q db.Querier, principal uuid.UUID, method authkit.FactorKind, code string) (bool, error) {
	return v.m.checkFactor(ctx, q, principal, method, code, v.m.core.Now())
}

func (v verifier) RecoveryCodesLeft(ctx context.Context, q db.Querier, principal uuid.UUID) (int, error) {
	return factor.RecoveryCodesLeft(ctx, q, principal)
}

func (v verifier) SendCode(ctx context.Context, q db.Querier, principal uuid.UUID) (authkit.EmailCodeRequest, time.Duration, error) {
	id, exp, retryAfter, err := factor.RequestEmailCode(ctx, q, v.m.core.Rand(), principal, factor.PurposeSignIn, v.m.core.Now(), v.m.emailRules())
	return authkit.EmailCodeRequest{ID: id, ExpiresAt: exp}, retryAfter, err
}

func (v verifier) ChallengeRules() (time.Duration, int) {
	return v.m.r.ChallengeTTL, v.m.r.MaxTries
}
