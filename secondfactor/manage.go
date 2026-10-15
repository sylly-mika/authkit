package secondfactor

import (
	"bytes"
	"context"
	"image/png"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	pqtotp "github.com/pquerna/otp/totp"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/factor"
	"github.com/sylly-mika/authkit/internal/totp"
)

// SecondFactorStatus is which second factors the caller has turned on and how many unused recovery codes remain. A bare pinned connection is fine.
func (s *Module) SecondFactorStatus(ctx context.Context, q db.Querier, c *authkit.Claims) (authkit.FactorStatus, error) {
	if len(s.r.Key) == 0 {
		return authkit.FactorStatus{}, authkit.ErrSecondFactorsOff
	}
	kinds, err := factor.ConfirmedKinds(ctx, q, c.Subject)
	if err != nil {
		return authkit.FactorStatus{}, err
	}
	n, err := factor.RecoveryCodesLeft(ctx, q, c.Subject)
	if err != nil {
		return authkit.FactorStatus{}, err
	}
	return authkit.FactorStatus{TOTP: slices.Contains(kinds, "totp"), Email: slices.Contains(kinds, "email"), RecoveryCodesLeft: n}, nil
}

// BeginTOTPSetup starts an authenticator setup for the caller, replacing an unconfirmed one: it stores the sealed secret and returns the otpauth URI, the secret and a QR code. It needs a sign-in within Rules.Reauth; authkit.ErrFactorExists when the authenticator is on already.
func (s *Module) BeginTOTPSetup(ctx context.Context, q db.Querier, c *authkit.Claims, m authkit.Meta) (authkit.Result, error) {
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
	_, ok, err := s.core.Fresh(ctx, q, c, s.r.Reauth, now)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrReauthRequired}, nil
	}
	p, err := s.core.Principals().ByID(ctx, q, c.Subject, authkit.Audience(c.Audience))
	if err != nil {
		return authkit.Result{}, err
	}
	secret, err := totp.NewSecret(s.core.Rand())
	if err != nil {
		return authkit.Result{}, err
	}
	key, err := pqtotp.Generate(pqtotp.GenerateOpts{Issuer: s.r.Issuer, AccountName: p.Login, Period: 30, Secret: secret, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		return authkit.Result{}, err
	}
	keys := factor.DeriveKeys(s.r.Key)
	sealed, err := keys.Seal(s.core.Rand(), secret, c.Subject)
	if err != nil {
		return authkit.Result{}, err
	}
	stored, err := factor.PutPendingTOTP(ctx, q, c.Subject, sealed, now)
	if err != nil {
		return authkit.Result{}, err
	}
	if !stored {
		return authkit.Result{Refusal: authkit.ErrFactorExists}, nil
	}
	img, err := key.Image(256, 256)
	if err != nil {
		return authkit.Result{}, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{TOTPSetup: &authkit.TOTPSetup{URI: key.URL(), Secret: key.Secret(), QRPNG: buf.Bytes(), ExpiresAt: now.Add(s.r.SetupTTL)}}, nil
}

// ConfirmTOTP turns the caller's authenticator on with a current code from it. The first second factor also returns 10 recovery codes, shown once. It needs a sign-in within Rules.Reauth.
func (s *Module) ConfirmTOTP(ctx context.Context, q db.Querier, c *authkit.Claims, code string, m authkit.Meta) (authkit.Result, error) {
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
	sess, ok, err := s.core.Fresh(ctx, q, c, s.r.Reauth, now)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrReauthRequired}, nil
	}
	f, found, err := factor.Load(ctx, q, c.Subject, "totp")
	if err != nil {
		return authkit.Result{}, err
	}
	if !found {
		return authkit.Result{Refusal: authkit.ErrFactorNotFound}, nil
	}
	if f.ConfirmedAt != nil {
		return authkit.Result{Refusal: authkit.ErrFactorExists}, nil
	}
	if !now.Before(f.CreatedAt.Add(s.r.SetupTTL)) {
		return authkit.Result{Refusal: authkit.ErrSetupExpired}, nil
	}
	keys := factor.DeriveKeys(s.r.Key)
	secret, err := keys.Open(f.Secret, c.Subject)
	if err != nil {
		return authkit.Result{}, err
	}
	step, ok := totp.VerifyTOTP(secret, code, now, f.LastStep)
	if !ok {
		if err := s.core.Record(ctx, q, authkit.SourceSecondFactor, authkit.Event{At: now, PrincipalID: &c.Subject, SessionID: &c.SessionID, ScopeID: sess.ScopeID, Audience: c.Audience, Result: authkit.ResultBadCode, IP: m.IP, UserAgent: m.UserAgent, SecondFactor: string(authkit.FactorTOTP)}); err != nil {
			return authkit.Result{}, err
		}
		return authkit.Result{Refusal: authkit.ErrBadCode}, nil
	}
	ok, err = factor.Confirm(ctx, q, c.Subject, "totp", &step, now)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrBadCode}, nil
	}
	kinds, err := factor.ConfirmedKinds(ctx, q, c.Subject)
	if err != nil {
		return authkit.Result{}, err
	}
	var codes []string
	if len(kinds) == 1 {
		codes, err = s.issueRecoveryCodes(ctx, q, keys, c.Subject, now)
		if err != nil {
			return authkit.Result{}, err
		}
	}
	if err := s.core.MarkSessionFactor(ctx, q, c.SessionID, authkit.FactorTOTP); err != nil {
		return authkit.Result{}, err
	}
	if err := s.core.Record(ctx, q, authkit.SourceSecondFactor, authkit.Event{At: now, PrincipalID: &c.Subject, SessionID: &c.SessionID, ScopeID: sess.ScopeID, Audience: c.Audience, Result: authkit.ResultFactorAdded, IP: m.IP, UserAgent: m.UserAgent, SecondFactor: string(authkit.FactorTOTP)}); err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{RecoveryCodes: codes}, nil
}

// RegenerateRecoveryCodes replaces the caller's recovery codes with 10 new ones, shown once. It needs a second factor and a sign-in within Rules.Reauth.
func (s *Module) RegenerateRecoveryCodes(ctx context.Context, q db.Querier, c *authkit.Claims, m authkit.Meta) (authkit.Result, error) {
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
	sess, ok, err := s.core.Fresh(ctx, q, c, s.r.Reauth, now)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrReauthRequired}, nil
	}
	kinds, err := factor.ConfirmedKinds(ctx, q, c.Subject)
	if err != nil {
		return authkit.Result{}, err
	}
	if len(kinds) == 0 {
		return authkit.Result{Refusal: authkit.ErrFactorNotFound}, nil
	}
	keys := factor.DeriveKeys(s.r.Key)
	codes, err := s.issueRecoveryCodes(ctx, q, keys, c.Subject, now)
	if err != nil {
		return authkit.Result{}, err
	}
	if err := s.core.Record(ctx, q, authkit.SourceSecondFactor, authkit.Event{At: now, PrincipalID: &c.Subject, SessionID: &c.SessionID, ScopeID: sess.ScopeID, Audience: c.Audience, Result: authkit.ResultRecoveryCodesRegenerated, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{RecoveryCodes: codes}, nil
}

func (s *Module) issueRecoveryCodes(ctx context.Context, q db.Querier, keys factor.Keys, principal uuid.UUID, now time.Time) ([]string, error) {
	codes, err := factor.NewRecoveryCodes(s.core.Rand(), s.r.RecoveryCodes)
	if err != nil {
		return nil, err
	}
	hashes := make([][]byte, len(codes))
	for i, code := range codes {
		hashes[i] = factor.HashCode(keys.RecoveryKey, principal, "recovery", factor.NormalizeCode(code))
	}
	if err := factor.ReplaceRecoveryCodes(ctx, q, s.core.Rand(), principal, hashes, now); err != nil {
		return nil, err
	}
	return codes, nil
}

// DisableSecondFactor turns off one of the caller's factors with a current code from any factor or a recovery code. A wrong code counts toward the login throttle. Turning off the last factor deletes the recovery codes. No session ends. Needs a recent sign-in and a transaction.
func (s *Module) DisableSecondFactor(ctx context.Context, q db.Querier, c *authkit.Claims, kind authkit.FactorKind, proof authkit.FactorProof, m authkit.Meta) (authkit.Result, error) {
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	if len(s.r.Key) == 0 {
		return authkit.Result{Refusal: authkit.ErrSecondFactorsOff}, nil
	}
	if kind != authkit.FactorTOTP && kind != authkit.FactorEmail {
		return authkit.Result{Refusal: authkit.ErrFactorNotFound}, nil
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
	if !slices.Contains(confirmed, string(kind)) {
		return authkit.Result{Refusal: authkit.ErrFactorNotFound}, nil
	}
	p, err := s.core.Principals().ByID(ctx, q, c.Subject, authkit.Audience(c.Audience))
	if err != nil {
		return authkit.Result{}, err
	}
	lt := s.core.Throttle(p.Login, authkit.Audience(c.Audience), now)
	until, locked, err := lt.Locked(ctx, q)
	if err != nil {
		return authkit.Result{}, err
	}
	if locked {
		return authkit.Result{Refusal: authkit.ErrLocked{RetryAfter: until.Sub(now)}}, nil
	}
	check, err := s.checkDisableProof(ctx, q, c, keys, confirmed, proof, now)
	if err != nil {
		return authkit.Result{}, err
	}
	switch check {
	case factor.CodeEnded:
		return authkit.Result{Refusal: authkit.ErrCodeEnded}, nil
	case factor.CodeBad:
		if err := lt.Fail(ctx, q); err != nil {
			return authkit.Result{}, err
		}
		if err := s.core.Record(ctx, q, authkit.SourceSecondFactor, authkit.Event{At: now, PrincipalID: &c.Subject, SessionID: &c.SessionID, ScopeID: sess.ScopeID, Audience: c.Audience, Result: authkit.ResultBadCode, SecondFactor: proofFactor(proof.Method), IP: m.IP, UserAgent: m.UserAgent}); err != nil {
			return authkit.Result{}, err
		}
		return authkit.Result{Refusal: authkit.ErrBadCode}, nil
	}
	if _, err := q.Exec(ctx, `DELETE FROM auth_second_factors WHERE principal_id = $1 AND kind = $2 AND confirmed_at IS NOT NULL`, c.Subject, string(kind)); err != nil {
		return authkit.Result{}, err
	}
	if kind == authkit.FactorEmail {
		if err := factor.DropEmailCodes(ctx, q, c.Subject); err != nil {
			return authkit.Result{}, err
		}
	}
	if len(confirmed) == 1 {
		if _, err := q.Exec(ctx, `DELETE FROM auth_recovery_codes WHERE principal_id = $1`, c.Subject); err != nil {
			return authkit.Result{}, err
		}
	}
	if err := s.core.Record(ctx, q, authkit.SourceSecondFactor, authkit.Event{At: now, PrincipalID: &c.Subject, SessionID: &c.SessionID, ScopeID: sess.ScopeID, Audience: c.Audience, Result: authkit.ResultFactorRemoved, SecondFactor: string(kind), IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return authkit.Result{}, err
	}
	if proof.Method != authkit.FactorRecovery {
		return authkit.Result{}, nil
	}
	left, err := factor.RecoveryCodesLeft(ctx, q, c.Subject)
	if err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{RecoveryCodesLeft: &left}, nil
}

func (s *Module) checkDisableProof(ctx context.Context, q db.Querier, c *authkit.Claims, keys factor.Keys, confirmed []string, proof authkit.FactorProof, now time.Time) (factor.CodeCheck, error) {
	switch proof.Method {
	case authkit.FactorTOTP:
		if !slices.Contains(confirmed, string(authkit.FactorTOTP)) {
			return factor.CodeBad, nil
		}
		f, ok, err := factor.Load(ctx, q, c.Subject, string(authkit.FactorTOTP))
		if err != nil {
			return factor.CodeBad, err
		}
		if !ok {
			return factor.CodeBad, nil
		}
		secret, err := keys.Open(f.Secret, c.Subject)
		if err != nil {
			return factor.CodeBad, nil
		}
		step, ok := totp.VerifyTOTP(secret, proof.Code, now, f.LastStep)
		if !ok {
			return factor.CodeBad, nil
		}
		won, err := factor.AcceptStep(ctx, q, c.Subject, step)
		if err != nil {
			return factor.CodeBad, err
		}
		if !won {
			return factor.CodeBad, nil
		}
		return factor.CodeOK, nil
	case authkit.FactorEmail:
		if !slices.Contains(confirmed, string(authkit.FactorEmail)) {
			return factor.CodeEnded, nil
		}
		return factor.CheckEmailCode(ctx, q, keys.EmailKey, c.Subject, factor.PurposeProof, proof.Code, now, s.r.MaxTries)
	case authkit.FactorRecovery:
		spent, err := factor.SpendRecoveryCode(ctx, q, c.Subject, factor.HashCode(keys.RecoveryKey, c.Subject, "recovery", factor.NormalizeCode(proof.Code)), now)
		if err != nil {
			return factor.CodeBad, err
		}
		if !spent {
			return factor.CodeBad, nil
		}
		return factor.CodeOK, nil
	}
	return factor.CodeBad, nil
}

func proofFactor(method authkit.FactorKind) string {
	switch method {
	case authkit.FactorTOTP, authkit.FactorEmail, authkit.FactorRecovery:
		return string(method)
	}
	return ""
}
