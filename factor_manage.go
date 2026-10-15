package authkit

import (
	"bytes"
	"context"
	"errors"
	"image/png"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	pqtotp "github.com/pquerna/otp/totp"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/events"
	"github.com/sylly-mika/authkit/internal/factor"
	"github.com/sylly-mika/authkit/internal/throttle"
	"github.com/sylly-mika/authkit/internal/totp"
	"github.com/sylly-mika/authkit/session"
)

// FactorKind names a second factor: a stored factor, a recovery code, or a passkey sign-in.
type FactorKind string

// The factor kinds. FactorPasskey only ever names how a session was signed in.
const (
	FactorTOTP     FactorKind = "totp"
	FactorEmail    FactorKind = "email"
	FactorRecovery FactorKind = "recovery"
	FactorPasskey  FactorKind = "passkey"
)

// FactorStatus is which second factors a principal has turned on and how many unused recovery codes remain.
type FactorStatus struct {
	TOTP              bool
	Email             bool
	RecoveryCodesLeft int
}

// TOTPSetup is a begun authenticator setup: the otpauth URI, its base32 secret, a 256x256 PNG QR code of the URI, and when the setup ends unconfirmed.
type TOTPSetup struct {
	URI       string
	Secret    string
	QRPNG     []byte
	ExpiresAt time.Time
}

// SecondStep is a password sign-in that needs a second factor: the challenge token, its end, and the methods the principal may use.
type SecondStep struct {
	Token     string
	ExpiresAt time.Time
	Methods   []FactorKind
}

// EmailCodeRequest names an emailed code to send; the app passes ID to MintEmailCode when it sends the mail.
type EmailCodeRequest struct {
	ID        uuid.UUID
	ExpiresAt time.Time
}

// EmailCodeMail is a minted emailed code, for the app's mail only.
type EmailCodeMail struct {
	PrincipalID uuid.UUID
	Purpose     string
	Code        string
	ExpiresAt   time.Time
}

// FactorProof is a current code from one of the principal's factors, or a recovery code.
type FactorProof struct {
	Method FactorKind
	Code   string
}

// SecondFactorStatus is which second factors the caller has turned on and how many unused recovery codes remain. A bare pinned connection is fine.
func (s *Service) SecondFactorStatus(ctx context.Context, q db.Querier, c *Claims) (FactorStatus, error) {
	if len(s.cfg.SecondFactors.Key) == 0 {
		return FactorStatus{}, ErrSecondFactorsOff
	}
	kinds, err := factor.ConfirmedKinds(ctx, q, c.Subject)
	if err != nil {
		return FactorStatus{}, err
	}
	n, err := factor.RecoveryCodesLeft(ctx, q, c.Subject)
	if err != nil {
		return FactorStatus{}, err
	}
	return FactorStatus{TOTP: slices.Contains(kinds, "totp"), Email: slices.Contains(kinds, "email"), RecoveryCodesLeft: n}, nil
}

// BeginTOTPSetup starts an authenticator setup for the caller, replacing an unconfirmed one: it stores the sealed secret and returns the otpauth URI, the secret and a QR code. It needs a sign-in within SecondFactors.Reauth; ErrFactorExists when the authenticator is on already.
func (s *Service) BeginTOTPSetup(ctx context.Context, q db.Querier, c *Claims, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if len(s.cfg.SecondFactors.Key) == 0 {
		return Result{Refusal: ErrSecondFactorsOff}, nil
	}
	m = m.clean()
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
	p, err := s.principals.ByID(ctx, q, c.Subject, Audience(c.Audience))
	if err != nil {
		return Result{}, err
	}
	secret, err := totp.NewSecret(s.cfg.Rand)
	if err != nil {
		return Result{}, err
	}
	key, err := pqtotp.Generate(pqtotp.GenerateOpts{Issuer: s.cfg.SecondFactors.Issuer, AccountName: p.Login, Period: 30, Secret: secret, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		return Result{}, err
	}
	keys := factor.DeriveKeys(s.cfg.SecondFactors.Key)
	sealed, err := keys.Seal(s.cfg.Rand, secret, c.Subject)
	if err != nil {
		return Result{}, err
	}
	stored, err := factor.PutPendingTOTP(ctx, q, c.Subject, sealed, now)
	if err != nil {
		return Result{}, err
	}
	if !stored {
		return Result{Refusal: ErrFactorExists}, nil
	}
	img, err := key.Image(256, 256)
	if err != nil {
		return Result{}, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return Result{}, err
	}
	return Result{TOTPSetup: &TOTPSetup{URI: key.URL(), Secret: key.Secret(), QRPNG: buf.Bytes(), ExpiresAt: now.Add(s.cfg.SecondFactors.SetupTTL)}}, nil
}

// ConfirmTOTP turns the caller's authenticator on with a current code from it. The first second factor also returns 10 recovery codes, shown once. It needs a sign-in within SecondFactors.Reauth.
func (s *Service) ConfirmTOTP(ctx context.Context, q db.Querier, c *Claims, code string, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if len(s.cfg.SecondFactors.Key) == 0 {
		return Result{Refusal: ErrSecondFactorsOff}, nil
	}
	m = m.clean()
	now := s.now()
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
	f, found, err := factor.Load(ctx, q, c.Subject, "totp")
	if err != nil {
		return Result{}, err
	}
	if !found {
		return Result{Refusal: ErrFactorNotFound}, nil
	}
	if f.ConfirmedAt != nil {
		return Result{Refusal: ErrFactorExists}, nil
	}
	if !now.Before(f.CreatedAt.Add(s.cfg.SecondFactors.SetupTTL)) {
		return Result{Refusal: ErrSetupExpired}, nil
	}
	keys := factor.DeriveKeys(s.cfg.SecondFactors.Key)
	secret, err := keys.Open(f.Secret, c.Subject)
	if err != nil {
		return Result{}, err
	}
	step, ok := totp.VerifyTOTP(secret, code, now, f.LastStep)
	if !ok {
		if err := s.record(ctx, q, now, SourceSecondFactor, events.Event{PrincipalID: &c.Subject, SessionID: &c.SessionID, ScopeID: sess.ScopeID, Audience: c.Audience, Result: ResultBadCode, IP: m.IP, UserAgent: m.UserAgent, SecondFactor: string(FactorTOTP)}); err != nil {
			return Result{}, err
		}
		return Result{Refusal: ErrBadCode}, nil
	}
	ok, err = factor.Confirm(ctx, q, c.Subject, "totp", &step, now)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrBadCode}, nil
	}
	kinds, err := factor.ConfirmedKinds(ctx, q, c.Subject)
	if err != nil {
		return Result{}, err
	}
	var codes []string
	if len(kinds) == 1 {
		codes, err = s.issueRecoveryCodes(ctx, q, keys, c.Subject, now)
		if err != nil {
			return Result{}, err
		}
	}
	if err := s.markSessionFactor(ctx, q, c.SessionID, FactorTOTP); err != nil {
		return Result{}, err
	}
	if err := s.record(ctx, q, now, SourceSecondFactor, events.Event{PrincipalID: &c.Subject, SessionID: &c.SessionID, ScopeID: sess.ScopeID, Audience: c.Audience, Result: ResultFactorAdded, IP: m.IP, UserAgent: m.UserAgent, SecondFactor: string(FactorTOTP)}); err != nil {
		return Result{}, err
	}
	return Result{RecoveryCodes: codes}, nil
}

// RegenerateRecoveryCodes replaces the caller's recovery codes with 10 new ones, shown once. It needs a second factor and a sign-in within SecondFactors.Reauth.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, q db.Querier, c *Claims, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if len(s.cfg.SecondFactors.Key) == 0 {
		return Result{Refusal: ErrSecondFactorsOff}, nil
	}
	m = m.clean()
	now := s.now()
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
	kinds, err := factor.ConfirmedKinds(ctx, q, c.Subject)
	if err != nil {
		return Result{}, err
	}
	if len(kinds) == 0 {
		return Result{Refusal: ErrFactorNotFound}, nil
	}
	keys := factor.DeriveKeys(s.cfg.SecondFactors.Key)
	codes, err := s.issueRecoveryCodes(ctx, q, keys, c.Subject, now)
	if err != nil {
		return Result{}, err
	}
	if err := s.record(ctx, q, now, SourceSecondFactor, events.Event{PrincipalID: &c.Subject, SessionID: &c.SessionID, ScopeID: sess.ScopeID, Audience: c.Audience, Result: ResultRecoveryCodesRegenerated, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return Result{}, err
	}
	return Result{RecoveryCodes: codes}, nil
}

func (s *Service) factorSession(ctx context.Context, q db.Querier, c *Claims, now time.Time) (session.Session, bool, error) {
	sess, err := session.LockOpen(ctx, q, c.SessionID, c.Subject, now)
	if errors.Is(err, db.ErrNoRows) {
		return session.Session{}, false, nil
	}
	if err != nil {
		return session.Session{}, false, err
	}
	if now.Sub(sess.AuthenticatedAt) > s.cfg.SecondFactors.Reauth {
		return session.Session{}, false, nil
	}
	return sess, true, nil
}

func (s *Service) markSessionFactor(ctx context.Context, q db.Querier, sessionID uuid.UUID, kind FactorKind) error {
	_, err := q.Exec(ctx, `UPDATE auth_sessions SET second_factor = $2 WHERE id = $1 AND second_factor = ''`, sessionID, string(kind))
	return err
}

func (s *Service) issueRecoveryCodes(ctx context.Context, q db.Querier, keys factor.Keys, principal uuid.UUID, now time.Time) ([]string, error) {
	codes, err := factor.NewRecoveryCodes(s.cfg.Rand, s.cfg.SecondFactors.RecoveryCodes)
	if err != nil {
		return nil, err
	}
	hashes := make([][]byte, len(codes))
	for i, code := range codes {
		hashes[i] = factor.HashCode(keys.RecoveryKey, principal, "recovery", factor.NormalizeCode(code))
	}
	if err := factor.ReplaceRecoveryCodes(ctx, q, s.cfg.Rand, principal, hashes, now); err != nil {
		return nil, err
	}
	return codes, nil
}

// DisableSecondFactor turns off one of the caller's factors with a current code from any factor or a recovery code. A wrong code counts toward the login throttle. Turning off the last factor deletes the recovery codes. No session ends. Needs a recent sign-in and a transaction.
func (s *Service) DisableSecondFactor(ctx context.Context, q db.Querier, c *Claims, kind FactorKind, proof FactorProof, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if len(s.cfg.SecondFactors.Key) == 0 {
		return Result{Refusal: ErrSecondFactorsOff}, nil
	}
	if kind != FactorTOTP && kind != FactorEmail {
		return Result{Refusal: ErrFactorNotFound}, nil
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
	if !slices.Contains(confirmed, string(kind)) {
		return Result{Refusal: ErrFactorNotFound}, nil
	}
	p, err := s.principals.ByID(ctx, q, c.Subject, Audience(c.Audience))
	if err != nil {
		return Result{}, err
	}
	key := s.throttleKey(Normalize(p.Login))
	aud := string(c.Audience)
	until, locked, err := throttle.Locked(ctx, q, key, aud, now)
	if err != nil {
		return Result{}, err
	}
	if locked {
		return Result{Refusal: ErrLocked{RetryAfter: until.Sub(now)}}, nil
	}
	check, err := s.checkDisableProof(ctx, q, c, keys, confirmed, proof, now)
	if err != nil {
		return Result{}, err
	}
	switch check {
	case factor.CodeEnded:
		return Result{Refusal: ErrCodeEnded}, nil
	case factor.CodeBad:
		if err := throttle.Fail(ctx, q, key, aud, now, s.cfg.Throttle); err != nil {
			return Result{}, err
		}
		if err := s.record(ctx, q, now, SourceSecondFactor, events.Event{PrincipalID: &c.Subject, SessionID: &c.SessionID, ScopeID: sess.ScopeID, Audience: c.Audience, Result: ResultBadCode, SecondFactor: proofFactor(proof.Method), IP: m.IP, UserAgent: m.UserAgent}); err != nil {
			return Result{}, err
		}
		return Result{Refusal: ErrBadCode}, nil
	}
	if _, err := q.Exec(ctx, `DELETE FROM auth_second_factors WHERE principal_id = $1 AND kind = $2 AND confirmed_at IS NOT NULL`, c.Subject, string(kind)); err != nil {
		return Result{}, err
	}
	if kind == FactorEmail {
		if err := factor.DropEmailCodes(ctx, q, c.Subject); err != nil {
			return Result{}, err
		}
	}
	if len(confirmed) == 1 {
		if _, err := q.Exec(ctx, `DELETE FROM auth_recovery_codes WHERE principal_id = $1`, c.Subject); err != nil {
			return Result{}, err
		}
	}
	if err := s.record(ctx, q, now, SourceSecondFactor, events.Event{PrincipalID: &c.Subject, SessionID: &c.SessionID, ScopeID: sess.ScopeID, Audience: c.Audience, Result: ResultFactorRemoved, SecondFactor: string(kind), IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return Result{}, err
	}
	if proof.Method != FactorRecovery {
		return Result{}, nil
	}
	left, err := factor.RecoveryCodesLeft(ctx, q, c.Subject)
	if err != nil {
		return Result{}, err
	}
	return Result{RecoveryCodesLeft: &left}, nil
}

func (s *Service) checkDisableProof(ctx context.Context, q db.Querier, c *Claims, keys factor.Keys, confirmed []string, proof FactorProof, now time.Time) (factor.CodeCheck, error) {
	switch proof.Method {
	case FactorTOTP:
		if !slices.Contains(confirmed, string(FactorTOTP)) {
			return factor.CodeBad, nil
		}
		f, ok, err := factor.Load(ctx, q, c.Subject, string(FactorTOTP))
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
	case FactorEmail:
		if !slices.Contains(confirmed, string(FactorEmail)) {
			return factor.CodeEnded, nil
		}
		return factor.CheckEmailCode(ctx, q, keys.EmailKey, c.Subject, factor.PurposeProof, proof.Code, now, s.cfg.SecondFactors.MaxTries)
	case FactorRecovery:
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

func proofFactor(method FactorKind) string {
	switch method {
	case FactorTOTP, FactorEmail, FactorRecovery:
		return string(method)
	}
	return ""
}
