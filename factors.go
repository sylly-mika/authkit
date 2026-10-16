package authkit

import (
	"time"

	"github.com/google/uuid"
)

// FactorKind names a second factor: a stored factor, a recovery code, or a passkey or OIDC sign-in.
type FactorKind string

// The factor kinds. FactorPasskey and FactorOIDC only ever name how a session was signed in.
const (
	FactorTOTP     FactorKind = "totp"
	FactorEmail    FactorKind = "email"
	FactorRecovery FactorKind = "recovery"
	FactorPasskey  FactorKind = "passkey"
	FactorOIDC     FactorKind = "oidc"
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
