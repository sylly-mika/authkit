package authkit

import (
	"errors"
	"fmt"
	"time"

	"github.com/sylly-mika/authkit/internal/events"
	"github.com/sylly-mika/authkit/internal/pwerr"
	"github.com/sylly-mika/authkit/internal/throttle"
	"github.com/sylly-mika/authkit/onetime"
	"github.com/sylly-mika/authkit/session"
	"github.com/sylly-mika/authkit/transport/bearer"
)

// The refusals and errors an app maps; the second group re-exports the
// sub-packages' sentinels, so an app imports authkit alone.
var (
	ErrInvalidCredentials   = errors.New("authkit: invalid login or password")
	ErrSessionEnded         = errors.New("authkit: the session has ended")
	ErrStale                = errors.New("authkit: the session's access changed; refresh")
	ErrCurrentPasswordWrong = errors.New("authkit: the current password is wrong")
	ErrSchemaBehind         = errors.New("authkit: the database schema is older than this library; run the app's migrations")

	ErrMissingToken  = bearer.ErrMissing
	ErrInvalidToken  = bearer.ErrInvalid
	ErrWrongAudience = bearer.ErrWrongAudience
	ErrTokenUnknown  = onetime.ErrUnknown
	ErrBusy          = pwerr.ErrBusy

	// ErrAttached refuses a second module under a name already attached.
	ErrAttached = errors.New("authkit: module already attached")
)

// ErrLocked refuses a login whose throttle is locked.
type ErrLocked struct{ RetryAfter time.Duration }

func (e ErrLocked) Error() string {
	return fmt.Sprintf("authkit: too many failed sign-ins; retry in %s", e.RetryAfter)
}

// ErrResendTooSoon refuses a new emailed code asked for too soon after the last.
type ErrResendTooSoon struct{ RetryAfter time.Duration }

func (e ErrResendTooSoon) Error() string {
	return fmt.Sprintf("authkit: a code was sent moments ago; retry in %s", e.RetryAfter)
}

// ErrPasskeysOff is the error of every passkey method while passkey.Rules.RPID is empty.
var ErrPasskeysOff = errors.New("authkit: passkeys are off")

// Passkey refusals, returned in Result.Refusal.
var (
	ErrPasskeyRejected = errors.New("authkit: the passkey was not accepted")
	ErrReauthRequired  = errors.New("authkit: sign in again to change sign-in methods")
	ErrPasskeyLimit    = errors.New("authkit: the principal holds the most passkeys allowed")
	ErrPasskeyExists   = errors.New("authkit: the passkey is registered already")
	ErrPasskeyInvalid  = errors.New("authkit: the passkey registration is not valid")
	ErrPasskeyNotFound = errors.New("authkit: no such passkey")
	ErrPasskeyLabel    = errors.New("authkit: a passkey label is 1 to 64 characters, without control characters")
	ErrNoPassword      = errors.New("authkit: the account needs a password before a passkey")
)

// Second-factor refusals, returned in Result.Refusal.
var (
	ErrSecondFactorsOff = errors.New("authkit: second factors are off")
	ErrBadCode          = errors.New("authkit: the code is not valid")
	ErrChallengeEnded   = errors.New("authkit: the second-step challenge has ended; sign in again")
	ErrCodeEnded        = errors.New("authkit: the emailed code has ended; ask for a new one")
	ErrFactorExists     = errors.New("authkit: the second factor is on already")
	ErrFactorNotFound   = errors.New("authkit: no such second factor")
	ErrSetupExpired     = errors.New("authkit: the setup has expired; start it again")
	ErrNoRecoveryCodes  = errors.New("authkit: no recovery codes are left")
)

// Aliases of the sub-packages' types an app meets through the Service.
type (
	ErrTokenGone = onetime.ErrGone
	PolicyError  = pwerr.PolicyError
	Claims       = bearer.Claims
	Session      = session.Session
	Event        = events.Event
	Throttle     = throttle.Rules
)

// Sign-in event results; an app adds its own through Refuse.
const (
	ResultSignedIn      = "signed_in"
	ResultSignedOut     = "signed_out"
	ResultBadPassword   = "bad_password"
	ResultUnknownLogin  = "unknown_login"
	ResultNoPassword    = "no_password"
	ResultPasswordSet   = "password_set"
	ResultPasswordReset = "password_reset"
	ResultRevoked       = "revoked"
	ResultLocked        = "locked"
	ResultReuseDetected = "reuse_detected"
	// ResultPasswordChanged is ChangePassword's, unless Events.ChangeLogsReset.
	ResultPasswordChanged = "password_changed"
	ResultBadPasskey      = "bad_passkey"
	ResultPasskeyAdded    = "passkey_added"
	ResultPasskeyRemoved  = "passkey_removed"
	ResultPasskeysReset   = "passkeys_reset"

	ResultSecondStepRequired       = "second_step_required"
	ResultBadCode                  = "bad_code"
	ResultFactorAdded              = "factor_added"
	ResultFactorRemoved            = "factor_removed"
	ResultRecoveryCodesRegenerated = "recovery_codes_regenerated"

	ResultBadIdentity      = "bad_identity"
	ResultIdentityLinked   = "identity_linked"
	ResultIdentityUnlinked = "identity_unlinked"
	ResultRegistered       = "registered"
	ResultInviteAccepted   = "invite_accepted"
	ResultReverified       = "reverified"
	ResultEmailChanged     = "email_changed"
)

// Event.Source values: the Service method that recorded the event.
const (
	SourceLogin               = "login"
	SourceOpenSession         = "open_session"
	SourceCompleteReset       = "complete_reset"
	SourceChangePassword      = "change_password"
	SourceSetPassword         = "set_password"
	SourceVerifyPassword      = "verify_password"
	SourceLogout              = "logout"
	SourceRevokeSession       = "revoke_session"
	SourceRevokeAll           = "revoke_all"
	SourceRefresh             = "refresh"
	SourceAuthenticateSession = "authenticate_session"
	// SourceAuthenticate is the Proposal.Source of Authenticate; no event carries it.
	SourceAuthenticate    = "authenticate"
	SourcePasskeyLogin    = "passkey_login"
	SourcePasskeyRegister = "passkey_register"
	SourceDeletePasskey   = "delete_passkey"
	SourceSecondStep      = "second_step"
	SourceSecondFactor    = "second_factor"
	SourceRequestReset    = "request_reset" // RequestReset records no event; reserved
	SourceOIDC            = "oidc"
	SourceRegister        = "register"
	SourceInvite          = "invite"
	SourceReverify        = "reverify"
	SourceEmailChange     = "email_change"
)

// Revoke reasons, as auth_sessions_revoke_reason lists them.
const (
	ReasonLogout          = "logout"
	ReasonUser            = "user"
	ReasonPasswordChanged = "password_changed"
	ReasonPasswordReset   = "password_reset"
	ReasonReuseDetected   = "reuse_detected"
	// ReasonAdmin is RevokeAllSessions on an admin's or the app's behalf.
	ReasonAdmin = "admin"
	// ReasonPasskeyRemoved is DeletePasskey's: it ends the principal's other sessions.
	ReasonPasskeyRemoved = "passkey_removed"
	// ReasonIdentityRemoved is Unlink's: it ends the principal's other sessions.
	ReasonIdentityRemoved = "identity_removed"
	// ReasonEmailChanged is a confirmed email change's: it ends the principal's other sessions.
	ReasonEmailChanged = "email_changed"
)

// PurposeReset is the one-time-link purpose of RequestReset and CompleteReset.
const PurposeReset = "reset"

// PurposeRegister is the one-time-link purpose of registration links.
const PurposeRegister = "register"

// PurposeInvite is the one-time-link purpose of invite links.
const PurposeInvite = "invite"

// PurposeEmailChange is the one-time-link purpose of email-change confirmation links.
const PurposeEmailChange = "email_change"
