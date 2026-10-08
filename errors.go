package authkit

import (
	"errors"
	"fmt"
	"time"

	"github.com/sylly-mika/authkit/events"
	"github.com/sylly-mika/authkit/onetime"
	"github.com/sylly-mika/authkit/password"
	"github.com/sylly-mika/authkit/session"
	"github.com/sylly-mika/authkit/throttle"
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
	ErrBusy          = password.ErrBusy
)

// ErrLocked refuses a login whose throttle is locked (spec §8.9).
type ErrLocked struct{ RetryAfter time.Duration }

func (e ErrLocked) Error() string {
	return fmt.Sprintf("authkit: too many failed sign-ins; retry in %s", e.RetryAfter)
}

// Aliases of the sub-packages' types an app meets through the Service.
type (
	ErrTokenGone = onetime.ErrGone
	PolicyError  = password.PolicyError
	Claims       = bearer.Claims
	Session      = session.Session
	Event        = events.Event
	Throttle     = throttle.Rules
)

// Sign-in event results (spec §6); an app adds its own through Refuse.
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
)

// Event.Source values: the Service method that recorded the event (spec §3.7).
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
	SourceRequestReset        = "request_reset" // RequestReset records no event; reserved
)

// Revoke reasons, as auth_sessions_revoke_reason lists them.
const (
	ReasonLogout          = "logout"
	ReasonUser            = "user"
	ReasonPasswordChanged = "password_changed"
	ReasonPasswordReset   = "password_reset"
	ReasonReuseDetected   = "reuse_detected"
)

// PurposeReset is the one-time-link purpose of RequestReset and CompleteReset.
const PurposeReset = "reset"
