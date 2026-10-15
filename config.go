package authkit

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sylly-mika/authkit/db"
)

// Transport is how a Service's sessions travel. The zero value is Bearer.
type Transport int

const (
	// TransportBearer: a short-lived access token (JWT) and a rotating refresh
	// token (Login, Refresh, Authenticate); v0.1's only mode.
	TransportBearer Transport = iota
	// TransportSession: one opaque session token, carried in an HttpOnly
	// cookie and checked against the database on every request
	// (AuthenticateSession). Issuer, Secret and AccessTTL are ignored.
	TransportSession
)

// SessionRules bound a session's life. A negative duration
// switches the rule off.
type SessionRules struct {
	// IdleTTL ends a session unused for this long. Zero is 30 minutes.
	IdleTTL time.Duration
	// AbsoluteTTL ends a session this long after its sign-in, however busy.
	// Zero is 12 hours; negative is no cap.
	AbsoluteTTL time.Duration
	// RotateEvery (Session mode) replaces the session token once it is this
	// old. Zero is 15 minutes; negative never rotates.
	RotateEvery time.Duration
}

// ResetRules shape password reset.
type ResetRules struct {
	// MayCreateCredential lets a reset give a principal its first password.
	// False (the default): RequestReset creates a link only for a principal
	// that has a credential, and CompleteReset refuses, as an unknown link, to
	// set a first one.
	MayCreateCredential bool
}

// EventRules shape the sign-in log.
type EventRules struct {
	// ChangeLogsReset makes ChangePassword log password_reset, as v0.1 did,
	// instead of password_changed.
	ChangeLogsReset bool
}

// SecondFactorRules configure two-factor sign-in. An empty Key switches second factors off.
type SecondFactorRules struct {
	// Key is 32 random bytes that seal authenticator secrets and key the code hashes. Empty is off.
	Key []byte
	// Issuer names the app in authenticator apps. Zero is "authkit".
	Issuer string
	// ChallengeTTL is how long a password sign-in's second step may be finished. Zero is 10 minutes.
	ChallengeTTL time.Duration
	// EmailCodeTTL is how long an emailed code is valid. Zero is 10 minutes.
	EmailCodeTTL time.Duration
	// SetupTTL is how long a begun authenticator setup may be confirmed. Zero is 15 minutes.
	SetupTTL time.Duration
	// ResendEvery is the least time between two emailed codes. Zero is 60 seconds.
	ResendEvery time.Duration
	// Reauth is how recent a sign-in must be to change sign-in methods. Zero is 5 minutes.
	Reauth time.Duration
	// MaxTries is how many wrong codes end a second step or an emailed code. Zero is 5.
	MaxTries int
	// MaxSends is how many times one emailed code may be sent. Zero is 5.
	MaxSends int
	// RecoveryCodes is how many recovery codes one set holds. Zero is 10.
	RecoveryCodes int
}

// RevokeOnChange is which sessions ChangePassword revokes.
type RevokeOnChange int

const (
	// RevokeOthers (the default) revokes every other session and keeps the caller's.
	RevokeOthers RevokeOnChange = iota
	// RevokeAll revokes every session, the caller's included, asks Admit and
	// opens the caller a new one (Result.Tokens or Result.SessionToken).
	RevokeAll
)

// Config is built by the app from its own environment. A zero field takes its
// default; an app sets explicitly what it wants different.
type Config struct {
	Transport Transport
	Issuer    string // Bearer: required
	Secret    []byte // Bearer: at least 32 bytes
	AccessTTL time.Duration
	Session   SessionRules
	// Deprecated: RefreshTTL is Session.IdleTTL's v0.1 name. When it is set it wins.
	RefreshTTL    time.Duration
	RefreshTTLFor map[Audience]time.Duration // a per-audience IdleTTL
	Throttle      Throttle
	Events        EventRules
	// EventRetention is how long Prune keeps auth_events rows. Zero is 90
	// days; negative keeps them forever.
	EventRetention time.Duration
	// OnEvent runs straight after authkit records an event, on the same
	// querier, so in the same transaction. Its error fails the method. Nil is none.
	OnEvent    func(ctx context.Context, q db.Querier, e Event) error
	ReuseGrace time.Duration
	Clock      Clock
	Rand       io.Reader
	// SecondFactors configure two-factor sign-in; the zero value leaves it off.
	SecondFactors SecondFactorRules
}

func withDefaults(c Config) Config {
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	if c.RefreshTTL != 0 {
		c.Session.IdleTTL = c.RefreshTTL
	}
	def(&c.AccessTTL, 15*time.Minute)
	def(&c.Session.IdleTTL, 30*time.Minute)
	def(&c.Session.AbsoluteTTL, 12*time.Hour)
	def(&c.Session.RotateEvery, 15*time.Minute)
	def(&c.EventRetention, 90*24*time.Hour)
	def(&c.ReuseGrace, 30*time.Second)
	if c.SecondFactors.Issuer == "" {
		c.SecondFactors.Issuer = "authkit"
	}
	def(&c.SecondFactors.ChallengeTTL, 10*time.Minute)
	def(&c.SecondFactors.EmailCodeTTL, 10*time.Minute)
	def(&c.SecondFactors.SetupTTL, 15*time.Minute)
	def(&c.SecondFactors.ResendEvery, time.Minute)
	def(&c.SecondFactors.Reauth, 5*time.Minute)
	if c.SecondFactors.MaxTries == 0 {
		c.SecondFactors.MaxTries = 5
	}
	if c.SecondFactors.MaxSends == 0 {
		c.SecondFactors.MaxSends = 5
	}
	if c.SecondFactors.RecoveryCodes == 0 {
		c.SecondFactors.RecoveryCodes = 10
	}
	if c.Throttle.Failures == 0 {
		c.Throttle.Failures = 5
	}
	def(&c.Throttle.Window, 15*time.Minute)
	def(&c.Throttle.Lockout, 15*time.Minute)
	if c.Clock == nil {
		c.Clock = systemClock{}
	}
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	return c
}

func (c Config) check() error {
	switch c.Transport {
	case TransportBearer:
		if c.Issuer == "" {
			return errors.New("authkit: Config.Issuer is empty")
		}
		if len(c.Secret) < 32 {
			return errors.New("authkit: Config.Secret must be at least 32 bytes")
		}
	case TransportSession:
	default:
		return fmt.Errorf("authkit: Config.Transport %d is neither TransportBearer nor TransportSession", c.Transport)
	}
	if t := c.Throttle; t.Failures < 1 || t.Window <= 0 || t.Lockout <= 0 {
		return fmt.Errorf("authkit: Config.Throttle needs a positive limit, window and lockout: %+v", t)
	}
	if c.RefreshTTL < 0 {
		return fmt.Errorf("authkit: Config.RefreshTTL must be positive, not %v", c.RefreshTTL)
	}
	for _, d := range []struct {
		field string
		v     time.Duration
	}{{"Session.IdleTTL", c.Session.IdleTTL}, {"ReuseGrace", c.ReuseGrace}} {
		if d.v <= 0 {
			return fmt.Errorf("authkit: Config.%s must be positive, not %v", d.field, d.v)
		}
	}
	if err := c.SecondFactors.check(); err != nil {
		return err
	}
	return c.checkSessions()
}

func (r SecondFactorRules) check() error {
	if len(r.Key) != 0 && len(r.Key) != 32 {
		return fmt.Errorf("authkit: Config.SecondFactors.Key must be 32 bytes, not %d", len(r.Key))
	}
	// WHY: the otpauth label is Issuer:account; a colon in the issuer splits it wrongly in authenticator apps.
	if strings.Contains(r.Issuer, ":") {
		return fmt.Errorf("authkit: Config.SecondFactors.Issuer %q must not contain a colon", r.Issuer)
	}
	for _, d := range []struct {
		field string
		v     time.Duration
	}{{"ChallengeTTL", r.ChallengeTTL}, {"EmailCodeTTL", r.EmailCodeTTL}, {"SetupTTL", r.SetupTTL}} {
		if d.v <= 0 || d.v > time.Hour {
			return fmt.Errorf("authkit: Config.SecondFactors.%s must be in (0, 1h], not %v", d.field, d.v)
		}
	}
	for _, d := range []struct {
		field string
		v     time.Duration
	}{{"ResendEvery", r.ResendEvery}, {"Reauth", r.Reauth}} {
		if d.v <= 0 || d.v > 10*time.Minute {
			return fmt.Errorf("authkit: Config.SecondFactors.%s must be in (0, 10m], not %v", d.field, d.v)
		}
	}
	if r.MaxTries < 1 || r.MaxTries > 10 {
		return fmt.Errorf("authkit: Config.SecondFactors.MaxTries must be in [1, 10], not %d", r.MaxTries)
	}
	if r.MaxSends < 1 || r.MaxSends > 20 {
		return fmt.Errorf("authkit: Config.SecondFactors.MaxSends must be in [1, 20], not %d", r.MaxSends)
	}
	if r.RecoveryCodes < 8 || r.RecoveryCodes > 16 {
		return fmt.Errorf("authkit: Config.SecondFactors.RecoveryCodes must be in [8, 16], not %d", r.RecoveryCodes)
	}
	return nil
}

func (c Config) checkSessions() error {
	idle := map[string]time.Duration{"Session.IdleTTL": c.Session.IdleTTL}
	for aud, d := range c.RefreshTTLFor {
		if d <= 0 {
			return fmt.Errorf("authkit: Config.RefreshTTLFor[%q] is not positive", aud)
		}
		idle[fmt.Sprintf("RefreshTTLFor[%q]", aud)] = d
	}
	for field, d := range idle {
		if s := c.Session; s.AbsoluteTTL > 0 && d > s.AbsoluteTTL {
			return fmt.Errorf("authkit: Config.%s (%v) exceeds Session.AbsoluteTTL (%v)", field, d, s.AbsoluteTTL)
		}
		if s := c.Session; c.Transport == TransportSession && s.RotateEvery > 0 && s.RotateEvery >= d {
			return fmt.Errorf("authkit: Config.Session.RotateEvery (%v) must be shorter than %s (%v)", s.RotateEvery, field, d)
		}
	}
	return nil
}
