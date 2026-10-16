package authkit

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
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
	// AbsoluteTTLFor is AbsoluteTTL per audience: negative is no cap, zero is refused, and an absent audience uses AbsoluteTTL.
	AbsoluteTTLFor map[Audience]time.Duration
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
	// days; negative keeps them forever, and Forget then deletes a person's rows instead of unlinking them.
	EventRetention time.Duration
	// Recent is how long after a sign-in or re-verify a session may make sensitive changes, at most 10 minutes; zero means 5 minutes, and a negative value is refused.
	Recent time.Duration
	// OnEvent runs straight after authkit records an event, on the same
	// querier, so in the same transaction. Its error fails the method. Nil is none.
	OnEvent    func(ctx context.Context, q db.Querier, e Event) error
	ReuseGrace time.Duration
	Clock      Clock
	Rand       io.Reader
	// Schema is the PostgreSQL schema that holds authkit's tables; "" uses the search path, as before.
	Schema string
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
	def(&c.Recent, 5*time.Minute)
	def(&c.ReuseGrace, 30*time.Second)
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
	}{{"Session.IdleTTL", c.Session.IdleTTL}, {"ReuseGrace", c.ReuseGrace}, {"Recent", c.Recent}} {
		if d.v <= 0 {
			return fmt.Errorf("authkit: Config.%s must be positive, not %v", d.field, d.v)
		}
	}
	// WHY: a module's passkey and second-factor re-auth window is at most 10 minutes, and a module with a zero Reauth inherits Recent.
	if c.Recent > 10*time.Minute {
		return fmt.Errorf("authkit: Config.Recent must be at most 10m0s, not %v", c.Recent)
	}
	return c.checkSessions()
}

func (c Config) checkSessions() error {
	s := c.Session
	for aud, d := range c.RefreshTTLFor {
		if d <= 0 {
			return fmt.Errorf("authkit: Config.RefreshTTLFor[%q] is not positive", aud)
		}
	}
	for aud, d := range s.AbsoluteTTLFor {
		if d == 0 {
			return fmt.Errorf("authkit: Config.Session.AbsoluteTTLFor[%q] is zero; set a positive cap, or a negative one for none", aud)
		}
	}
	type pair struct {
		idleField, limitField string
		idle, limit           time.Duration
	}
	pairs := []pair{{"Session.IdleTTL", "Session.AbsoluteTTL", s.IdleTTL, s.AbsoluteTTL}}
	auds := map[Audience]bool{}
	for aud := range c.RefreshTTLFor {
		auds[aud] = true
	}
	for aud := range s.AbsoluteTTLFor {
		auds[aud] = true
	}
	for aud := range auds {
		p := pairs[0]
		if d, ok := c.RefreshTTLFor[aud]; ok {
			p.idleField, p.idle = fmt.Sprintf("RefreshTTLFor[%q]", aud), d
		}
		if d, ok := s.AbsoluteTTLFor[aud]; ok {
			p.limitField, p.limit = fmt.Sprintf("Session.AbsoluteTTLFor[%q]", aud), d
		}
		pairs = append(pairs, p)
	}
	for _, p := range pairs {
		if p.limit > 0 && p.idle > p.limit {
			return fmt.Errorf("authkit: Config.%s (%v) exceeds %s (%v)", p.idleField, p.idle, p.limitField, p.limit)
		}
		if c.Transport == TransportSession && s.RotateEvery > 0 && s.RotateEvery >= p.idle {
			return fmt.Errorf("authkit: Config.Session.RotateEvery (%v) must be shorter than %s (%v)", s.RotateEvery, p.idleField, p.idle)
		}
	}
	return nil
}
