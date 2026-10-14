package authkit

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/password"
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

// PasskeyRules configure passkey sign-in. A zero RPID switches passkeys off.
type PasskeyRules struct {
	// RPID is the relying party's domain, such as "example.com": no scheme, port or path.
	RPID string
	// RPName is the name the browser shows. Zero is "authkit".
	RPName string
	// Origins lists, per audience, the pages allowed to run a ceremony, as scheme://host[:port].
	Origins map[Audience][]string
	// CeremonyTTL is how long a begun ceremony may be finished. Zero is 2 minutes.
	CeremonyTTL time.Duration
	// Reauth is how recent a sign-in must be to add or remove a passkey. Zero is 5 minutes.
	Reauth time.Duration
	// Max is the most passkeys one principal may hold. Zero is 10.
	Max int
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
	ResetTTL      time.Duration
	ResetFloor    time.Duration
	Reset         ResetRules
	Password      password.Policy
	Hashing       password.Params
	Throttle      Throttle
	// RevokeOnPasswordChange: RevokeOthers (zero) or RevokeAll.
	RevokeOnPasswordChange RevokeOnChange
	Events                 EventRules
	// EventRetention is how long Prune keeps auth_events rows. Zero is 90
	// days; negative keeps them forever.
	EventRetention time.Duration
	// OnEvent runs straight after authkit records an event, on the same
	// querier, so in the same transaction. Its error fails the method. Nil is none.
	OnEvent         func(ctx context.Context, q db.Querier, e Event) error
	HashConcurrency int
	HashWait        time.Duration
	ReuseGrace      time.Duration
	Clock           Clock
	Rand            io.Reader
	// Passkeys configure passkey sign-in; the zero value leaves passkeys off.
	Passkeys PasskeyRules
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
	def(&c.ResetTTL, time.Hour)
	def(&c.ResetFloor, 500*time.Millisecond)
	def(&c.EventRetention, 90*24*time.Hour)
	def(&c.HashWait, 2*time.Second)
	def(&c.ReuseGrace, 30*time.Second)
	if c.Passkeys.RPName == "" {
		c.Passkeys.RPName = "authkit"
	}
	def(&c.Passkeys.CeremonyTTL, 2*time.Minute)
	def(&c.Passkeys.Reauth, 5*time.Minute)
	if c.Passkeys.Max == 0 {
		c.Passkeys.Max = 10
	}
	if c.Password == (password.Policy{}) {
		c.Password = password.DefaultPolicy
	}
	if c.Hashing == (password.Params{}) {
		c.Hashing = password.Default
	}
	if c.Throttle.Failures == 0 {
		c.Throttle.Failures = 5
	}
	def(&c.Throttle.Window, 15*time.Minute)
	def(&c.Throttle.Lockout, 15*time.Minute)
	if c.HashConcurrency == 0 {
		c.HashConcurrency = 4
	}
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
	if p := c.Password; p.MinRunes < 1 || p.MaxRunes < p.MinRunes {
		return fmt.Errorf("authkit: Config.Password needs 1 <= MinRunes <= MaxRunes: %+v", p)
	}
	if c.RefreshTTL < 0 {
		return fmt.Errorf("authkit: Config.RefreshTTL must be positive, not %v", c.RefreshTTL)
	}
	if c.RevokeOnPasswordChange != RevokeOthers && c.RevokeOnPasswordChange != RevokeAll {
		return fmt.Errorf("authkit: Config.RevokeOnPasswordChange %d is neither RevokeOthers nor RevokeAll", c.RevokeOnPasswordChange)
	}
	for _, d := range []struct {
		field string
		v     time.Duration
	}{{"Session.IdleTTL", c.Session.IdleTTL}, {"ResetTTL", c.ResetTTL}, {"ResetFloor", c.ResetFloor}, {"HashWait", c.HashWait}, {"ReuseGrace", c.ReuseGrace}} {
		if d.v <= 0 {
			return fmt.Errorf("authkit: Config.%s must be positive, not %v", d.field, d.v)
		}
	}
	if err := c.Passkeys.check(); err != nil {
		return err
	}
	return c.checkSessions()
}

func (p PasskeyRules) check() error {
	if p.RPID == "" {
		if len(p.Origins) > 0 {
			return errors.New("authkit: Config.Passkeys.Origins needs Config.Passkeys.RPID")
		}
		return nil
	}
	if err := protocol.ValidateRPID(p.RPID); err != nil {
		return fmt.Errorf("authkit: Config.Passkeys.RPID %q is not a domain: %v", p.RPID, err)
	}
	if p.RPID != strings.ToLower(p.RPID) {
		return fmt.Errorf("authkit: Config.Passkeys.RPID %q must be lower case", p.RPID)
	}
	if len(p.Origins) == 0 {
		return errors.New("authkit: Config.Passkeys.Origins is empty")
	}
	seen := map[string]Audience{}
	for _, aud := range slices.Sorted(maps.Keys(p.Origins)) {
		if len(p.Origins[aud]) == 0 {
			return fmt.Errorf("authkit: Config.Passkeys.Origins[%q] is empty", aud)
		}
		for _, o := range p.Origins[aud] {
			u, err := url.Parse(o)
			if err != nil || u.Host == "" || o != u.Scheme+"://"+u.Host {
				return fmt.Errorf("authkit: Config.Passkeys.Origins[%q] %q is not an origin (scheme://host[:port])", aud, o)
			}
			if u.Scheme != "https" && !(u.Scheme == "http" && p.RPID == "localhost") {
				return fmt.Errorf("authkit: Config.Passkeys.Origins[%q] %q must use https", aud, o)
			}
			if host := u.Hostname(); host != p.RPID && !strings.HasSuffix(host, "."+p.RPID) {
				return fmt.Errorf("authkit: Config.Passkeys.Origins[%q] %q is outside RPID %q", aud, o, p.RPID)
			}
			// WHY: a surface must not accept the other surface's page.
			if prev, ok := seen[o]; ok && prev != aud {
				return fmt.Errorf("authkit: Config.Passkeys.Origins %q is listed for both %q and %q", o, prev, aud)
			}
			seen[o] = aud
		}
	}
	for _, d := range []struct {
		field string
		v     time.Duration
	}{{"CeremonyTTL", p.CeremonyTTL}, {"Reauth", p.Reauth}} {
		if d.v <= 0 || d.v > 10*time.Minute {
			return fmt.Errorf("authkit: Config.Passkeys.%s must be in (0, 10m], not %v", d.field, d.v)
		}
	}
	if p.Max < 1 || p.Max > 100 {
		return fmt.Errorf("authkit: Config.Passkeys.Max must be in [1, 100], not %d", p.Max)
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
