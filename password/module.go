package password

import (
	"context"
	"fmt"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/onetime"
)

// Config configures the password module. A zero field takes its default.
type Config struct {
	ResetTTL               time.Duration
	ResetFloor             time.Duration
	Reset                  authkit.ResetRules
	Password               Policy
	Hashing                Params
	RevokeOnPasswordChange authkit.RevokeOnChange
	HashConcurrency        int
	HashWait               time.Duration
}

// Module signs principals in with a password and changes and resets passwords. It is safe for concurrent use.
type Module struct {
	core       *authkit.Core
	cfg        Config
	hasher     *Hasher
	links      *onetime.Store
	principals authkit.Principals
	onVerify   func()
}

// New attaches the password module to svc as "password". Zero fields of cfg take their defaults; New refuses a Config that disables a guard, hashing parameters NewHasher refuses, and a second module named "password" (authkit.ErrAttached).
func New(svc *authkit.Service, cfg Config) (*Module, error) {
	cfg = cfg.withDefaults()
	if err := cfg.check(); err != nil {
		return nil, err
	}
	core, err := svc.Attach("password")
	if err != nil {
		return nil, err
	}
	hasher, err := NewHasher(cfg.Hashing, cfg.HashConcurrency, cfg.HashWait, core.Rand())
	if err != nil {
		return nil, err
	}
	return &Module{core: core, cfg: cfg, hasher: hasher, links: svc.OneTime(), principals: core.Principals()}, nil
}

func (c Config) withDefaults() Config {
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	def(&c.ResetTTL, time.Hour)
	def(&c.ResetFloor, 500*time.Millisecond)
	def(&c.HashWait, 2*time.Second)
	if c.Password == (Policy{}) {
		c.Password = DefaultPolicy
	}
	if c.Hashing == (Params{}) {
		c.Hashing = Default
	}
	if c.HashConcurrency == 0 {
		c.HashConcurrency = 4
	}
	return c
}

func (c Config) check() error {
	if p := c.Password; p.MinRunes < 1 || p.MaxRunes < p.MinRunes {
		return fmt.Errorf("authkit: Config.Password needs 1 <= MinRunes <= MaxRunes: %+v", p)
	}
	if c.RevokeOnPasswordChange != authkit.RevokeOthers && c.RevokeOnPasswordChange != authkit.RevokeAll {
		return fmt.Errorf("authkit: Config.RevokeOnPasswordChange %d is neither RevokeOthers nor RevokeAll", c.RevokeOnPasswordChange)
	}
	for _, d := range []struct {
		field string
		v     time.Duration
	}{{"ResetTTL", c.ResetTTL}, {"ResetFloor", c.ResetFloor}, {"HashWait", c.HashWait}} {
		if d.v <= 0 {
			return fmt.Errorf("authkit: Config.%s must be positive, not %v", d.field, d.v)
		}
	}
	return nil
}

// ResetFloor is how long a reset request answers at the least (authkit.PadSince).
func (s *Module) ResetFloor() time.Duration { return s.cfg.ResetFloor }

// CheckPassword applies the password policy alone, for an app that validates
// before it writes.
func (s *Module) CheckPassword(pw string) error { return s.cfg.Password.Check(pw) }

func (s *Module) now() time.Time { return s.core.Now() }

func (s *Module) record(ctx context.Context, q db.Querier, at time.Time, src string, e authkit.Event) error {
	e.At = at
	return s.core.Record(ctx, q, src, e)
}
