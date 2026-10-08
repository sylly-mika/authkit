// Package authkit is shared authentication for Go services: password sign-in,
// sessions with rotating refresh tokens and reuse detection, password reset,
// one-time links, the sign-in log and a per-login throttle, over tables it
// owns and keys by the app's principal uuid.
//
// It never opens a transaction and never binds an RLS setting. Every Service
// method runs on the db.Querier the caller hands it, and those that write or
// lock need a transaction (db.ErrTxRequired). A refused attempt is
// Result.Refusal, not an error: Login's refusals, Refresh's reuse branch and
// VerifyPassword's bad_password write what the caller's transaction must
// commit, CompleteReset keeps the spend of a link whose owner is gone, and
// every other refusal comes before the method's first write.
package authkit

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/onetime"
	"github.com/sylly-mika/authkit/password"
	"github.com/sylly-mika/authkit/transport/bearer"
)

// Audience is an app-defined sign-in surface: "staff", "client", "admin", …
type Audience string

// Principal is the app's user as the Service sees it: its uuid and its login.
type Principal struct {
	ID    uuid.UUID
	Login string // as stored
}

// Proposal is a session about to be created (ScopeID nil), refreshed or used.
type Proposal struct {
	Principal Principal
	Audience  Audience
	ScopeID   *uuid.UUID
}

// Admission is Admit's answer for a session it allows.
type Admission struct {
	ScopeID *uuid.UUID     // the scope the session binds to
	Claims  map[string]any // the app's claims in the access token
	Context any            // the app's value for its handlers
}

// Principals is the app side of the seam (spec §5.1).
type Principals interface {
	// Lookup resolves a normalised login for an audience; ErrUnknownLogin when absent.
	// Match the normalised login exactly: folding further gives each variant
	// its own throttle budget.
	Lookup(ctx context.Context, q db.Querier, login string, aud Audience) (Principal, error)
	// ByID resolves a principal by id; ErrUnknownLogin when absent.
	ByID(ctx context.Context, q db.Querier, id uuid.UUID, aud Audience) (Principal, error)
	// Admit decides whether the principal may hold this session now. A refusal
	// is Refuse(result, err).
	Admit(ctx context.Context, q db.Querier, p Proposal) (Admission, error)
}

// ErrUnknownLogin is what Principals.Lookup and ByID return when no principal
// matches.
var ErrUnknownLogin = errors.New("authkit: unknown login")

// Refusal is an app's refusal from Admit: Result is the sign-in event result
// to log, Err what Login and Refresh hand back unchanged.
type Refusal struct {
	Result string
	Err    error
}

func (r *Refusal) Error() string {
	if r.Err == nil {
		return "authkit: refused (" + r.Result + ")"
	}
	return r.Err.Error()
}
func (r *Refusal) Unwrap() error { return r.Err }

// Refuse is how Admit refuses: result is the sign-in event to log, err the
// refusal Login and Refresh return.
func Refuse(result string, err error) error { return &Refusal{Result: result, Err: err} }

// Clock is the Service's time source: every timestamp it writes or compares
// comes from it.
type Clock interface{ Now() time.Time }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Meta is the request's client IP and user agent, stored with sessions and
// sign-in events.
type Meta struct {
	IP        string
	UserAgent string
}

// TokenPair is a session's access token and its rotating refresh token.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time // when AccessToken expires
}

// Result is what every Service method returns. Refusal is set when the attempt
// was refused; error is only for infrastructure failures.
type Result struct {
	Refusal   error
	Principal Principal
	Session   *Session
	Tokens    *TokenPair
	Admission *Admission
	TokenID   *uuid.UUID // RequestReset: the one-time link to mail
}

// Service is authkit's entry point: every flow is one of its methods, run on
// the db.Querier the caller hands it. It is safe for concurrent use when
// Config.Clock and Config.Rand are.
type Service struct {
	cfg        Config
	principals Principals
	hasher     *password.Hasher
	codec      *bearer.Codec
	links      *onetime.Store
	onVerify   func()
}

// New builds the Service. It reads no database: the app calls CheckSchema at
// startup. Zero fields take the v0.2 defaults. New refuses a nil Principals
// and every Config that check refuses, and hashing parameters NewHasher
// refuses. A Session-mode Service has no Codec.
func New(cfg Config, principals Principals) (*Service, error) {
	if principals == nil {
		return nil, errors.New("authkit: New needs the app's Principals")
	}
	cfg = withDefaults(cfg)
	if err := cfg.check(); err != nil {
		return nil, err
	}
	hasher, err := password.NewHasher(cfg.Hashing, cfg.HashConcurrency, cfg.HashWait, cfg.Rand)
	if err != nil {
		return nil, err
	}
	s := &Service{cfg: cfg, principals: principals, hasher: hasher, links: onetime.New(cfg.Clock.Now, cfg.Rand)}
	if cfg.Transport == TransportBearer {
		if s.codec, err = bearer.NewCodec(cfg.Issuer, cfg.Secret, cfg.AccessTTL, cfg.Clock.Now); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Service) now() time.Time { return s.cfg.Clock.Now() }

func (s *Service) refreshTTL(aud Audience) time.Duration {
	if d, ok := s.cfg.RefreshTTLFor[aud]; ok {
		return d
	}
	return s.cfg.Session.IdleTTL
}

// Codec parses and mints access tokens (echov5.ParseBearer; app tests); nil
// in Session mode.
func (s *Service) Codec() *bearer.Codec { return s.codec }

// OneTime is the one-time link store for the app's own purposes (invites).
func (s *Service) OneTime() *onetime.Store { return s.links }

// ResetFloor is how long a reset request answers at the least (PadSince).
func (s *Service) ResetFloor() time.Duration { return s.cfg.ResetFloor }

// CheckPassword applies the password policy alone, for an app that validates
// before it writes.
func (s *Service) CheckPassword(pw string) error { return s.cfg.Password.Check(pw) }
