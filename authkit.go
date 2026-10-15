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
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/events"
	"github.com/sylly-mika/authkit/internal/factor"
	"github.com/sylly-mika/authkit/internal/nsql"
	"github.com/sylly-mika/authkit/internal/throttle"
	"github.com/sylly-mika/authkit/migrations"
	"github.com/sylly-mika/authkit/onetime"
	"github.com/sylly-mika/authkit/session"
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
	// SecondFactor is the factor that completed the sign-in this admit is for: empty for a password alone.
	SecondFactor FactorKind
	// Source is the flow asking: one of the Source* constants.
	Source string
}

// Admission is Admit's answer for a session it allows.
type Admission struct {
	ScopeID *uuid.UUID     // the scope the session binds to
	Claims  map[string]any // the app's claims in the access token
	Context any            // the app's value for its handlers
}

// Principals is the app side of the seam.
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
// comes from it. The Service truncates the time to microseconds, the database's precision.
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
	Tokens    *TokenPair // Bearer mode
	// SessionToken (Session mode) is the raw session token to set as the
	// cookie: on a sign-in, and when AuthenticateSession rotated it. Empty
	// means the cookie stays as it is.
	SessionToken string
	Admission    *Admission
	TokenID      *uuid.UUID // RequestReset: the one-time link to mail
	// Ceremony is a passkey begin's answer.
	Ceremony *Ceremony
	// Passkey is the passkey a registration or rename wrote.
	Passkey *Passkey
	// PasskeysRemoved is how many passkeys a completed reset deleted.
	PasskeysRemoved int
	// SecondStep is set instead of a session when the sign-in needs a second factor.
	SecondStep *SecondStep
	// TOTPSetup is BeginTOTPSetup's answer.
	TOTPSetup *TOTPSetup
	// EmailCode names an emailed code the app must send.
	EmailCode *EmailCodeRequest
	// RecoveryCodes are new recovery codes, shown once.
	RecoveryCodes []string
	// RecoveryCodesLeft is set when a recovery code was spent.
	RecoveryCodesLeft *int
}

// Claims is the session the Result names, as the account methods take it
// (Logout, ListSessions, RevokeSession, ChangePassword): Subject, SessionID
// and Audience. Nil when the Result has no Session.
func (r Result) Claims() *Claims {
	if r.Session == nil {
		return nil
	}
	return &Claims{Subject: r.Session.PrincipalID, SessionID: r.Session.ID, Audience: r.Session.Audience}
}

// Service is authkit's entry point: every flow is one of its methods, run on
// the db.Querier the caller hands it. It is safe for concurrent use when
// Config.Clock and Config.Rand are.
type Service struct {
	cfg        Config
	principals Principals
	names      *nsql.Names
	codec      *bearer.Codec
	links      *onetime.Store
	mu         sync.Mutex
	attached   map[string]bool
	verifier   SecondStepVerifier
}

// New builds the Service. It reads no database: the app calls CheckSchema at
// startup. Zero fields take their defaults. New refuses a nil Principals
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
	if cfg.Schema != "" {
		if err := nsql.Check(cfg.Schema); err != nil {
			return nil, err
		}
	}
	var err error
	s := &Service{cfg: cfg, principals: principals, names: nsql.NewNames(cfg.Schema), attached: map[string]bool{}}
	if cfg.Schema != "" {
		s.principals = plainPrincipals{app: principals}
	}
	if s.links, err = onetime.NewIn(cfg.Schema, s.now, cfg.Rand); err != nil {
		return nil, err
	}
	if cfg.Transport == TransportBearer {
		if s.codec, err = bearer.NewCodec(cfg.Issuer, cfg.Secret, cfg.AccessTTL, s.now); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Attach registers a module by name and returns its Core. Call it at startup, once per name; a taken name is ErrAttached.
func (s *Service) Attach(name string) (*Core, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == "" {
		return nil, errors.New("authkit: Attach needs a module name")
	}
	if s.attached[name] {
		return nil, ErrAttached
	}
	s.attached[name] = true
	return &Core{s: s, name: name}, nil
}

// WHY: PostgreSQL stores timestamptz at microseconds, so a value written and read back must compare the same in Go.
func (s *Service) now() time.Time { return s.cfg.Clock.Now().Truncate(time.Microsecond) }

// WHY: every expires_at predicate relies on this clamp to enforce the cap.
func (s *Service) expiry(now time.Time, aud Audience, absolute *time.Time) time.Time {
	idle := s.cfg.Session.IdleTTL
	if d, ok := s.cfg.RefreshTTLFor[aud]; ok {
		idle = d
	}
	if exp := now.Add(idle); absolute == nil || exp.Before(*absolute) {
		return exp
	}
	return *absolute
}

func (s *Service) absoluteFrom(now time.Time) *time.Time {
	if s.cfg.Session.AbsoluteTTL < 0 {
		return nil
	}
	at := now.Add(s.cfg.Session.AbsoluteTTL)
	return &at
}

// Codec parses and mints access tokens (echov5.ParseBearer; app tests); nil
// in Session mode.
func (s *Service) Codec() *bearer.Codec { return s.codec }

// OneTime is the one-time link store for the app's own purposes (invites).
func (s *Service) OneTime() *onetime.Store { return s.links }

// CheckSchema refuses a database whose auth_schema.version is older than this
// library's migrations. The app calls it once at startup. With Config.Schema
// set, call Service.CheckSchema.
func CheckSchema(ctx context.Context, q db.Querier) error {
	return checkSchema(ctx, q, "auth_schema")
}

// CheckSchema checks the tables in this Service's Config.Schema as the package func CheckSchema checks the search path.
func (s *Service) CheckSchema(ctx context.Context, q db.Querier) error {
	q = s.names.Q(q)
	return checkSchema(ctx, q, nsql.Rewrite(s.cfg.Schema, "auth_schema"))
}

func checkSchema(ctx context.Context, q db.Querier, table string) error {
	var exists bool
	if err := q.QueryRow(ctx, `SELECT to_regclass($1::text) IS NOT NULL`, table).Scan(&exists); err != nil {
		return fmt.Errorf("authkit: look for auth_schema: %w", err)
	}
	if !exists {
		return fmt.Errorf("%w (no auth_schema table)", ErrSchemaBehind)
	}
	var v int
	err := q.QueryRow(ctx, `SELECT version FROM auth_schema WHERE id`).Scan(&v)
	if errors.Is(err, db.ErrNoRows) {
		return fmt.Errorf("%w (no auth_schema row visible; call CheckSchema with no workspace bound)", ErrSchemaBehind)
	}
	if err != nil {
		return fmt.Errorf("authkit: read auth_schema: %w", err)
	}
	if v < migrations.Version {
		return fmt.Errorf("%w (database %d, library %d)", ErrSchemaBehind, v, migrations.Version)
	}
	return nil
}

const retention = 30 * 24 * time.Hour

const ceremonyRetention = time.Hour

// Prune deletes what no flow reads any more: throttle counters
// whose window and lock have passed, sessions and one-time links dead for 30
// days, passkey ceremonies and second-step challenges an hour past their
// expiry, and sign-in events older than EventRetention unless it is negative.
// The app's worker runs it with no workspace bound.
func (s *Service) Prune(ctx context.Context, q db.Querier) error {
	q = s.names.Q(q)
	if err := db.RequireTx(q); err != nil {
		return err
	}
	now := s.now()
	if _, err := throttle.Prune(ctx, q, now, s.cfg.Throttle); err != nil {
		return err
	}
	if _, err := session.Prune(ctx, q, now.Add(-retention)); err != nil {
		return err
	}
	if s.cfg.EventRetention > 0 {
		if _, err := events.Prune(ctx, q, now.Add(-s.cfg.EventRetention)); err != nil {
			return err
		}
	}
	// WHY: the same DELETE as ceremony.Prune, so the core does not import the passkey ceremony package.
	if _, err := q.Exec(ctx, `DELETE FROM auth_passkey_ceremonies WHERE expires_at < $1`, now.Add(-ceremonyRetention)); err != nil {
		return err
	}
	if _, err := factor.PruneChallenges(ctx, q, now.Add(-ceremonyRetention)); err != nil {
		return err
	}
	_, err := s.links.Prune(ctx, q, now.Add(-retention))
	return err
}

// PadSince sleeps until floor has passed since start. The app's
// reset-request handler calls it after its transaction commits, so a known
// and an unknown email take as long.
func PadSince(start time.Time, floor time.Duration) {
	if d := floor - time.Since(start); d > 0 {
		time.Sleep(d)
	}
}

// Ceremony is a passkey begin's answer: the id the finish sends back, the options for navigator.credentials, and when it expires.
type Ceremony struct {
	ID        string
	Options   json.RawMessage
	ExpiresAt time.Time
}

// Passkey is one of a principal's registered passkeys as the app lists it.
type Passkey struct {
	ID         uuid.UUID
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	BackedUp   bool
}
