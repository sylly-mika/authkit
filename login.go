package authkit

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/events"
	"github.com/sylly-mika/authkit/internal/token"
	"github.com/sylly-mika/authkit/session"
	"github.com/sylly-mika/authkit/throttle"
	"github.com/sylly-mika/authkit/transport/bearer"
)

// Login signs a principal in with its password (spec §7 Login): normalise,
// check the throttle, look the login up, run exactly one argon2id
// verification, count and log a failure, ask Admit, then open the session,
// mint the pair, clear the throttle and log signed_in. Its refusals return
// normally after writing their throttle increment and event.
func (s *Service) Login(ctx context.Context, q db.Querier, aud Audience, login, pw string, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	m = m.clean()
	now := s.now()
	key := Normalize(login)
	ev := events.Event{Audience: string(aud), Login: typedLogin(login), IP: m.IP, UserAgent: m.UserAgent}
	// A login longer than any account's is neither counted nor looked up: it
	// is unknown, so no account escapes the throttle through it.
	counted := utf8.RuneCountInString(key) <= maxLoginRunes

	until, locked := time.Time{}, false
	if counted {
		var err error
		if until, locked, err = throttle.Locked(ctx, q, key, string(aud), now); err != nil {
			return Result{}, err
		}
	}
	if locked {
		ev.Result = ResultLocked
		if err := s.record(ctx, q, now, ev); err != nil {
			return Result{}, err
		}
		return Result{Refusal: ErrLocked{RetryAfter: until.Sub(now)}}, nil
	}

	var p Principal
	err := ErrUnknownLogin
	if counted {
		p, err = s.principals.Lookup(ctx, q, key, aud)
	}
	known := err == nil
	if err != nil && !errors.Is(err, ErrUnknownLogin) {
		return Result{}, err
	}
	var hash string
	var hasCredential bool
	if known {
		ev.PrincipalID = &p.ID
		if hash, hasCredential, err = credentialOf(ctx, q, p.ID); err != nil {
			return Result{}, err
		}
	}
	ok, err := s.verify(ctx, hash, hasCredential, pw)
	if errors.Is(err, ErrBusy) {
		return Result{Refusal: ErrBusy}, nil
	}
	if err != nil {
		return Result{}, err
	}
	if !ok {
		switch {
		case !known:
			ev.Result = ResultUnknownLogin
		case !hasCredential:
			ev.Result = ResultNoPassword
		default:
			ev.Result = ResultBadPassword
		}
		if counted {
			if err := throttle.Fail(ctx, q, key, string(aud), now, s.cfg.Throttle); err != nil {
				return Result{}, err
			}
		}
		if err := s.record(ctx, q, now, ev); err != nil {
			return Result{}, err
		}
		return Result{Refusal: ErrInvalidCredentials}, nil
	}

	adm, refusal, err := s.admit(ctx, q, Proposal{Principal: p, Audience: aud})
	if err != nil {
		return Result{}, err
	}
	if refusal != nil {
		ev.Result = refusal.Result
		if err := s.record(ctx, q, now, ev); err != nil {
			return Result{}, err
		}
		return Result{Refusal: refusal.Err}, nil
	}
	if s.hasher.NeedsRehash(hash) {
		if err := s.rehash(ctx, q, p.ID, hash, pw); err != nil {
			return Result{}, err
		}
	}
	sess, pair, err := s.openSession(ctx, q, p, aud, adm, m, now)
	if err != nil {
		return Result{}, err
	}
	if err := throttle.Clear(ctx, q, key, string(aud)); err != nil {
		return Result{}, err
	}
	ev.Result, ev.SessionID, ev.ScopeID = ResultSignedIn, &sess.ID, adm.ScopeID
	if err := s.record(ctx, q, now, ev); err != nil {
		return Result{}, err
	}
	return Result{Principal: p, Session: &sess, Tokens: &pair, Admission: &adm}, nil
}

// verify runs exactly one argon2id verification: against the stored hash, or
// the dummy when there is none (spec §8.6).
func (s *Service) verify(ctx context.Context, hash string, has bool, pw string) (bool, error) {
	if s.onVerify != nil {
		s.onVerify()
	}
	if !has {
		return false, s.hasher.VerifyDummy(ctx, pw)
	}
	return s.hasher.Verify(ctx, hash, pw)
}

// admit asks the app. A Refusal comes back as a value; any other error is an
// infrastructure failure. The admission's claims are checked for reserved
// names here, so a misbehaving app fails fast instead of minting.
func (s *Service) admit(ctx context.Context, q db.Querier, p Proposal) (Admission, *Refusal, error) {
	adm, err := s.principals.Admit(ctx, q, p)
	var refusal *Refusal
	if errors.As(err, &refusal) {
		if refusal.Err == nil {
			return Admission{}, nil, errors.New("authkit: Admit refused with a nil error; Refuse needs the error to return")
		}
		return Admission{}, refusal, nil
	}
	if err != nil {
		return Admission{}, nil, err
	}
	if err := bearer.CheckAppClaims(adm.Claims); err != nil {
		return Admission{}, nil, err
	}
	return adm, nil, nil
}

func (s *Service) record(ctx context.Context, q db.Querier, now time.Time, e events.Event) error {
	id, err := token.ID(s.cfg.Rand)
	if err != nil {
		return err
	}
	e.ID, e.At = id, now
	return events.Record(ctx, q, e)
}

func (s *Service) openSession(ctx context.Context, q db.Querier, p Principal, aud Audience, adm Admission, m Meta, now time.Time) (Session, TokenPair, error) {
	id, err := token.ID(s.cfg.Rand)
	if err != nil {
		return Session{}, TokenPair{}, err
	}
	raw, hash, err := token.New(s.cfg.Rand)
	if err != nil {
		return Session{}, TokenPair{}, err
	}
	sess := Session{ID: id, PrincipalID: p.ID, Audience: string(aud), ScopeID: adm.ScopeID, IP: m.IP, UserAgent: m.UserAgent,
		AuthenticatedAt: now, CreatedAt: now, AbsoluteExpiresAt: s.absoluteFrom(now)}
	sess.ExpiresAt = s.expiry(now, aud, sess.AbsoluteExpiresAt)
	if err := session.Create(ctx, q, sess, hash); err != nil {
		return Session{}, TokenPair{}, err
	}
	access, exp, err := s.codec.MintAt(now, p.ID, id, string(aud), adm.Claims)
	if err != nil {
		return Session{}, TokenPair{}, err
	}
	return sess, TokenPair{AccessToken: access, RefreshToken: raw, ExpiresAt: exp}, nil
}

// rehash re-encodes a password under the current parameters (spec §8.7),
// unless the stored hash changed since Login read it. A full ceiling skips
// it; the next sign-in tries again.
func (s *Service) rehash(ctx context.Context, q db.Querier, id uuid.UUID, old, pw string) error {
	hash, err := s.hasher.Hash(ctx, pw)
	if errors.Is(err, ErrBusy) {
		return nil
	}
	if err != nil {
		return err
	}
	return rehashCredential(ctx, q, id, old, hash)
}
