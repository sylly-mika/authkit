package authkit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// Login signs a principal in with its password (spec §3.2; P1 spec §7). By
// default every attempt is counted before its verification: the hash slot
// first (from ctx, or taken here), so a Busy refusal counts nothing; then the
// login's throttle row, locked until the caller commits, is counted, and an
// attempt past the limit is refused ErrLocked without a verification. Then
// the lookup, exactly one argon2id verification, Admit, the session, the
// counter cleared and signed_in. Throttle.CountAfterVerify is v0.1's order:
// check the lock, verify, count a failure. Its refusals return normally after
// writing their throttle count and event.
func (s *Service) Login(ctx context.Context, q db.Querier, aud Audience, login, pw string, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	m = m.clean()
	a := &attempt{aud: aud, key: Normalize(login), now: s.now(), m: m,
		ev: events.Event{Audience: string(aud), Login: typedLogin(login), IP: m.IP, UserAgent: m.UserAgent}}
	// A login longer than any account's is neither counted nor looked up: it
	// is unknown, so no account escapes the throttle through it.
	a.counted = utf8.RuneCountInString(a.key) <= maxLoginRunes
	if !s.cfg.Throttle.CountAfterVerify {
		held, release, err := s.hasher.Hold(ctx)
		if errors.Is(err, ErrBusy) {
			return Result{Refusal: ErrBusy}, nil
		}
		if err != nil {
			return Result{}, err
		}
		defer release()
		ctx = held
	}
	until, locked, err := s.throttled(ctx, q, a)
	if err != nil {
		return Result{}, err
	}
	if locked {
		return s.refuseLocked(ctx, q, a, until)
	}

	var p Principal
	err = ErrUnknownLogin
	if a.counted {
		p, err = s.principals.Lookup(ctx, q, a.key, aud)
	}
	known := err == nil
	if err != nil && !errors.Is(err, ErrUnknownLogin) {
		return Result{}, err
	}
	var hash string
	var hasCredential bool
	if known {
		a.ev.PrincipalID = &p.ID
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
			a.ev.Result = ResultUnknownLogin
		case !hasCredential:
			a.ev.Result = ResultNoPassword
		default:
			a.ev.Result = ResultBadPassword
		}
		return s.refuseFailed(ctx, q, a)
	}
	return s.signIn(ctx, q, a, p, hash, pw)
}

// attempt is one Login call's state.
type attempt struct {
	aud     Audience
	key     string // the normalised login
	counted bool   // false for a login too long to be any account's
	now     time.Time
	m       Meta
	ev      events.Event
}

// throttleKey is the auth_throttle key of a normalised login: its sha256 in
// hex, so the table holds no logins, unless Throttle.PlainLoginKey. Turning
// PlainLoginKey off on a running app orphans its counters; they lapse within
// Lockout and Prune deletes them.
func (s *Service) throttleKey(normalised string) string {
	if s.cfg.Throttle.PlainLoginKey {
		return normalised
	}
	sum := sha256.Sum256([]byte(normalised))
	return hex.EncodeToString(sum[:])
}

// throttled counts the attempt (count-before) or reads the lock
// (CountAfterVerify), and reports whether the login is locked.
func (s *Service) throttled(ctx context.Context, q db.Querier, a *attempt) (time.Time, bool, error) {
	switch {
	case !a.counted:
		return time.Time{}, false, nil
	case s.cfg.Throttle.CountAfterVerify:
		return throttle.Locked(ctx, q, s.throttleKey(a.key), string(a.aud), a.now)
	}
	return throttle.Count(ctx, q, s.throttleKey(a.key), string(a.aud), a.now, s.cfg.Throttle)
}

// refuseLocked logs an attempt on a locked login, verified by nobody. In the
// count-before order its event names the principal when the login resolves
// (spec §3.6); CountAfterVerify keeps v0.1's event, without one.
func (s *Service) refuseLocked(ctx context.Context, q db.Querier, a *attempt, until time.Time) (Result, error) {
	if !s.cfg.Throttle.CountAfterVerify {
		p, err := s.principals.Lookup(ctx, q, a.key, a.aud)
		switch {
		case err == nil:
			a.ev.PrincipalID = &p.ID
		case !errors.Is(err, ErrUnknownLogin):
			return Result{}, err
		}
	}
	a.ev.Result = ResultLocked
	if err := s.record(ctx, q, a.now, a.ev); err != nil {
		return Result{}, err
	}
	return Result{Refusal: ErrLocked{RetryAfter: until.Sub(a.now)}}, nil
}

// refuseFailed logs a failed verification; CountAfterVerify counts it here,
// the count-before order counted it already.
func (s *Service) refuseFailed(ctx context.Context, q db.Querier, a *attempt) (Result, error) {
	if a.counted && s.cfg.Throttle.CountAfterVerify {
		if err := throttle.Fail(ctx, q, s.throttleKey(a.key), string(a.aud), a.now, s.cfg.Throttle); err != nil {
			return Result{}, err
		}
	}
	if err := s.record(ctx, q, a.now, a.ev); err != nil {
		return Result{}, err
	}
	return Result{Refusal: ErrInvalidCredentials}, nil
}

// signIn finishes a verified attempt: Admit, the rehash, the session, the
// counter cleared and signed_in. An Admit refusal leaves the counter as it
// is: only a sign-in clears it.
func (s *Service) signIn(ctx context.Context, q db.Querier, a *attempt, p Principal, hash, pw string) (Result, error) {
	adm, refusal, err := s.admit(ctx, q, Proposal{Principal: p, Audience: a.aud})
	if err != nil {
		return Result{}, err
	}
	if refusal != nil {
		a.ev.Result = refusal.Result
		if err := s.record(ctx, q, a.now, a.ev); err != nil {
			return Result{}, err
		}
		return Result{Refusal: refusal.Err}, nil
	}
	if s.hasher.NeedsRehash(hash) {
		if err := s.rehash(ctx, q, p.ID, hash, pw); err != nil {
			return Result{}, err
		}
	}
	sess, pair, err := s.openSession(ctx, q, p, a.aud, adm, a.m, a.now)
	if err != nil {
		return Result{}, err
	}
	if err := throttle.Clear(ctx, q, s.throttleKey(a.key), string(a.aud)); err != nil {
		return Result{}, err
	}
	a.ev.Result, a.ev.SessionID, a.ev.ScopeID = ResultSignedIn, &sess.ID, adm.ScopeID
	if err := s.record(ctx, q, a.now, a.ev); err != nil {
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
