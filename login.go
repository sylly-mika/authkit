package authkit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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

// Login signs a principal in with its password. By
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
	// WHY: a login longer than any account's is unknown, so no account escapes the throttle through it.
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

type attempt struct {
	aud     Audience
	key     string
	counted bool
	now     time.Time
	m       Meta
	ev      events.Event
}

// WHY: the key is the sha256 of the normalised login in hex, so the table holds no logins unless Throttle.PlainLoginKey is set.
// WHY: turning PlainLoginKey off on a running app orphans its counters.
func (s *Service) throttleKey(normalised string) string {
	if s.cfg.Throttle.PlainLoginKey {
		return normalised
	}
	sum := sha256.Sum256([]byte(normalised))
	return hex.EncodeToString(sum[:])
}

func (s *Service) throttled(ctx context.Context, q db.Querier, a *attempt) (time.Time, bool, error) {
	switch {
	case !a.counted:
		return time.Time{}, false, nil
	case s.cfg.Throttle.CountAfterVerify:
		return throttle.Locked(ctx, q, s.throttleKey(a.key), string(a.aud), a.now)
	}
	return throttle.Count(ctx, q, s.throttleKey(a.key), string(a.aud), a.now, s.cfg.Throttle)
}

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
	if err := s.record(ctx, q, a.now, SourceLogin, a.ev); err != nil {
		return Result{}, err
	}
	return Result{Refusal: ErrLocked{RetryAfter: until.Sub(a.now)}}, nil
}

func (s *Service) refuseFailed(ctx context.Context, q db.Querier, a *attempt) (Result, error) {
	if a.counted && s.cfg.Throttle.CountAfterVerify {
		if err := throttle.Fail(ctx, q, s.throttleKey(a.key), string(a.aud), a.now, s.cfg.Throttle); err != nil {
			return Result{}, err
		}
	}
	if err := s.record(ctx, q, a.now, SourceLogin, a.ev); err != nil {
		return Result{}, err
	}
	return Result{Refusal: ErrInvalidCredentials}, nil
}

// WHY: an Admit refusal leaves the throttle counter as it is; only a sign-in clears it.
func (s *Service) signIn(ctx context.Context, q db.Querier, a *attempt, p Principal, hash, pw string) (Result, error) {
	adm, refusal, err := s.admit(ctx, q, Proposal{Principal: p, Audience: a.aud})
	if err != nil {
		return Result{}, err
	}
	if refusal != nil {
		a.ev.Result = refusal.Result
		if err := s.record(ctx, q, a.now, SourceLogin, a.ev); err != nil {
			return Result{}, err
		}
		return Result{Refusal: refusal.Err}, nil
	}
	if s.hasher.NeedsRehash(hash) {
		if err := s.rehash(ctx, q, p.ID, hash, pw); err != nil {
			return Result{}, err
		}
	}
	res, err := s.openSession(ctx, q, p, a.aud, adm, a.m, a.now)
	if err != nil {
		return Result{}, err
	}
	if err := throttle.Clear(ctx, q, s.throttleKey(a.key), string(a.aud)); err != nil {
		return Result{}, err
	}
	a.ev.Result, a.ev.SessionID, a.ev.ScopeID = ResultSignedIn, &res.Session.ID, adm.ScopeID
	if err := s.record(ctx, q, a.now, SourceLogin, a.ev); err != nil {
		return Result{}, err
	}
	return res, nil
}

// WHY: every login spends one verification, against the dummy when there is no hash, so unknown logins take as long as known ones.
func (s *Service) verify(ctx context.Context, hash string, has bool, pw string) (bool, error) {
	if s.onVerify != nil {
		s.onVerify()
	}
	if !has {
		return false, s.hasher.VerifyDummy(ctx, pw)
	}
	return s.hasher.Verify(ctx, hash, pw)
}

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

// WHY: record hands the event to Config.OnEvent on the same querier, so the app's mirror of it commits or rolls back with it.
func (s *Service) record(ctx context.Context, q db.Querier, now time.Time, source string, e events.Event) error {
	id, err := token.ID(s.cfg.Rand)
	if err != nil {
		return err
	}
	e.ID, e.At, e.Source = id, now, source
	if err := events.Record(ctx, q, e); err != nil {
		return err
	}
	if s.cfg.OnEvent == nil {
		return nil
	}
	if err := s.cfg.OnEvent(ctx, q, e); err != nil {
		return fmt.Errorf("authkit: OnEvent: %w", err)
	}
	return nil
}

func (s *Service) openSession(ctx context.Context, q db.Querier, p Principal, aud Audience, adm Admission, m Meta, now time.Time) (Result, error) {
	id, err := token.ID(s.cfg.Rand)
	if err != nil {
		return Result{}, err
	}
	raw, hash, err := token.New(s.cfg.Rand)
	if err != nil {
		return Result{}, err
	}
	sess := Session{ID: id, PrincipalID: p.ID, Audience: string(aud), ScopeID: adm.ScopeID, IP: m.IP, UserAgent: m.UserAgent,
		AuthenticatedAt: now, CreatedAt: now, AbsoluteExpiresAt: s.absoluteFrom(now)}
	sess.ExpiresAt = s.expiry(now, aud, sess.AbsoluteExpiresAt)
	if err := session.Create(ctx, q, sess, hash); err != nil {
		return Result{}, err
	}
	res := Result{Principal: p, Session: &sess, Admission: &adm}
	if s.cfg.Transport == TransportSession {
		res.SessionToken = raw
		return res, nil
	}
	access, exp, err := s.codec.MintAt(now, p.ID, id, string(aud), adm.Claims)
	if err != nil {
		return Result{}, err
	}
	res.Tokens = &TokenPair{AccessToken: access, RefreshToken: raw, ExpiresAt: exp}
	return res, nil
}

// WHY: the rehash is skipped unless the stored hash is still the one Login read, so a change committed since the read wins.
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
