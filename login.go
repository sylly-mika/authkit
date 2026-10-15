package authkit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/events"
	"github.com/sylly-mika/authkit/internal/throttle"
	"github.com/sylly-mika/authkit/internal/token"
	"github.com/sylly-mika/authkit/session"
	"github.com/sylly-mika/authkit/transport/bearer"
)

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

func (s *Service) openSession(ctx context.Context, q db.Querier, p Principal, aud Audience, adm Admission, m Meta, now time.Time, factor FactorKind) (Result, error) {
	return s.openSessionAt(ctx, q, p, aud, adm, m, now, now, factor)
}

func (s *Service) openSessionAt(ctx context.Context, q db.Querier, p Principal, aud Audience, adm Admission, m Meta, now, authAt time.Time, factor FactorKind) (Result, error) {
	id, err := token.ID(s.cfg.Rand)
	if err != nil {
		return Result{}, err
	}
	raw, hash, err := token.New(s.cfg.Rand)
	if err != nil {
		return Result{}, err
	}
	sess := Session{ID: id, PrincipalID: p.ID, Audience: string(aud), ScopeID: adm.ScopeID, IP: m.IP, UserAgent: m.UserAgent,
		AuthenticatedAt: authAt, SecondFactor: string(factor), CreatedAt: now, AbsoluteExpiresAt: s.absoluteFrom(now)}
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

// Normalize is the form a login is looked up and throttled under: without
// invalid UTF-8 or NUL, trimmed, Unicode NFC, lower case. NFC runs
// again after lower-casing, so the result is NFC and Normalize is idempotent.
func Normalize(login string) string {
	return norm.NFC.String(strings.ToLower(norm.NFC.String(strings.TrimSpace(clean(login)))))
}

// WHY: Postgres text cannot hold invalid UTF-8 or NUL, so clean drops both.
func clean(s string) string { return strings.ReplaceAll(strings.ToValidUTF8(s, ""), "\x00", "") }

// WHY: auth_sessions and auth_events can store the request metadata only once cleaned.
func (m Meta) clean() Meta {
	m.IP, m.UserAgent = clean(m.IP), clean(m.UserAgent)
	return m
}

// Clean returns m with invalid UTF-8 and NUL bytes removed from IP and UserAgent.
func (m Meta) Clean() Meta { return m.clean() }

// HashToken is the stored form of a raw refresh or one-time token.
func HashToken(raw string) []byte { return token.Hash(raw) }

const maxLoginRunes = 254

func typedLogin(login string) string {
	s := clean(login)
	if r := []rune(s); len(r) > maxLoginRunes {
		return string(r[:maxLoginRunes])
	}
	return s
}
