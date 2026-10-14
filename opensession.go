package authkit

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/events"
	"github.com/sylly-mika/authkit/session"
)

// OpenSession signs a principal in that the app has authenticated itself
// (an accepted invitation): Admit, a new session, signed_in. Admit's refusal
// is logged and returned. Bearer mode returns Tokens, Session mode
// SessionToken. Needs a transaction.
func (s *Service) OpenSession(ctx context.Context, q db.Querier, p Principal, aud Audience, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	return s.openFor(ctx, q, p, aud, m, time.Time{})
}

var errNotFromSession = errors.New("authkit: OpenSessionFrom: the session is not the principal's, or is for another audience")

// OpenSessionFrom is OpenSession for a workspace switch: the new session keeps session from's authenticated_at.
func (s *Service) OpenSessionFrom(ctx context.Context, q db.Querier, from uuid.UUID, p Principal, aud Audience, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	prev, err := session.Load(ctx, q, from, p.ID)
	if errors.Is(err, db.ErrNoRows) {
		return Result{}, errNotFromSession
	}
	if err != nil {
		return Result{}, err
	}
	if prev.Audience != string(aud) {
		return Result{}, errNotFromSession
	}
	return s.openFor(ctx, q, p, aud, m, prev.AuthenticatedAt)
}

func (s *Service) openFor(ctx context.Context, q db.Querier, p Principal, aud Audience, m Meta, authAt time.Time) (Result, error) {
	m = m.clean()
	now := s.now()
	adm, refusal, err := s.admit(ctx, q, Proposal{Principal: p, Audience: aud})
	if err != nil {
		return Result{}, err
	}
	if refusal != nil {
		if err := s.record(ctx, q, now, SourceOpenSession, events.Event{PrincipalID: &p.ID, Audience: string(aud), Login: p.Login,
			Result: refusal.Result, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
			return Result{}, err
		}
		return Result{Refusal: refusal.Err}, nil
	}
	return s.openSignedIn(ctx, q, SourceOpenSession, grant{p: p, aud: aud, adm: adm, m: m, now: now, authAt: authAt})
}

type grant struct {
	p      Principal
	aud    Audience
	adm    Admission
	m      Meta
	now    time.Time
	authAt time.Time
	factor FactorKind
}

func (s *Service) openSignedIn(ctx context.Context, q db.Querier, source string, g grant) (Result, error) {
	at := g.now
	if !g.authAt.IsZero() {
		at = g.authAt
	}
	res, err := s.openSessionAt(ctx, q, g.p, g.aud, g.adm, g.m, g.now, at, g.factor)
	if err != nil {
		return Result{}, err
	}
	if err := s.record(ctx, q, g.now, source, events.Event{PrincipalID: &g.p.ID, SessionID: &res.Session.ID, ScopeID: g.adm.ScopeID,
		Audience: string(g.aud), Login: g.p.Login, Result: ResultSignedIn, IP: g.m.IP, UserAgent: g.m.UserAgent, SecondFactor: string(g.factor)}); err != nil {
		return Result{}, err
	}
	return res, nil
}
