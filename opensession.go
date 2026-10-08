package authkit

import (
	"context"
	"time"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/events"
)

// OpenSession signs a principal in that the app has authenticated itself
// (an accepted invitation): Admit, a new session, signed_in. Admit's refusal
// is logged and returned. Bearer mode returns Tokens, Session mode
// SessionToken. Needs a transaction.
func (s *Service) OpenSession(ctx context.Context, q db.Querier, p Principal, aud Audience, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
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
	return s.openSignedIn(ctx, q, SourceOpenSession, grant{p: p, aud: aud, adm: adm, m: m, now: now})
}

// grant is a sign-in Admit has allowed: whom, for which audience, with what
// admission, from which request, at the method's one now.
type grant struct {
	p   Principal
	aud Audience
	adm Admission
	m   Meta
	now time.Time
}

// openSignedIn opens g's session and logs signed_in from source: the sign-in
// that OpenSession, CompleteReset and ChangePassword under RevokeAll end with.
func (s *Service) openSignedIn(ctx context.Context, q db.Querier, source string, g grant) (Result, error) {
	res, err := s.openSession(ctx, q, g.p, g.aud, g.adm, g.m, g.now)
	if err != nil {
		return Result{}, err
	}
	if err := s.record(ctx, q, g.now, source, events.Event{PrincipalID: &g.p.ID, SessionID: &res.Session.ID, ScopeID: g.adm.ScopeID,
		Audience: string(g.aud), Login: g.p.Login, Result: ResultSignedIn, IP: g.m.IP, UserAgent: g.m.UserAgent}); err != nil {
		return Result{}, err
	}
	return res, nil
}
