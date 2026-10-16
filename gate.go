package authkit

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/events"
	"github.com/sylly-mika/authkit/internal/factor"
	"github.com/sylly-mika/authkit/internal/throttle"
	"github.com/sylly-mika/authkit/session"
)

// FactorPassword is the first factor of a password sign-in or reset; sessions, events and proposals store it as "".
const FactorPassword FactorKind = "password"

// SecondStepVerifier checks second-step codes for the core; the secondfactor module supplies it.
type SecondStepVerifier interface {
	Verify(ctx context.Context, q db.Querier, principal uuid.UUID, method FactorKind, code string) (ok bool, err error)
	RecoveryCodesLeft(ctx context.Context, q db.Querier, principal uuid.UUID) (int, error)
	SendCode(ctx context.Context, q db.Querier, principal uuid.UUID) (req EmailCodeRequest, retryAfter time.Duration, err error)
	ChallengeRules() (ttl time.Duration, maxTries int)
}

// SetVerifier gives the core its second-step verifier, once, before the Service serves requests.
func (c *Core) SetVerifier(v SecondStepVerifier) error {
	s := c.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if v == nil {
		return errors.New("authkit: SetVerifier needs a verifier")
	}
	if s.verifier != nil {
		return ErrAttached
	}
	s.verifier = v
	return nil
}

func sessionFactor(f FactorKind) FactorKind {
	if f == FactorPassword {
		return ""
	}
	return f
}

func (s *Service) core() *Core {
	return &Core{s: s}
}

func (s *Service) gateMethods(ctx context.Context, q db.Querier, id uuid.UUID, f FactorKind, skip bool) ([]FactorKind, bool, error) {
	if f == FactorPasskey || (f == FactorOIDC && skip) {
		return nil, false, nil
	}
	kinds, err := factor.ConfirmedKinds(ctx, q, id)
	if err != nil {
		return nil, false, err
	}
	// WHY: the verifier is checked before secondFactorMethods, which calls it.
	if len(kinds) > 0 && s.verifier == nil {
		return nil, true, nil
	}
	methods, err := s.secondFactorMethods(ctx, q, id, kinds)
	return methods, false, err
}

// WHY: an Admit refusal leaves the throttle counter as it is; only a sign-in clears it.
func (c *Core) SignIn(ctx context.Context, q db.Querier, a *Attempt, p Principal, f FactorKind) (Result, error) {
	q = c.Q(q)
	s := c.s
	ev := a.ev
	ev.PrincipalID = &p.ID
	if ev.Login == "" {
		ev.Login = p.Login
	}
	if a.src == SourceCompleteReset {
		return c.signInReset(ctx, q, a, p, ev)
	}
	adm, refusal, err := s.admit(ctx, q, Proposal{Principal: p, Audience: a.aud, SecondFactor: sessionFactor(f), Source: a.src})
	if err != nil {
		return Result{}, err
	}
	if refusal != nil {
		ev.Result = refusal.Result
		if err := s.record(ctx, q, a.now, a.src, ev); err != nil {
			return Result{}, err
		}
		return Result{Refusal: refusal.Err}, nil
	}
	methods, off, err := s.gateMethods(ctx, q, p.ID, f, a.skip)
	if err != nil {
		return Result{}, err
	}
	if off {
		return Result{Refusal: ErrSecondFactorsOff}, nil
	}
	if a.commit != nil {
		if err := a.commit(ctx, q); err != nil {
			return Result{}, err
		}
	}
	if len(methods) > 0 {
		key := a.key
		if !a.keyed {
			key = Normalize(p.Login)
		}
		return s.issueSecondStep(ctx, q, a.src, p, a.aud, "login", s.throttleKey(key), methods, adm.ScopeID, a.m, a.now)
	}
	res, err := s.openSession(ctx, q, p, a.aud, adm, a.m, a.now, sessionFactor(f))
	if err != nil {
		return Result{}, err
	}
	if a.counted {
		if err := throttle.Clear(ctx, q, s.throttleKey(a.key), string(a.aud)); err != nil {
			return Result{}, err
		}
	}
	ev.Result, ev.SessionID, ev.ScopeID, ev.SecondFactor = ResultSignedIn, &res.Session.ID, adm.ScopeID, string(sessionFactor(f))
	if err := s.record(ctx, q, a.now, a.src, ev); err != nil {
		return Result{}, err
	}
	return res, nil
}

func (c *Core) signInReset(ctx context.Context, q db.Querier, a *Attempt, p Principal, ev events.Event) (Result, error) {
	s := c.s
	methods, off, err := s.gateMethods(ctx, q, p.ID, FactorPassword, false)
	if err != nil {
		return Result{}, err
	}
	if off {
		return Result{Refusal: ErrSecondFactorsOff}, nil
	}
	var adm Admission
	if s.cfg.Transport == TransportSession || len(methods) > 0 {
		var refusal *Refusal
		if adm, refusal, err = s.admit(ctx, q, Proposal{Principal: p, Audience: a.aud, Source: SourceCompleteReset}); err != nil {
			return Result{}, err
		}
		if refusal != nil {
			ev.Result = refusal.Result
			if err := s.record(ctx, q, a.now, SourceCompleteReset, ev); err != nil {
				return Result{}, err
			}
			return Result{Refusal: refusal.Err}, nil
		}
	}
	if a.commit != nil {
		if err := a.commit(ctx, q); err != nil {
			return Result{}, err
		}
	}
	if len(methods) > 0 {
		return s.issueSecondStep(ctx, q, SourceCompleteReset, p, a.aud, "reset", s.throttleKey(Normalize(p.Login)), methods, adm.ScopeID, a.m, a.now)
	}
	if s.cfg.Transport != TransportSession {
		return Result{Principal: p}, nil
	}
	return s.openSignedIn(ctx, q, SourceCompleteReset, grant{p: p, aud: a.aud, adm: adm, m: a.m, now: a.now})
}

// WHY: Admit runs before any write, so a refusal leaves the credential and the sessions as they were.
func (c *Core) Reopen(ctx context.Context, q db.Querier, sess uuid.UUID, p Principal, src string, m Meta, now time.Time, commit func(ctx context.Context, q db.Querier) error) (Result, error) {
	q = c.Q(q)
	s := c.s
	open, err := session.LockOpen(ctx, q, sess, p.ID, now)
	if errors.Is(err, db.ErrNoRows) {
		return Result{Refusal: ErrSessionEnded}, nil
	}
	if err != nil {
		return Result{}, err
	}
	g := grant{p: p, aud: Audience(open.Audience), m: m, now: now, factor: FactorKind(open.SecondFactor)}
	adm, refusal, err := s.admit(ctx, q, Proposal{Principal: p, Audience: g.aud, ScopeID: open.ScopeID, SecondFactor: g.factor, Source: src})
	if err != nil {
		return Result{}, err
	}
	if refusal != nil {
		return Result{Refusal: refusal.Err}, nil
	}
	g.adm = adm
	if err := commit(ctx, q); err != nil {
		return Result{}, err
	}
	return s.openSignedIn(ctx, q, src, g)
}
