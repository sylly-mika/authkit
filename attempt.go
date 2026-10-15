package authkit

import (
	"context"
	"errors"
	"unicode/utf8"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/events"
	"github.com/sylly-mika/authkit/internal/throttle"
)

// Attempt is one sign-in attempt, from Begin or BeginVerified to its Refuse or Commit.
type Attempt struct {
	attempt
	c      *Core
	keyed  bool
	src    string
	commit func(ctx context.Context, q db.Querier) error
}

// Begin starts a sign-in attempt for login under aud; a throttled login gets ErrLocked in Result.Refusal and no Attempt.
func (c *Core) Begin(ctx context.Context, q db.Querier, src string, aud Audience, login string, m Meta) (*Attempt, Result, error) {
	m = m.clean()
	a := &Attempt{c: c, src: src, keyed: true, attempt: attempt{aud: aud, key: Normalize(login), now: c.s.now(), m: m,
		ev: events.Event{Audience: string(aud), Login: typedLogin(login), IP: m.IP, UserAgent: m.UserAgent}}}
	a.counted = utf8.RuneCountInString(a.key) <= maxLoginRunes
	until, locked, err := c.s.throttled(ctx, q, &a.attempt)
	if err != nil {
		return nil, Result{}, err
	}
	if !locked {
		return a, Result{}, nil
	}
	if !c.s.cfg.Throttle.CountAfterVerify {
		p, err := c.s.principals.Lookup(ctx, q, a.key, aud)
		switch {
		case err == nil:
			a.ev.PrincipalID = &p.ID
		case !errors.Is(err, ErrUnknownLogin):
			return nil, Result{}, err
		}
	}
	a.ev.Result = ResultLocked
	if err := c.s.record(ctx, q, a.now, src, a.ev); err != nil {
		return nil, Result{}, err
	}
	return nil, Result{Refusal: ErrLocked{RetryAfter: until.Sub(a.now)}}, nil
}

// BeginVerified starts an attempt for a sign-in the module has already verified; it has no login to throttle.
func (c *Core) BeginVerified(src string, aud Audience, m Meta) *Attempt {
	m = m.clean()
	return &Attempt{c: c, src: src, attempt: attempt{aud: aud, now: c.s.now(), m: m, ev: events.Event{Audience: string(aud), IP: m.IP, UserAgent: m.UserAgent}}}
}

// Login returns the normalised login the attempt is for.
func (a *Attempt) Login() string { return a.key }

// Counted reports whether the attempt counts against its login's throttle.
func (a *Attempt) Counted() bool { return a.counted }

// SetPrincipal names p in the attempt's log row; nil names no principal.
func (a *Attempt) SetPrincipal(p *Principal) {
	if p == nil {
		a.ev.PrincipalID = nil
		return
	}
	a.ev.PrincipalID = &p.ID
	if !a.keyed {
		a.ev.Login = p.Login
	}
}

// Refuse ends the attempt with result, returns refusal in Result.Refusal and writes the attempt's log row.
func (a *Attempt) Refuse(ctx context.Context, q db.Querier, result string, refusal error) (Result, error) {
	s := a.c.s
	if a.keyed && a.counted && s.cfg.Throttle.CountAfterVerify {
		if err := throttle.Fail(ctx, q, s.throttleKey(a.key), string(a.aud), a.now, s.cfg.Throttle); err != nil {
			return Result{}, err
		}
	}
	a.ev.Result = result
	if err := s.record(ctx, q, a.now, a.src, a.ev); err != nil {
		return Result{}, err
	}
	return Result{Refusal: refusal}, nil
}

// Commit stores fn, the writes a sign-in of the attempt runs; it runs nothing itself.
func (a *Attempt) Commit(fn func(ctx context.Context, q db.Querier) error) {
	a.commit = fn
}
