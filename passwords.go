package authkit

import (
	"context"
	"errors"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/events"
	"github.com/sylly-mika/authkit/session"
)

// ChangePassword replaces the caller's password (spec §7, §8.10) on the
// caller's own transaction, normally on the pinned connection. Both argon2id
// steps run before any lock. Then it locks the credential and the session in
// that order, the order CompleteReset writes them in, and every refusal comes
// before the first write. A reset that lands after the verify answers
// ErrCurrentPasswordWrong; a revoke, ErrSessionEnded.
func (s *Service) ChangePassword(ctx context.Context, q db.Querier, c *Claims, current, next string, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	m = m.clean()
	checked, has, err := credentialOf(ctx, q, c.Subject)
	if err != nil {
		return Result{}, err
	}
	ok, err := s.verify(ctx, checked, has, current)
	if errors.Is(err, ErrBusy) {
		return Result{Refusal: ErrBusy}, nil
	}
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{Refusal: ErrCurrentPasswordWrong}, nil
	}
	if err := s.cfg.Password.Check(next); err != nil {
		return Result{Refusal: err}, nil
	}
	hash, err := s.hasher.Hash(ctx, next)
	if errors.Is(err, ErrBusy) {
		return Result{Refusal: ErrBusy}, nil
	}
	if err != nil {
		return Result{}, err
	}
	now := s.now()
	locked, has, err := lockCredential(ctx, q, c.Subject)
	if err != nil {
		return Result{}, err
	}
	if !has || locked != checked {
		return Result{Refusal: ErrCurrentPasswordWrong}, nil
	}
	sess, err := session.LockOpen(ctx, q, c.SessionID, c.Subject, now)
	if errors.Is(err, db.ErrNoRows) {
		return Result{Refusal: ErrSessionEnded}, nil
	}
	if err != nil {
		return Result{}, err
	}
	p, err := s.principals.ByID(ctx, q, c.Subject, Audience(sess.Audience))
	if err != nil {
		return Result{}, err
	}
	if err := setCredential(ctx, q, p.ID, hash, now); err != nil {
		return Result{}, err
	}
	if err := session.RevokeOthers(ctx, q, p.ID, sess.ID, ReasonPasswordChanged, now); err != nil {
		return Result{}, err
	}
	if err := session.SetAuthenticated(ctx, q, sess.ID, now); err != nil {
		return Result{}, err
	}
	sess.AuthenticatedAt = now
	result := ResultPasswordChanged
	if s.cfg.Events.ChangeLogsReset {
		result = ResultPasswordReset
	}
	return Result{Principal: p, Session: &sess}, s.record(ctx, q, now, SourceChangePassword, events.Event{PrincipalID: &p.ID,
		SessionID: &sess.ID, ScopeID: sess.ScopeID, Audience: sess.Audience, Login: p.Login, Result: result, IP: m.IP, UserAgent: m.UserAgent})
}

// SetPassword gives a principal without a password its first one inside the
// app's own flow (ino-tasks: accepting an invite creates the user, then calls
// this in the same transaction) and logs password_set. It revokes nothing, so
// replacing a password goes through ChangePassword or CompleteReset.
func (s *Service) SetPassword(ctx context.Context, q db.Querier, p Principal, aud Audience, pw string, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	m = m.clean()
	if err := s.cfg.Password.Check(pw); err != nil {
		return Result{Refusal: err}, nil
	}
	hash, err := s.hasher.Hash(ctx, pw)
	if errors.Is(err, ErrBusy) {
		return Result{Refusal: ErrBusy}, nil
	}
	if err != nil {
		return Result{}, err
	}
	now := s.now()
	_, had, err := credentialOf(ctx, q, p.ID)
	if err != nil {
		return Result{}, err
	}
	if err := setCredential(ctx, q, p.ID, hash, now); err != nil {
		return Result{}, err
	}
	result := ResultPasswordSet
	if had {
		result = ResultPasswordReset
	}
	return Result{Principal: p}, s.record(ctx, q, now, SourceSetPassword, events.Event{PrincipalID: &p.ID, Audience: string(aud), Login: p.Login,
		Result: result, IP: m.IP, UserAgent: m.UserAgent})
}

// VerifyPassword checks an existing principal's password inside the app's own
// flow (ino-tasks: accepting an invite with an existing account). A mismatch
// logs bad_password and is refused with ErrInvalidCredentials; the caller
// commits the event. It does not touch the throttle.
func (s *Service) VerifyPassword(ctx context.Context, q db.Querier, p Principal, aud Audience, pw string, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	m = m.clean()
	hash, has, err := credentialOf(ctx, q, p.ID)
	if err != nil {
		return Result{}, err
	}
	ok, err := s.verify(ctx, hash, has, pw)
	if errors.Is(err, ErrBusy) {
		return Result{Refusal: ErrBusy}, nil
	}
	if err != nil {
		return Result{}, err
	}
	if ok {
		return Result{Principal: p}, nil
	}
	if err := s.record(ctx, q, s.now(), SourceVerifyPassword, events.Event{PrincipalID: &p.ID, Audience: string(aud), Login: p.Login,
		Result: ResultBadPassword, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return Result{}, err
	}
	return Result{Refusal: ErrInvalidCredentials}, nil
}
