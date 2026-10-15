package password

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/events"
)

// ChangePassword replaces the caller's password on the
// caller's own transaction, normally on the pinned connection. Both argon2id
// steps run before any lock. Then it locks the credential and the session in
// that order, the order CompleteReset writes them in, and every refusal comes
// before the first write. A reset that lands after the verify answers
// ErrCurrentPasswordWrong; a revoke, ErrSessionEnded. RevokeOnPasswordChange
// says whether the caller's own session survives (RevokeOthers) or is
// replaced by a new one (RevokeAll).
func (s *Module) ChangePassword(ctx context.Context, q db.Querier, c *authkit.Claims, current, next string, m authkit.Meta) (authkit.Result, error) {
	q = s.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	m = m.Clean()
	checked, has, err := credentialOf(ctx, q, c.Subject)
	if err != nil {
		return authkit.Result{}, err
	}
	ok, err := s.verify(ctx, checked, has, current)
	if errors.Is(err, ErrBusy) {
		return authkit.Result{Refusal: ErrBusy}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrCurrentPasswordWrong}, nil
	}
	if err := s.cfg.Password.Check(next); err != nil {
		return authkit.Result{Refusal: err}, nil
	}
	hash, err := s.hasher.Hash(ctx, next)
	if errors.Is(err, ErrBusy) {
		return authkit.Result{Refusal: ErrBusy}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	now := s.now()
	locked, has, err := lockCredential(ctx, q, c.Subject)
	if err != nil {
		return authkit.Result{}, err
	}
	if !has || locked != checked {
		return authkit.Result{Refusal: authkit.ErrCurrentPasswordWrong}, nil
	}
	sess, err := s.core.LockSession(ctx, q, c, now)
	if errors.Is(err, db.ErrNoRows) {
		return authkit.Result{Refusal: authkit.ErrSessionEnded}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	p, err := s.principals.ByID(ctx, q, c.Subject, authkit.Audience(sess.Audience))
	if err != nil {
		return authkit.Result{}, err
	}
	if s.cfg.RevokeOnPasswordChange == authkit.RevokeAll {
		return s.core.Reopen(ctx, q, sess.ID, p, authkit.SourceChangePassword, m, now, func(ctx context.Context, q db.Querier) error {
			if err := setCredential(ctx, q, p.ID, hash, now); err != nil {
				return err
			}
			if err := s.core.RevokeAll(ctx, q, p.ID, authkit.ReasonPasswordChanged, now); err != nil {
				return err
			}
			return s.record(ctx, q, now, authkit.SourceChangePassword, s.changeEvent(p, sess, m))
		})
	}
	if err := setCredential(ctx, q, p.ID, hash, now); err != nil {
		return authkit.Result{}, err
	}
	if err := s.core.RevokeOthers(ctx, q, p.ID, sess.ID, authkit.ReasonPasswordChanged, now); err != nil {
		return authkit.Result{}, err
	}
	if err := s.core.MarkAuthenticated(ctx, q, sess.ID, now); err != nil {
		return authkit.Result{}, err
	}
	sess.AuthenticatedAt = now
	return authkit.Result{Principal: p, Session: &sess}, s.record(ctx, q, now, authkit.SourceChangePassword, s.changeEvent(p, sess, m))
}

func (s *Module) changeEvent(p authkit.Principal, sess authkit.Session, m authkit.Meta) events.Event {
	result := authkit.ResultPasswordChanged
	if s.core.Config().Events.ChangeLogsReset {
		result = authkit.ResultPasswordReset
	}
	return events.Event{PrincipalID: &p.ID, SessionID: &sess.ID, ScopeID: sess.ScopeID, Audience: sess.Audience, Login: p.Login,
		Result: result, IP: m.IP, UserAgent: m.UserAgent}
}

// SetPassword gives a principal without a password its first one inside the
// app's own flow (for example, accepting an invite: the app creates the user,
// then calls this in the same transaction) and logs password_set. It revokes nothing, so
// replacing a password goes through ChangePassword or CompleteReset.
func (s *Module) SetPassword(ctx context.Context, q db.Querier, p authkit.Principal, aud authkit.Audience, pw string, m authkit.Meta) (authkit.Result, error) {
	q = s.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	m = m.Clean()
	if err := s.cfg.Password.Check(pw); err != nil {
		return authkit.Result{Refusal: err}, nil
	}
	hash, err := s.hasher.Hash(ctx, pw)
	if errors.Is(err, ErrBusy) {
		return authkit.Result{Refusal: ErrBusy}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	now := s.now()
	_, had, err := credentialOf(ctx, q, p.ID)
	if err != nil {
		return authkit.Result{}, err
	}
	if err := setCredential(ctx, q, p.ID, hash, now); err != nil {
		return authkit.Result{}, err
	}
	result := authkit.ResultPasswordSet
	if had {
		result = authkit.ResultPasswordReset
	}
	return authkit.Result{Principal: p}, s.record(ctx, q, now, authkit.SourceSetPassword, events.Event{PrincipalID: &p.ID, Audience: string(aud), Login: p.Login,
		Result: result, IP: m.IP, UserAgent: m.UserAgent})
}

// VerifyPassword checks an existing principal's password inside the app's own
// flow (for example, accepting an invite with an existing account). A mismatch
// logs bad_password and is refused with ErrInvalidCredentials; the caller
// commits the event. It does not touch the throttle.
func (s *Module) VerifyPassword(ctx context.Context, q db.Querier, p authkit.Principal, aud authkit.Audience, pw string, m authkit.Meta) (authkit.Result, error) {
	q = s.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	m = m.Clean()
	hash, has, err := credentialOf(ctx, q, p.ID)
	if err != nil {
		return authkit.Result{}, err
	}
	ok, err := s.verify(ctx, hash, has, pw)
	if errors.Is(err, ErrBusy) {
		return authkit.Result{Refusal: ErrBusy}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	if ok {
		return authkit.Result{Principal: p}, nil
	}
	if err := s.record(ctx, q, s.now(), authkit.SourceVerifyPassword, events.Event{PrincipalID: &p.ID, Audience: string(aud), Login: p.Login,
		Result: authkit.ResultBadPassword, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{Refusal: authkit.ErrInvalidCredentials}, nil
}

// AcquireHashSlot takes one of the Service's argon2id slots before the app
// opens its transaction. Under the returned context, Login,
// VerifyPassword, ChangePassword, CompleteReset and SetPassword hash on that
// slot and take no other, so a wait for a slot holds no connection. release
// is idempotent and always non-nil; call it when the request ends. A full
// ceiling after HashWait is Result.Refusal ErrBusy (count nothing, answer
// 503); error is only ctx's.
func (s *Module) AcquireHashSlot(ctx context.Context) (context.Context, func(), authkit.Result, error) {
	held, release, err := s.hasher.Hold(ctx)
	if errors.Is(err, ErrBusy) {
		return ctx, release, authkit.Result{Refusal: ErrBusy}, nil
	}
	if err != nil {
		return ctx, release, authkit.Result{}, err
	}
	return held, release, authkit.Result{}, nil
}

func credentialOf(ctx context.Context, q db.Querier, id uuid.UUID) (hash string, ok bool, err error) {
	return scanCredential(q.QueryRow(ctx, `SELECT password_hash FROM auth_credentials WHERE principal_id = $1`, id))
}

func lockCredential(ctx context.Context, q db.Querier, id uuid.UUID) (hash string, ok bool, err error) {
	return scanCredential(q.QueryRow(ctx, `SELECT password_hash FROM auth_credentials WHERE principal_id = $1 FOR UPDATE`, id))
}

func scanCredential(row db.Row) (string, bool, error) {
	var hash string
	err := row.Scan(&hash)
	if errors.Is(err, db.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return hash, true, nil
}

// WHY: the update is conditional on the stored hash, so a change or reset committed since the read wins.
// WHY: changed_at stays, since a rehash is not a password change.
func rehashCredential(ctx context.Context, q db.Querier, id uuid.UUID, old, hash string) error {
	_, err := q.Exec(ctx, `UPDATE auth_credentials SET password_hash = $3 WHERE principal_id = $1 AND password_hash = $2`, id, old, hash)
	return err
}

// WHY: it passes the self policy on a pinned connection and the _auth policy without one.
func setCredential(ctx context.Context, q db.Querier, id uuid.UUID, hash string, now time.Time) error {
	_, err := q.Exec(ctx, `
		INSERT INTO auth_credentials (principal_id, password_hash, changed_at) VALUES ($1, $2, $3)
		ON CONFLICT (principal_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, changed_at = EXCLUDED.changed_at`,
		id, hash, now)
	return err
}

// HasCredential reports whether the principal has a password. A bare
// connection is fine.
func (s *Module) HasCredential(ctx context.Context, q db.Querier, principal uuid.UUID) (bool, error) {
	q = s.core.Q(q)
	_, has, err := credentialOf(ctx, q, principal)
	return has, err
}
