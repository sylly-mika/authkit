package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/ceremony"
)

// BeginReverify starts a passkey assertion bound to the caller's session. Needs a transaction.
func (mod *Module) BeginReverify(ctx context.Context, q db.Querier, c *authkit.Claims) (authkit.Result, error) {
	q = mod.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	if mod.rules.RPID == "" {
		return authkit.Result{}, authkit.ErrPasskeysOff
	}
	now := mod.core.Now()
	sess, err := mod.core.LockSession(ctx, q, c, now)
	if errors.Is(err, db.ErrNoRows) {
		return authkit.Result{Refusal: authkit.ErrSessionEnded}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	aud := authkit.Audience(sess.Audience)
	rp, ok, err := mod.relyingParty(aud)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrPasskeyRejected}, nil
	}
	n, err := countPasskeys(ctx, q, c.Subject)
	if err != nil {
		return authkit.Result{}, err
	}
	if n == 0 {
		return authkit.Result{Refusal: authkit.ErrPasskeyRejected}, nil
	}
	assertion, sd, err := rp.BeginDiscoverableLogin()
	if err != nil {
		return authkit.Result{}, err
	}
	opts, err := json.Marshal(assertion)
	if err != nil {
		return authkit.Result{}, err
	}
	id, exp, err := ceremony.Create(ctx, q, mod.core.Rand(), ceremony.KindReverify, string(aud), &c.Subject, &sess.ID, *sd, now, mod.rules.CeremonyTTL)
	if err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{Ceremony: &authkit.Ceremony{ID: id, Options: opts, ExpiresAt: exp}}, nil
}

// FinishReverify checks the assertion and marks the session as just authenticated. Needs a transaction.
func (mod *Module) FinishReverify(ctx context.Context, q db.Querier, c *authkit.Claims, ceremonyID string, response []byte, m authkit.Meta) (authkit.Result, error) {
	q = mod.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return authkit.Result{}, err
	}
	if mod.rules.RPID == "" {
		return authkit.Result{}, authkit.ErrPasskeysOff
	}
	m = m.Clean()
	now := mod.core.Now()
	// WHY: DeletePasskey, ChangePassword and CompleteReset lock the credential row before session and passkey rows; without it a delete from another session deadlocks with this call.
	if _, _, err := lockCredential(ctx, q, c.Subject); err != nil {
		return authkit.Result{}, err
	}
	sess, err := mod.core.LockSession(ctx, q, c, now)
	if errors.Is(err, db.ErrNoRows) {
		return authkit.Result{Refusal: authkit.ErrSessionEnded}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	aud := authkit.Audience(sess.Audience)
	rp, ok, err := mod.relyingParty(aud)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrPasskeyRejected}, nil
	}
	p, err := mod.core.Principals().ByID(ctx, q, c.Subject, aud)
	if err != nil {
		return authkit.Result{}, err
	}
	sd, ok, err := ceremony.Spend(ctx, q, ceremony.KindReverify, string(aud), ceremonyID, &c.Subject, &sess.ID, now)
	if err != nil {
		return authkit.Result{}, err
	}
	if !ok {
		return authkit.Result{Refusal: authkit.ErrPasskeyRejected}, nil
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return mod.refuseReverify(ctx, q, sess, p, m, now)
	}
	var hit *passkeyRow
	var infraErr error
	_, cred, err := rp.ValidatePasskeyLogin(passkeyHandler(ctx, q, &hit, &infraErr), sd, parsed)
	if infraErr != nil {
		return authkit.Result{}, infraErr
	}
	if err != nil || cred.Authenticator.CloneWarning || hit.principal != c.Subject {
		return mod.refuseReverify(ctx, q, sess, p, m, now)
	}
	data, err := json.Marshal(*cred)
	if err != nil {
		return authkit.Result{}, err
	}
	if _, err := q.Exec(ctx, "UPDATE auth_passkeys SET data = $2, last_used_at = $3 WHERE id = $1", hit.id, string(data), now); err != nil {
		return authkit.Result{}, err
	}
	if err := mod.core.MarkAuthenticated(ctx, q, sess.ID, now); err != nil {
		return authkit.Result{}, err
	}
	if err := mod.core.Record(ctx, q, authkit.SourceReverify, reverifyEvent(sess, p, m, now, authkit.ResultReverified)); err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{Principal: p}, nil
}

func (mod *Module) refuseReverify(ctx context.Context, q db.Querier, sess authkit.Session, p authkit.Principal, m authkit.Meta, now time.Time) (authkit.Result, error) {
	if err := mod.core.Record(ctx, q, authkit.SourceReverify, reverifyEvent(sess, p, m, now, authkit.ResultBadPasskey)); err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{Refusal: authkit.ErrPasskeyRejected}, nil
}

func reverifyEvent(sess authkit.Session, p authkit.Principal, m authkit.Meta, now time.Time, result string) authkit.Event {
	return authkit.Event{At: now, PrincipalID: &sess.PrincipalID, SessionID: &sess.ID, ScopeID: sess.ScopeID, Audience: sess.Audience,
		Login: p.Login, Result: result, IP: m.IP, UserAgent: m.UserAgent, SecondFactor: string(authkit.FactorPasskey)}
}
