package oidc

import (
	"context"
	"errors"
	"time"

	"golang.org/x/oauth2"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// BeginReverify starts a provider round trip with prompt=login for a provider the principal has linked.
func (m *Module) BeginReverify(ctx context.Context, q db.Querier, cl *authkit.Claims, provider string) (Redirect, error) {
	qc := m.core.Q(q)
	if err := db.RequireTx(qc); err != nil {
		return Redirect{}, err
	}
	if _, ok := m.providers[provider]; !ok {
		return Redirect{}, ErrUnknownProvider
	}
	sess, err := m.core.LockSession(ctx, q, cl, m.core.Now())
	if errors.Is(err, db.ErrNoRows) {
		return Redirect{}, authkit.ErrSessionEnded
	}
	if err != nil {
		return Redirect{}, err
	}
	var linked int
	if err := qc.QueryRow(ctx, `SELECT count(*) FROM auth_identities WHERE principal_id = $1 AND provider = $2`, cl.Subject, provider).Scan(&linked); err != nil {
		return Redirect{}, err
	}
	if linked == 0 {
		return Redirect{}, ErrNotLinked
	}
	return m.begin(ctx, q, "reverify", provider, authkit.Audience(sess.Audience), &cl.Subject,
		oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
}

// FinishReverify checks that the provider signed in the linked subject just now and marks the session as just authenticated.
func (m *Module) FinishReverify(ctx context.Context, q db.Querier, cl *authkit.Claims, cb Callback, binding string, meta authkit.Meta) (authkit.Result, error) {
	qc := m.core.Q(q)
	if err := db.RequireTx(qc); err != nil {
		return authkit.Result{}, err
	}
	now := m.core.Now()
	c, err := spendReverify(ctx, qc, digest(cb.State), now)
	if err != nil {
		return authkit.Result{}, err
	}
	if c == nil {
		return refuseReverify(ctx, q, m.core.BeginVerified(authkit.SourceReverify, "", meta))
	}
	a := m.core.BeginVerified(authkit.SourceReverify, c.audience, meta)
	now = a.Now()
	if !c.principal.Valid || c.principal.UUID != cl.Subject {
		return refuseReverify(ctx, q, a)
	}
	ck, err := m.checkCallback(ctx, c, cb, binding, now)
	if errors.Is(err, ErrCancelled) {
		return authkit.Result{Refusal: ErrCancelled}, nil
	}
	if err != nil {
		return refuseReverify(ctx, q, a)
	}
	var linked int
	if err := qc.QueryRow(ctx, `SELECT count(*) FROM auth_identities WHERE principal_id = $1 AND provider = $2 AND subject = $3`, cl.Subject, c.provider, ck.tok.Subject).Scan(&linked); err != nil {
		return authkit.Result{}, err
	}
	if linked == 0 {
		return refuseReverify(ctx, q, a)
	}
	var at struct {
		AuthTime *float64 `json:"auth_time"`
	}
	if err := ck.tok.Claims(&at); err != nil {
		return refuseReverify(ctx, q, a)
	}
	if at.AuthTime != nil {
		t := time.Unix(int64(*at.AuthTime), 0)
		if now.Sub(t) > m.core.Config().Recent || t.After(now.Add(m.rules.Skew)) {
			return refuseReverify(ctx, q, a)
		}
	}
	sess, err := m.core.LockSession(ctx, q, cl, now)
	if errors.Is(err, db.ErrNoRows) {
		return authkit.Result{Refusal: authkit.ErrSessionEnded}, nil
	}
	if err != nil {
		return authkit.Result{}, err
	}
	who, err := m.core.Principals().ByID(ctx, q, cl.Subject, authkit.Audience(sess.Audience))
	if errors.Is(err, authkit.ErrUnknownLogin) {
		return refuseReverify(ctx, q, a)
	}
	if err != nil {
		return authkit.Result{}, err
	}
	if err := m.core.MarkAuthenticated(ctx, q, sess.ID, now); err != nil {
		return authkit.Result{}, err
	}
	m2 := meta.Clean()
	ev := authkit.Event{At: now, PrincipalID: &who.ID, SessionID: &sess.ID, ScopeID: sess.ScopeID, Audience: sess.Audience, Login: who.Login, Result: authkit.ResultReverified, IP: m2.IP, UserAgent: m2.UserAgent, SecondFactor: "oidc"}
	if err := m.core.Record(ctx, q, authkit.SourceReverify, ev); err != nil {
		return authkit.Result{}, err
	}
	return authkit.Result{Principal: who}, nil
}

func spendReverify(ctx context.Context, q db.Querier, stateHash []byte, now time.Time) (*ceremony, error) {
	var c ceremony
	var aud string
	err := q.QueryRow(ctx, `UPDATE auth_ceremonies SET spent_at = $2 WHERE state_hash = $1 AND kind = 'reverify' AND spent_at IS NULL AND expires_at > $2 RETURNING id, kind, provider, audience, binding_hash, nonce_hash, verifier, principal_id`,
		stateHash, now).Scan(&c.id, &c.kind, &c.provider, &aud, &c.bindingHash, &c.nonceHash, &c.verifier, &c.principal)
	if errors.Is(err, db.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.audience = authkit.Audience(aud)
	return &c, nil
}

func refuseReverify(ctx context.Context, q db.Querier, a *authkit.Attempt) (authkit.Result, error) {
	return a.Refuse(ctx, q, authkit.ResultBadIdentity, authkit.ErrInvalidCredentials)
}
