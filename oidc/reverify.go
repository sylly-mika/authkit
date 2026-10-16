package oidc

import (
	"context"
	"errors"

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
