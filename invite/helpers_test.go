package invite_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/invite"
)

const aud authkit.Audience = "staff"

const (
	addr = "ada@example.invalid"
	bob  = "bob@example.invalid"
)

type counted struct {
	db.Querier
	n *int
}

func (c counted) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	*c.n++
	return c.Querier.Exec(ctx, query, args...)
}

func (c counted) Query(ctx context.Context, query string, args ...any) (db.Rows, error) {
	*c.n++
	return c.Querier.Query(ctx, query, args...)
}

func (c counted) QueryRow(ctx context.Context, query string, args ...any) db.Row {
	*c.n++
	return c.Querier.QueryRow(ctx, query, args...)
}

type fixture struct {
	*kittest.World
	Inv *invite.Module
}

func newFixture(t *testing.T, tweaks ...func(*invite.Rules)) *fixture {
	t.Helper()
	w := kittest.New(t)
	r := invite.Rules{Create: stub}
	for _, tweak := range tweaks {
		tweak(&r)
	}
	inv, err := invite.New(w.Svc.Service, w.Svc.Password, r)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{World: w, Inv: inv}
}

func stub(context.Context, db.Querier, invite.Pending, json.RawMessage) (authkit.Principal, error) {
	return authkit.Principal{}, errors.New("invite test: Create runs only at accept")
}

func joinOK(context.Context, db.Querier, invite.Pending, authkit.Principal) error { return nil }

func req(email string) invite.Request { return invite.Request{Audience: aud, Email: email} }

func (f *fixture) invite(r invite.Request) (invite.Invited, error) {
	f.T.Helper()
	var inv invite.Invited
	var err error
	if e := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		inv, err = f.Inv.Invite(f.Ctx, q, r)
		return nil
	}); e != nil {
		f.T.Fatal(e)
	}
	return inv, err
}

func (f *fixture) resend(id uuid.UUID) (invite.Invited, error) {
	f.T.Helper()
	var inv invite.Invited
	var err error
	if e := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		inv, err = f.Inv.Resend(f.Ctx, q, id)
		return nil
	}); e != nil {
		f.T.Fatal(e)
	}
	return inv, err
}

func (f *fixture) revoke(id uuid.UUID) error {
	f.T.Helper()
	var err error
	if e := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		err = f.Inv.Revoke(f.Ctx, q, id)
		return nil
	}); e != nil {
		f.T.Fatal(e)
	}
	return err
}

func (f *fixture) list(aud authkit.Audience, scope *uuid.UUID, limit, offset int) ([]invite.Invite, int, error) {
	f.T.Helper()
	var rows []invite.Invite
	var total int
	var err error
	if e := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		rows, total, err = f.Inv.List(f.Ctx, q, aud, scope, limit, offset)
		return nil
	}); e != nil {
		f.T.Fatal(e)
	}
	return rows, total, err
}

func (f *fixture) accepted(id, by uuid.UUID) {
	f.T.Helper()
	f.D.Exec(f.T, "UPDATE auth_invites SET accepted_at = $2, accepted_by = $3 WHERE id = $1", id, f.Clock.Now(), by)
}

func (f *fixture) clean(raw string, errs ...error) {
	f.T.Helper()
	for _, err := range errs {
		if raw != "" && err != nil && strings.Contains(err.Error(), raw) {
			f.T.Error("an error carries the raw link")
		}
	}
	if n := f.Count("SELECT count(*) FROM auth_events"); n != 0 {
		f.T.Errorf("auth_events rows = %d, want 0", n)
	}
}
