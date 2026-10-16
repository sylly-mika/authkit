package emailchange_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/emailchange"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/onetime"
)

const (
	ada  = "ada@example.invalid"
	pw   = "the right password"
	addr = "ada.new@example.invalid"
)

type fixture struct {
	*kittest.World
	EC      *emailchange.Module
	ID      uuid.UUID
	changes int
}

func newFixture(t *testing.T, tweaks ...func(*emailchange.Rules)) *fixture {
	t.Helper()
	f := &fixture{World: kittest.New(t)}
	r := emailchange.Rules{Change: func(ctx context.Context, q db.Querier, p authkit.Principal, newLogin string) error {
		f.changes++
		_, err := q.Exec(ctx, `UPDATE users SET email = $1 WHERE id = $2`, newLogin, p.ID)
		return err
	}}
	for _, tweak := range tweaks {
		tweak(&r)
	}
	m, err := emailchange.New(f.Svc.Service, r)
	if err != nil {
		t.Fatal(err)
	}
	f.EC, f.ID = m, f.User(ada, pw)
	return f
}

func (f *fixture) session() *authkit.Claims {
	return f.Claims(f.SignIn(ada, pw))
}

func (f *fixture) start(cl *authkit.Claims, email string) emailchange.Started {
	f.T.Helper()
	var st emailchange.Started
	err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		st, err = f.EC.Start(f.Ctx, q, cl, email)
		return err
	})
	if err != nil {
		f.T.Fatal(err)
	}
	return st
}

func (f *fixture) startFor(login, email string) emailchange.Started {
	f.T.Helper()
	var st emailchange.Started
	err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		st, err = f.EC.StartFor(f.Ctx, q, authkit.Principal{ID: f.ID, Login: login}, "staff", email)
		return err
	})
	if err != nil {
		f.T.Fatal(err)
	}
	return st
}

func (f *fixture) mint(id uuid.UUID) (emailchange.Mail, error) {
	f.T.Helper()
	var mail emailchange.Mail
	err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		mail, err = f.EC.Mint(f.Ctx, q, id)
		return err
	})
	return mail, err
}

func (f *fixture) pending() *emailchange.Pending {
	f.T.Helper()
	var p *emailchange.Pending
	err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		p, err = f.EC.Pending(f.Ctx, q, authkit.Principal{ID: f.ID})
		return err
	})
	if err != nil {
		f.T.Fatal(err)
	}
	return p
}

func (f *fixture) cancel() {
	f.T.Helper()
	err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		return f.EC.Cancel(f.Ctx, q, authkit.Principal{ID: f.ID})
	})
	if err != nil {
		f.T.Fatal(err)
	}
}

func (f *fixture) peek(raw string) onetime.Token {
	f.T.Helper()
	var tok onetime.Token
	err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
		var err error
		tok, err = f.Svc.OneTime().Peek(f.Ctx, q, raw)
		return err
	})
	if err != nil {
		f.T.Fatal(err)
	}
	return tok
}

func (f *fixture) rows() int {
	return f.Count("SELECT count(*) FROM auth_email_changes WHERE principal_id = $1", f.ID)
}

func (f *fixture) links() int {
	return f.Count("SELECT count(*) FROM auth_tokens WHERE purpose = 'email_change' AND owner_id = $1", f.ID)
}

func (f *fixture) login() string {
	f.T.Helper()
	var email string
	if err := f.D.Row(f.T, "SELECT email FROM users WHERE id = $1", f.ID).Scan(&email); err != nil {
		f.T.Fatal(err)
	}
	return email
}
