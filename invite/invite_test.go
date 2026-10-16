package invite_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/invite"
	"github.com/sylly-mika/authkit/password"
)

func TestNewRefuses(t *testing.T) {
	w := kittest.New(t)
	var nilPW *password.Module
	cases := []struct {
		name string
		pw   *password.Module
		r    invite.Rules
		want string
	}{
		{"Create", w.Svc.Password, invite.Rules{}, "invite: Rules.Create is nil"},
		{"password", nilPW, invite.Rules{Create: stub}, "invite: the password module is nil"},
		{"TTL", w.Svc.Password, invite.Rules{Create: stub, TTL: -time.Second}, "invite: Rules.TTL is negative"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := invite.New(w.Svc.Service, c.pw, c.r)
			if m != nil {
				t.Errorf("module = %v, want nil", m)
			}
			if err == nil || err.Error() != c.want {
				t.Errorf("error = %v, want %q", err, c.want)
			}
		})
	}
	t.Run("valid", func(t *testing.T) {
		m, err := invite.New(w.Svc.Service, w.Svc.Password, invite.Rules{Create: stub})
		if err != nil || m == nil {
			t.Errorf("New = (%v, %v), want a module and no error", m, err)
		}
	})
}

func TestInviteTTLDefault(t *testing.T) {
	f := newFixture(t)
	T0 := f.Clock.Now()
	inv, err := f.invite(invite.Request{Audience: aud, Email: "  Ada@Example.INVALID "})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Holder != nil {
		t.Errorf("Holder = %v, want nil", inv.Holder)
	}
	if n := f.Count(`SELECT count(*) FROM auth_invites WHERE id = $1 AND email = $2 AND payload = '{}'::jsonb AND created_at = $3 AND expires_at = $4`,
		inv.ID, addr, T0, T0.Add(72*time.Hour)); n != 1 {
		t.Errorf("invite rows with 72h expiry = %d, want 1", n)
	}
	if n := f.Count(`SELECT count(*) FROM auth_tokens WHERE id = $1 AND purpose = 'invite' AND owner_id = $2 AND token_hash IS NULL`,
		inv.TokenID, inv.ID); n != 1 {
		t.Errorf("unsent invite tokens = %d, want 1", n)
	}
	t.Run("TTL 7 days", func(t *testing.T) {
		g := newFixture(t, func(r *invite.Rules) { r.TTL = 7 * 24 * time.Hour })
		t0 := g.Clock.Now()
		b, err := g.invite(req(bob))
		if err != nil {
			t.Fatal(err)
		}
		if n := g.Count(`SELECT count(*) FROM auth_invites WHERE id = $1 AND expires_at = $2`, b.ID, t0.Add(168*time.Hour)); n != 1 {
			t.Errorf("invite rows with 168h expiry = %d, want 1", n)
		}
		if b.Holder != nil {
			t.Errorf("Holder = %v, want nil", b.Holder)
		}
	})
}

func TestInviteHolder(t *testing.T) {
	f := newFixture(t, func(r *invite.Rules) { r.Join = joinOK })
	h := f.User(addr, "")
	first, err := f.invite(req(addr))
	if err != nil {
		t.Fatal(err)
	}
	if first.Holder == nil || first.Holder.ID != h {
		t.Fatalf("Holder = %v, want principal %v", first.Holder, h)
	}
	if n := f.Count(`SELECT count(*) FROM auth_invites WHERE id = $1`, first.ID); n != 1 {
		t.Errorf("invite rows = %d, want 1", n)
	}
	if n := f.Count(`SELECT count(*) FROM auth_tokens WHERE id = $1`, first.TokenID); n != 1 {
		t.Errorf("invite tokens = %d, want 1", n)
	}
	second, err := f.invite(req(bob))
	if err != nil {
		t.Fatal(err)
	}
	if second.Holder != nil {
		t.Errorf("Holder for an unknown address = %v, want nil", second.Holder)
	}
}

func TestInviteHeldNoJoin(t *testing.T) {
	t.Run("held address refused", func(t *testing.T) {
		f := newFixture(t)
		f.User(addr, "")
		_, err := f.invite(req(addr))
		if !errors.Is(err, invite.ErrAddressHeld) {
			t.Fatalf("Invite error = %v, want ErrAddressHeld", err)
		}
		if n := f.Count(`SELECT count(*) FROM auth_invites`); n != 0 {
			t.Errorf("invite rows = %d, want 0", n)
		}
		if n := f.Count(`SELECT count(*) FROM auth_tokens WHERE purpose = 'invite'`); n != 0 {
			t.Errorf("invite tokens = %d, want 0", n)
		}
	})
	t.Run("held at resend refused", func(t *testing.T) {
		f := newFixture(t)
		T0 := f.Clock.Now()
		b, err := f.invite(req(bob))
		if err != nil {
			t.Fatal(err)
		}
		f.User(bob, "")
		f.Clock.Advance(time.Hour)
		if _, err := f.resend(b.ID); !errors.Is(err, invite.ErrAddressHeld) {
			t.Fatalf("Resend error = %v, want ErrAddressHeld", err)
		}
		if n := f.Count(`SELECT count(*) FROM auth_invites WHERE id = $1 AND expires_at = $2`, b.ID, T0.Add(72*time.Hour)); n != 1 {
			t.Errorf("invite rows with the original expiry = %d, want 1", n)
		}
		if n := f.Count(`SELECT count(*) FROM auth_tokens WHERE owner_id = $1 AND purpose = 'invite'`, b.ID); n != 1 {
			t.Errorf("invite tokens = %d, want 1", n)
		}
		if n := f.Count(`SELECT count(*) FROM auth_tokens WHERE id = $1 AND owner_id = $2 AND purpose = 'invite' AND revoked_at IS NULL`, b.TokenID, b.ID); n != 1 {
			t.Errorf("live first invite token = %d, want 1", n)
		}
	})
}

func TestInvitePending(t *testing.T) {
	f := newFixture(t)
	first, err := f.invite(req(addr))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.invite(invite.Request{Audience: aud, Email: "ADA@example.invalid"}); !errors.Is(err, invite.ErrInvitePending) {
		t.Fatalf("second invite error = %v, want ErrInvitePending", err)
	}
	if n := f.Count(`SELECT count(*) FROM auth_invites WHERE email = $1 AND scope_id IS NULL AND audience = 'staff'`, addr); n != 1 {
		t.Errorf("open invite rows = %d, want 1", n)
	}
	if n := f.Count(`SELECT count(*) FROM auth_tokens WHERE purpose = 'invite'`); n != 1 {
		t.Errorf("invite tokens = %d, want 1", n)
	}
	s := uuid.New()
	scoped, err := f.invite(invite.Request{Audience: aud, Email: addr, ScopeID: &s})
	if err != nil {
		t.Fatalf("scoped invite: %v", err)
	}
	if n := f.Count(`SELECT count(*) FROM auth_invites WHERE id = $1 AND scope_id = $2`, scoped.ID, s); n != 1 {
		t.Errorf("scoped invite rows = %d, want 1", n)
	}
	if _, err := f.invite(invite.Request{Audience: aud, Email: addr, ScopeID: &s}); !errors.Is(err, invite.ErrInvitePending) {
		t.Errorf("second scoped invite error = %v, want ErrInvitePending", err)
	}
	if _, err := f.invite(invite.Request{Audience: "client", Email: addr}); err != nil {
		t.Errorf("invite for another audience: %v", err)
	}
	if err := f.revoke(first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.invite(req(addr)); err != nil {
		t.Errorf("invite after the open one was revoked: %v", err)
	}
	if n := f.Count(`SELECT count(*) FROM auth_invites WHERE email = $1 AND scope_id IS NULL AND audience = 'staff'`, addr); n != 2 {
		t.Errorf("staff invite rows without scope = %d, want 2", n)
	}
}

func TestResendClosed(t *testing.T) {
	f := newFixture(t)
	closed, err := f.invite(req(addr))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.revoke(closed.ID); err != nil {
		t.Fatal(err)
	}
	acc, err := f.invite(req(bob))
	if err != nil {
		t.Fatal(err)
	}
	f.accepted(acc.ID, f.User("x@example.invalid", ""))
	for _, id := range []uuid.UUID{closed.ID, acc.ID, uuid.New()} {
		tokens := f.Count(`SELECT count(*) FROM auth_tokens WHERE owner_id = $1`, id)
		if _, err := f.resend(id); !errors.Is(err, invite.ErrInviteClosed) {
			t.Errorf("Resend(%v) error = %v, want ErrInviteClosed", id, err)
		}
		if err := f.revoke(id); !errors.Is(err, invite.ErrInviteClosed) {
			t.Errorf("Revoke(%v) error = %v, want ErrInviteClosed", id, err)
		}
		if n := f.Count(`SELECT count(*) FROM auth_tokens WHERE owner_id = $1`, id); n != tokens {
			t.Errorf("Resend or Revoke(%v) changed its tokens from %d to %d", id, tokens, n)
		}
	}
	if n := f.Count(`SELECT count(*) FROM auth_invites WHERE id = $1 AND accepted_at IS NOT NULL AND revoked_at IS NULL`, acc.ID); n != 1 {
		t.Errorf("accepted invite rows without revoked_at = %d, want 1", n)
	}
}

func TestResendRacesRevoke(t *testing.T) {
	f := newFixture(t)
	T0 := f.Clock.Now()
	inv, err := f.invite(req(addr))
	if err != nil {
		t.Fatal(err)
	}
	holder, err := f.D.Owner.BeginTx(f.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(f.Ctx, f.D.SQL("UPDATE auth_invites SET revoked_at = $2 WHERE id = $1"), inv.ID, T0); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		inv invite.Invited
		err error
	}
	done := make(chan answer, 1)
	go func() {
		var a answer
		if e := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
			a.inv, a.err = f.Inv.Resend(f.Ctx, q, inv.ID)
			return nil
		}); e != nil {
			a.err = e
		}
		done <- a
	}()
	f.D.WaitForLockWaiters(f.T, 1)
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	a := <-done
	if !errors.Is(a.err, invite.ErrInviteClosed) {
		t.Errorf("Resend error = %v, want ErrInviteClosed", a.err)
	}
	if n := f.Count(`SELECT count(*) FROM auth_tokens WHERE owner_id = $1 AND revoked_at IS NULL`, inv.ID); n != 1 {
		t.Errorf("live invite tokens = %d, want 1", n)
	}
	if n := f.Count(`SELECT count(*) FROM auth_invites WHERE id = $1 AND expires_at = $2`, inv.ID, T0.Add(72*time.Hour)); n != 1 {
		t.Errorf("invite rows with the original expiry = %d, want 1", n)
	}
}

func TestListStates(t *testing.T) {
	f := newFixture(t, func(r *invite.Rules) { r.TTL = time.Hour })
	e, err := f.invite(req(addr))
	if err != nil {
		t.Fatal(err)
	}
	f.Clock.Advance(2 * time.Hour)
	p, err := f.invite(req(bob))
	if err != nil {
		t.Fatal(err)
	}
	f.Clock.Advance(time.Minute)
	a, err := f.invite(req("carol@example.invalid"))
	if err != nil {
		t.Fatal(err)
	}
	f.accepted(a.ID, f.User("x@example.invalid", ""))
	f.Clock.Advance(time.Minute)
	r, err := f.invite(req("dan@example.invalid"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.revoke(r.ID); err != nil {
		t.Fatal(err)
	}
	s := uuid.New()
	if _, err := f.invite(invite.Request{Audience: aud, Email: addr, ScopeID: &s}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.invite(invite.Request{Audience: "client", Email: addr}); err != nil {
		t.Fatal(err)
	}

	rows, total, err := f.list(aud, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 {
		t.Errorf("total = %d, want 4", total)
	}
	wantIDs := []uuid.UUID{r.ID, a.ID, p.ID, e.ID}
	wantStates := []invite.State{"revoked", "accepted", "pending", "expired"}
	if len(rows) != len(wantIDs) {
		t.Fatalf("rows = %d, want %d", len(rows), len(wantIDs))
	}
	for i, row := range rows {
		if row.ID != wantIDs[i] || row.State != wantStates[i] {
			t.Errorf("row %d = (%v, %s), want (%v, %s)", i, row.ID, row.State, wantIDs[i], wantStates[i])
		}
	}
	if rows[0].RevokedAt == nil {
		t.Error("revoked row has no RevokedAt")
	}
	if rows[1].AcceptedBy == nil {
		t.Error("accepted row has no AcceptedBy")
	}

	page, total, err := f.list(aud, nil, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 {
		t.Errorf("page total = %d, want 4", total)
	}
	if len(page) != 2 || page[0].ID != a.ID || page[1].ID != p.ID {
		t.Errorf("page (limit 2, offset 1) has %d rows with the wrong ids, want the accepted and the pending invite", len(page))
	}

	scoped, total, err := f.list(aud, &s, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) != 1 || total != 1 {
		t.Errorf("scoped list = %d rows of total %d, want 1 of 1", len(scoped), total)
	}

	if _, _, err := f.list(aud, nil, -1, 0); err == nil {
		t.Error("list with a negative limit: no error")
	}
	f.clean("")
}

func TestInviteNeedsTx(t *testing.T) {
	f := newFixture(t)
	inv, err := f.invite(req(addr))
	if err != nil {
		t.Fatal(err)
	}
	c := sqldb.Conn(f.Pinned(f.User("pin@example.invalid", "")))
	t.Run("Invite", func(t *testing.T) {
		var n int
		_, err := f.Inv.Invite(f.Ctx, counted{c, &n}, req(bob))
		if !errors.Is(err, db.ErrTxRequired) || n != 0 {
			t.Errorf("Invite error = %v after %d statements, want ErrTxRequired and none", err, n)
		}
	})
	t.Run("Resend", func(t *testing.T) {
		var n int
		_, err := f.Inv.Resend(f.Ctx, counted{c, &n}, inv.ID)
		if !errors.Is(err, db.ErrTxRequired) || n != 0 {
			t.Errorf("Resend error = %v after %d statements, want ErrTxRequired and none", err, n)
		}
	})
	t.Run("Revoke", func(t *testing.T) {
		var n int
		err := f.Inv.Revoke(f.Ctx, counted{c, &n}, inv.ID)
		if !errors.Is(err, db.ErrTxRequired) || n != 0 {
			t.Errorf("Revoke error = %v after %d statements, want ErrTxRequired and none", err, n)
		}
	})
	t.Run("List", func(t *testing.T) {
		var n int
		_, _, err := f.Inv.List(f.Ctx, counted{c, &n}, aud, nil, 0, 0)
		if errors.Is(err, db.ErrTxRequired) {
			t.Errorf("List error = %v, want no ErrTxRequired", err)
		}
	})
}
