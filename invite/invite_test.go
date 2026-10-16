package invite_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/invite"
	"github.com/sylly-mika/authkit/onetime"
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
	t.Run("Mint", func(t *testing.T) {
		var n int
		_, err := f.Inv.Mint(f.Ctx, counted{c, &n}, inv.TokenID)
		if !errors.Is(err, db.ErrTxRequired) || n != 0 {
			t.Errorf("Mint error = %v after %d statements, want ErrTxRequired and none", err, n)
		}
	})
	t.Run("Open", func(t *testing.T) {
		var n int
		_, err := f.Inv.Open(f.Ctx, counted{c, &n}, "nope")
		if errors.Is(err, db.ErrTxRequired) {
			t.Errorf("Open error = %v, want no ErrTxRequired", err)
		}
	})
}

func TestResendRetiresLink(t *testing.T) {
	f := newFixture(t)
	T0 := f.Clock.Now()
	inv, err := f.invite(req(addr))
	if err != nil {
		t.Fatal(err)
	}
	raw1 := f.minted(inv.TokenID)
	f.Clock.Advance(time.Hour)
	r, err := f.resend(inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r.TokenID == inv.TokenID {
		t.Error("Resend kept the old token")
	}
	if n := f.Count(`SELECT count(*) FROM auth_invites WHERE id = $1 AND expires_at = $2`, inv.ID, T0.Add(73*time.Hour)); n != 1 {
		t.Errorf("invite rows with the resent expiry = %d, want 1", n)
	}
	_, oerr := f.open(raw1)
	if !errors.Is(oerr, authkit.ErrTokenUnknown) {
		t.Errorf("open of the retired link error = %v, want ErrTokenUnknown", oerr)
	}
	_, merr := f.mint(inv.TokenID)
	if !errors.Is(merr, invite.ErrNothingToSend) {
		t.Errorf("mint of the retired token error = %v, want ErrNothingToSend", merr)
	}
	if n := f.Count(`SELECT count(*) FROM auth_tokens WHERE id = $1 AND revoked_at IS NOT NULL`, inv.TokenID); n != 1 {
		t.Errorf("retired token revoked rows = %d, want 1", n)
	}
	mail, err := f.mint(r.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	if !mail.Invite.ExpiresAt.Equal(T0.Add(73 * time.Hour)) {
		t.Errorf("mail invite expiry = %v, want %v", mail.Invite.ExpiresAt, T0.Add(73*time.Hour))
	}
	f.Clock.Advance(80 * time.Hour)
	r2, err := f.resend(inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n := f.Count(`SELECT count(*) FROM auth_invites WHERE id = $1 AND expires_at = $2`, inv.ID, T0.Add(153*time.Hour)); n != 1 {
		t.Errorf("invite rows with the expiry after the late resend = %d, want 1", n)
	}
	if _, err := f.open(f.minted(r2.TokenID)); err != nil {
		t.Errorf("open of the link resent after expiry: %v", err)
	}
	f.clean(raw1, oerr, merr)
}

func TestRevokeLinkRevoked(t *testing.T) {
	f := newFixture(t)
	T0 := f.Clock.Now()
	inv, err := f.invite(req(addr))
	if err != nil {
		t.Fatal(err)
	}
	raw := f.minted(inv.TokenID)
	if err := f.revoke(inv.ID); err != nil {
		t.Fatal(err)
	}
	if n := f.Count(`SELECT count(*) FROM auth_invites WHERE id = $1 AND revoked_at = $2`, inv.ID, T0); n != 1 {
		t.Errorf("invite rows revoked at T0 = %d, want 1", n)
	}
	_, oerr := f.open(raw)
	var gone authkit.ErrTokenGone
	if !errors.As(oerr, &gone) || gone.State != onetime.StateRevoked {
		t.Errorf("open of a revoked invite's link error = %v, want revoked", oerr)
	}
	_, serr := f.spend(raw)
	var spent onetime.ErrGone
	if !errors.As(serr, &spent) || spent.State != onetime.StateRevoked {
		t.Errorf("spend of a revoked invite's link error = %v, want revoked", serr)
	}
	if n := f.Count(`SELECT count(*) FROM auth_tokens WHERE owner_id = $1 AND used_at IS NULL AND revoked_at IS NOT NULL`, inv.ID); n != 1 {
		t.Errorf("revoked unspent invite tokens = %d, want 1", n)
	}
	f.clean(raw, oerr, serr)
}

func TestMintCheckVoids(t *testing.T) {
	cerr := errors.New("inviter lost authority")
	var seen invite.Pending
	f := newFixture(t, func(r *invite.Rules) {
		r.Check = func(_ context.Context, _ db.Querier, p invite.Pending) error {
			seen = p
			return cerr
		}
	})
	inv, err := f.invite(req(addr))
	if err != nil {
		t.Fatal(err)
	}
	mail, err := f.mint(inv.TokenID)
	if !errors.Is(err, invite.ErrNothingToSend) || !errors.Is(err, cerr) {
		t.Errorf("mint error = %v, want ErrNothingToSend wrapping the check's error", err)
	}
	if mail.Raw != "" {
		t.Error("mint returned a link after the check failed")
	}
	if seen.ID != inv.ID || seen.Email != addr {
		t.Errorf("Check got invite %v for %q, want %v for %q", seen.ID, seen.Email, inv.ID, addr)
	}
	if n := f.Count(`SELECT count(*) FROM auth_invites WHERE id = $1 AND revoked_at IS NOT NULL`, inv.ID); n != 1 {
		t.Errorf("invite rows revoked = %d, want 1", n)
	}
	if n := f.Count(`SELECT count(*) FROM auth_tokens WHERE id = $1 AND revoked_at IS NOT NULL AND token_hash IS NULL`, inv.TokenID); n != 1 {
		t.Errorf("invite tokens revoked without a hash = %d, want 1", n)
	}
	f.clean("", err)
}

func TestMintHeld(t *testing.T) {
	f := newFixture(t, func(r *invite.Rules) { r.Join = joinOK })
	f.User(addr, "")
	a, err := f.invite(req(addr))
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.invite(req(bob))
	if err != nil {
		t.Fatal(err)
	}
	ma, err := f.mint(a.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	if !ma.Held || ma.To != addr || ma.Raw == "" || ma.Invite.ID != a.ID {
		t.Errorf("mint for a held address: held %v, to %q, invite %v; want held, to %q, invite %v", ma.Held, ma.To, ma.Invite.ID, addr, a.ID)
	}
	mb, err := f.mint(b.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	if mb.Held {
		t.Error("mint for an unheld address reports Held")
	}
	f.clean(ma.Raw)
	f.clean(mb.Raw)
}

func TestMintNothingToSend(t *testing.T) {
	check := func(t *testing.T, f *fixture, tokenID, owner uuid.UUID) {
		t.Helper()
		_, err := f.mint(tokenID)
		if !errors.Is(err, invite.ErrNothingToSend) {
			t.Errorf("mint error = %v, want ErrNothingToSend", err)
		}
		if n := f.Count(`SELECT count(*) FROM auth_tokens WHERE owner_id = $1 AND token_hash IS NOT NULL AND used_at IS NULL AND revoked_at IS NULL`, owner); n != 0 {
			t.Errorf("live minted links = %d, want 0", n)
		}
		f.clean("", err)
	}
	t.Run("unknown", func(t *testing.T) {
		f := newFixture(t)
		check(t, f, uuid.New(), uuid.Nil)
	})
	t.Run("register", func(t *testing.T) {
		f := newFixture(t)
		inv, err := f.invite(req(addr))
		if err != nil {
			t.Fatal(err)
		}
		var rid uuid.UUID
		if e := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
			var err error
			rid, err = f.Svc.OneTime().Create(f.Ctx, q, authkit.PurposeRegister, inv.ID, time.Hour)
			return err
		}); e != nil {
			t.Fatal(e)
		}
		check(t, f, rid, inv.ID)
	})
	t.Run("superseded", func(t *testing.T) {
		f := newFixture(t)
		inv, err := f.invite(req(addr))
		if err != nil {
			t.Fatal(err)
		}
		f.minted(inv.TokenID)
		if _, err := f.resend(inv.ID); err != nil {
			t.Fatal(err)
		}
		check(t, f, inv.TokenID, inv.ID)
	})
	t.Run("spent", func(t *testing.T) {
		f := newFixture(t)
		inv, err := f.invite(req(addr))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.spend(f.minted(inv.TokenID)); err != nil {
			t.Fatal(err)
		}
		check(t, f, inv.TokenID, inv.ID)
	})
	t.Run("revoked", func(t *testing.T) {
		f := newFixture(t)
		inv, err := f.invite(req(addr))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.revoke(inv.ID); err != nil {
			t.Fatal(err)
		}
		check(t, f, inv.TokenID, inv.ID)
	})
	t.Run("accepted", func(t *testing.T) {
		f := newFixture(t)
		inv, err := f.invite(req(addr))
		if err != nil {
			t.Fatal(err)
		}
		f.accepted(inv.ID, f.User("x@example.invalid", ""))
		check(t, f, inv.TokenID, inv.ID)
	})
	t.Run("expired", func(t *testing.T) {
		f := newFixture(t)
		inv, err := f.invite(req(addr))
		if err != nil {
			t.Fatal(err)
		}
		f.Clock.Advance(72 * time.Hour)
		check(t, f, inv.TokenID, inv.ID)
	})
}

func TestOpenSpendsNothing(t *testing.T) {
	f := newFixture(t)
	s := uuid.New()
	inv, err := f.invite(invite.Request{Audience: aud, Email: addr, ScopeID: &s, Payload: json.RawMessage(`{"role":"admin"}`)})
	if err != nil {
		t.Fatal(err)
	}
	raw := f.minted(inv.TokenID)
	var errs []error
	for i := 0; i < 2; i++ {
		o, err := f.open(raw)
		errs = append(errs, err)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		var payload map[string]string
		if err := json.Unmarshal(o.Payload, &payload); err != nil || payload["role"] != "admin" {
			t.Errorf("open %d payload = %s, want role admin", i, o.Payload)
		}
		if o.ID != inv.ID || o.Email != addr || o.ScopeID == nil || *o.ScopeID != s || o.Held {
			t.Errorf("open %d = invite %v for %q, held %v; want invite %v for %q, not held", i, o.ID, o.Email, o.Held, inv.ID, addr)
		}
	}
	if n := f.Count(`SELECT count(*) FROM auth_tokens WHERE id = $1 AND used_at IS NULL`, inv.TokenID); n != 1 {
		t.Errorf("unspent link tokens after open = %d, want 1", n)
	}
	f.User(addr, "")
	o, err := f.open(raw)
	errs = append(errs, err)
	if err != nil || !o.Held {
		t.Errorf("open after the address has an account: held %v, error %v; want held", o.Held, err)
	}
	_, err = f.spend(raw)
	errs = append(errs, err)
	if err != nil {
		t.Errorf("spend after open: %v", err)
	}
	_, err = f.open("nope")
	errs = append(errs, err)
	if !errors.Is(err, authkit.ErrTokenUnknown) {
		t.Errorf("open of an unknown link error = %v, want ErrTokenUnknown", err)
	}
	b, err := f.invite(req(bob))
	if err != nil {
		t.Fatal(err)
	}
	braw := f.minted(b.TokenID)
	f.accepted(b.ID, f.User("x@example.invalid", ""))
	_, err = f.open(braw)
	errs = append(errs, err)
	var used authkit.ErrTokenGone
	if !errors.As(err, &used) || used.State != onetime.StateUsed {
		t.Errorf("open of an accepted invite's link error = %v, want used", err)
	}
	c, err := f.invite(req("carl@example.invalid"))
	if err != nil {
		t.Fatal(err)
	}
	craw := f.minted(c.TokenID)
	f.Clock.Advance(73 * time.Hour)
	_, err = f.open(craw)
	errs = append(errs, err)
	var expired authkit.ErrTokenGone
	if !errors.As(err, &expired) || expired.State != onetime.StateExpired {
		t.Errorf("open of an expired invite's link error = %v, want expired", err)
	}
	d, err := f.invite(req("dan@example.invalid"))
	if err != nil {
		t.Fatal(err)
	}
	draw := f.minted(d.TokenID)
	bare := sqldb.Conn(f.Pinned(f.User("pin@example.invalid", "")))
	_, err = f.Inv.Open(f.Ctx, bare, draw)
	errs = append(errs, err)
	if errors.Is(err, db.ErrTxRequired) {
		t.Errorf("Open on a bare pinned connection error = %v, want no ErrTxRequired", err)
	}
	f.clean(raw, errs...)
}
