package invite_test

import (
	"errors"
	"testing"
	"time"

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
}
