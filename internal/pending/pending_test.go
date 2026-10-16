package pending_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/internal/pending"
	"github.com/sylly-mika/authkit/onetime"
)

type fixture struct {
	t     *testing.T
	ctx   context.Context
	d     *authkittest.DB
	clock *authkittest.Clock
	links *onetime.Store
}

func setup(t *testing.T) *fixture {
	t.Helper()
	schema := os.Getenv("AUTHKIT_TEST_SCHEMA")
	var opts []authkittest.Option
	if schema != "" {
		opts = append(opts, authkittest.Schema(schema))
	}
	clock := authkittest.NewClock()
	links, err := onetime.NewIn(schema, clock.Now, authkittest.Rand(1))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, ctx: context.Background(), d: authkittest.NewDB(t, opts...), clock: clock, links: links}
}

func (f *fixture) tx(fn func(q db.Querier) error) {
	f.t.Helper()
	if err := f.d.InAuthTx(f.ctx, fn); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) create(purpose string, owner uuid.UUID, ttl time.Duration) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	f.tx(func(q db.Querier) error {
		var err error
		id, err = f.links.Create(f.ctx, q, purpose, owner, ttl)
		return err
	})
	return id
}

func (f *fixture) mint(id uuid.UUID, rowExpires time.Time) (onetime.Minted, bool, error) {
	f.t.Helper()
	var mt onetime.Minted
	var ok bool
	var err error
	f.tx(func(q db.Querier) error {
		mt, ok, err = pending.Mint(f.ctx, q, f.links, id, rowExpires)
		return nil
	})
	return mt, ok, err
}

func (f *fixture) owner(raw, purpose string) (onetime.Token, bool, error) {
	f.t.Helper()
	var tok onetime.Token
	var ok bool
	var err error
	f.tx(func(q db.Querier) error {
		tok, ok, err = pending.Owner(f.ctx, q, f.links, raw, purpose)
		return nil
	})
	return tok, ok, err
}

func (f *fixture) spend(raw, purpose string) {
	f.t.Helper()
	f.tx(func(q db.Querier) error {
		_, err := f.links.Spend(f.ctx, q, raw, purpose)
		return err
	})
}

func (f *fixture) count(query string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.d.Row(f.t, query, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fixture) far() time.Time {
	return f.clock.Now().Add(1000 * time.Hour)
}

func (f *fixture) minted(id uuid.UUID) onetime.Minted {
	f.t.Helper()
	mt, ok, err := f.mint(id, f.far())
	if err != nil || !ok {
		f.t.Fatalf("mint %s: ok=%v err=%v", id, ok, err)
	}
	return mt
}

func (f *fixture) unminted(id uuid.UUID) bool {
	f.t.Helper()
	return f.count("SELECT count(*) FROM auth_tokens WHERE id = $1 AND token_hash IS NULL", id) == 1
}

func assertMiss(t *testing.T, mt onetime.Minted, ok bool, err error) {
	t.Helper()
	if ok || err != nil || mt.Raw != "" || !mt.ExpiresAt.IsZero() {
		t.Fatalf("want a miss, got ok=%v err=%v expires=%v", ok, err, mt.ExpiresAt)
	}
}

func TestOwnerPurpose(t *testing.T) {
	reg := authkit.PurposeRegister

	t.Run("match", func(t *testing.T) {
		f := setup(t)
		o := uuid.New()
		id := f.create(reg, o, time.Hour)
		mt := f.minted(id)
		tok, ok, err := f.owner(mt.Raw, reg)
		if err != nil || !ok {
			t.Fatalf("owner: ok=%v err=%v", ok, err)
		}
		if tok.ID != id || tok.Owner != o || tok.Purpose != reg || tok.State != onetime.StateLive {
			t.Fatalf("owner token = %+v, want id %s owner %s purpose %s live", tok, id, o, reg)
		}
	})

	t.Run("other purpose", func(t *testing.T) {
		f := setup(t)
		o := uuid.New()
		id := f.create(authkit.PurposeReset, o, time.Hour)
		mt := f.minted(id)
		tok, ok, err := f.owner(mt.Raw, reg)
		if ok || err != nil || tok != (onetime.Token{}) {
			t.Fatalf("owner of another purpose: tok=%+v ok=%v err=%v, want the zero token and a miss", tok, ok, err)
		}
		if n := f.count("SELECT count(*) FROM auth_tokens WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL", id); n != 1 {
			t.Fatalf("the other purpose's link was touched: %d live rows, want 1", n)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		f := setup(t)
		tok, ok, err := f.owner(strings.Repeat("A", 43), reg)
		if ok || err != nil || tok != (onetime.Token{}) {
			t.Fatalf("owner of an unknown link: tok=%+v ok=%v err=%v, want the zero token and a miss", tok, ok, err)
		}
	})

	t.Run("spent", func(t *testing.T) {
		f := setup(t)
		id := f.create(reg, uuid.New(), time.Hour)
		mt := f.minted(id)
		f.spend(mt.Raw, reg)
		tok, ok, err := f.owner(mt.Raw, reg)
		if !ok || err != nil {
			t.Fatalf("owner of a spent link: ok=%v err=%v, want ok", ok, err)
		}
		if tok.ID != id || tok.State != onetime.StateUsed {
			t.Fatalf("owner of a spent link = %+v, want id %s state used", tok, id)
		}
	})
}

func TestMintCapsExpiry(t *testing.T) {
	reg := authkit.PurposeRegister

	t.Run("row first", func(t *testing.T) {
		f := setup(t)
		t0 := f.clock.Now()
		id := f.create(reg, uuid.New(), 48*time.Hour)
		f.clock.Advance(2 * time.Hour)
		mt, ok, err := f.mint(id, t0.Add(48*time.Hour))
		if !ok || err != nil {
			t.Fatalf("mint: ok=%v err=%v", ok, err)
		}
		if mt.ID != id || mt.Raw == "" {
			t.Fatalf("mint returned id %s with an empty raw=%v, want id %s", mt.ID, mt.Raw == "", id)
		}
		if !mt.ExpiresAt.Equal(t0.Add(48 * time.Hour)) {
			t.Fatalf("minted ExpiresAt = %v, want the row's %v", mt.ExpiresAt, t0.Add(48*time.Hour))
		}
		if n := f.count("SELECT count(*) FROM auth_tokens WHERE id = $1 AND expires_at = $2", id, t0.Add(50*time.Hour)); n != 1 {
			t.Fatalf("the row's expiry is not the restarted one: %d rows, want 1", n)
		}
		f.spend(mt.Raw, reg)
	})

	t.Run("link first", func(t *testing.T) {
		f := setup(t)
		t0 := f.clock.Now()
		id := f.create(reg, uuid.New(), 48*time.Hour)
		f.clock.Advance(2 * time.Hour)
		mt, ok, err := f.mint(id, t0.Add(52*time.Hour))
		if !ok || err != nil {
			t.Fatalf("mint: ok=%v err=%v", ok, err)
		}
		if !mt.ExpiresAt.Equal(t0.Add(50 * time.Hour)) {
			t.Fatalf("minted ExpiresAt = %v, want the link's %v", mt.ExpiresAt, t0.Add(50*time.Hour))
		}
	})
}

func TestMintGone(t *testing.T) {
	reg := authkit.PurposeRegister

	t.Run("unknown", func(t *testing.T) {
		f := setup(t)
		mt, ok, err := f.mint(uuid.New(), f.far())
		assertMiss(t, mt, ok, err)
		if n := f.count("SELECT count(*) FROM auth_tokens"); n != 0 {
			t.Fatalf("auth_tokens has %d rows, want 0", n)
		}
	})

	t.Run("superseded", func(t *testing.T) {
		f := setup(t)
		o := uuid.New()
		first := f.create(reg, o, time.Hour)
		second := f.create(reg, o, time.Hour)
		mt, ok, err := f.mint(first, f.far())
		assertMiss(t, mt, ok, err)
		if !f.unminted(first) || !f.unminted(second) {
			t.Fatal("a superseded or replacing link was minted")
		}
	})

	t.Run("revoked", func(t *testing.T) {
		f := setup(t)
		o := uuid.New()
		id := f.create(reg, o, time.Hour)
		f.tx(func(q db.Querier) error { return f.links.Revoke(f.ctx, q, reg, o) })
		mt, ok, err := f.mint(id, f.far())
		assertMiss(t, mt, ok, err)
		if !f.unminted(id) {
			t.Fatal("a revoked link was minted")
		}
	})

	t.Run("spent", func(t *testing.T) {
		f := setup(t)
		id := f.create(reg, uuid.New(), time.Hour)
		m1 := f.minted(id)
		f.spend(m1.Raw, reg)
		mt, ok, err := f.mint(id, f.far())
		assertMiss(t, mt, ok, err)
		tok, ok, _ := f.owner(m1.Raw, reg)
		if !ok || tok.State != onetime.StateUsed {
			t.Fatalf("after a miss on a spent link: ok=%v state=%s, want the first link still used", ok, tok.State)
		}
	})
}

func TestMintNeedsTx(t *testing.T) {
	f := setup(t)
	id := f.create(authkit.PurposeRegister, uuid.New(), time.Hour)
	conn, err := f.d.App.Conn(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	mt, ok, err := pending.Mint(f.ctx, sqldb.Conn(conn), f.links, id, f.far())
	if !errors.Is(err, db.ErrTxRequired) || ok || mt.Raw != "" {
		t.Fatalf("mint on a bare connection: ok=%v err=%v raw=%v, want db.ErrTxRequired and no link", ok, err, mt.Raw == "")
	}
	if !f.unminted(id) {
		t.Fatal("a link was minted on a bare connection")
	}
}
