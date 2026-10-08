package onetime_test

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/onetime"
)

type fixture struct {
	d     *authkittest.DB
	links *onetime.Store
	clock *authkittest.Clock
	ctx   context.Context
}

func setup(t *testing.T) *fixture {
	clock := authkittest.NewClock()
	return &fixture{d: authkittest.NewDB(t), links: onetime.New(clock.Now, authkittest.Rand(1)), clock: clock, ctx: context.Background()}
}

func (f *fixture) create(t *testing.T, purpose string, owner uuid.UUID, ttl time.Duration) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.d.InAuthTx(f.ctx, func(q db.Querier) error {
		var err error
		id, err = f.links.Create(f.ctx, q, purpose, owner, ttl)
		return err
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	return id
}

func (f *fixture) mint(t *testing.T, id uuid.UUID) (onetime.Minted, error) {
	t.Helper()
	var m onetime.Minted
	err := f.d.InAuthTx(f.ctx, func(q db.Querier) error {
		var err error
		m, err = f.links.Mint(f.ctx, q, id)
		return err
	})
	return m, err
}

func (f *fixture) mustMint(t *testing.T, id uuid.UUID) onetime.Minted {
	t.Helper()
	m, err := f.mint(t, id)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return m
}

func (f *fixture) spend(raw, purpose string) (onetime.Token, error) {
	var tok onetime.Token
	err := f.d.InAuthTx(f.ctx, func(q db.Querier) error {
		var err error
		tok, err = f.links.Spend(f.ctx, q, raw, purpose)
		return err
	})
	return tok, err
}

func (f *fixture) peek(t *testing.T, raw string) (onetime.Token, error) {
	t.Helper()
	var tok onetime.Token
	err := f.d.InAuthTx(f.ctx, func(q db.Querier) error {
		var err error
		tok, err = f.links.Peek(f.ctx, q, raw)
		return err
	})
	return tok, err
}

func TestCreateStoresAnUnsentRow(t *testing.T) {
	f := setup(t)
	owner := f.d.NewPrincipal(t, "ada@example.invalid")
	id := f.create(t, "reset", owner, time.Hour)
	var unsent, expires bool
	var ttl string
	if err := f.d.Row(t, `SELECT token_hash IS NULL, ttl::text, expires_at = $2 FROM auth_tokens WHERE id = $1`,
		id, f.clock.Now().Add(time.Hour)).Scan(&unsent, &ttl, &expires); err != nil {
		t.Fatal(err)
	}
	if !unsent || ttl != "01:00:00" || !expires {
		t.Fatalf("row: unsent %v, ttl %s, provisional expiry %v; want true, 01:00:00, true", unsent, ttl, expires)
	}
}

func TestCreateSupersedesTheLiveRow(t *testing.T) {
	f := setup(t)
	owner := f.d.NewPrincipal(t, "ada@example.invalid")
	first := f.create(t, "reset", owner, time.Hour)
	old, err := f.mint(t, first)
	if err != nil {
		t.Fatal(err)
	}
	second := f.create(t, "reset", owner, time.Hour)
	if _, err := f.peek(t, old.Raw); !errors.Is(err, onetime.ErrUnknown) {
		t.Fatalf("the superseded link = %v, want ErrUnknown (its hash is gone: 404)", err)
	}
	var gone onetime.ErrGone
	if _, err := f.mint(t, first); !errors.As(err, &gone) || gone.State != onetime.StateRevoked {
		t.Fatalf("minting the superseded row = %v, want ErrGone{revoked}: its queued mail is skipped", err)
	}
	if _, err := f.mint(t, second); err != nil {
		t.Fatalf("the new row does not mint: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM auth_tokens WHERE owner_id = $1 AND used_at IS NULL AND revoked_at IS NULL`, owner); n != 1 {
		t.Fatalf("%d live rows, want 1", n)
	}
}

func (f *fixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := f.d.Row(t, query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestConcurrentCreatesSerialiseAndBothSucceed(t *testing.T) {
	f := setup(t)
	owner := f.d.NewPrincipal(t, "ada@example.invalid")
	holder, err := f.d.App.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(f.ctx, `SELECT pg_advisory_xact_lock(hashtext('reset'), hashtext($1::text))`, owner); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			errs <- f.d.InAuthTx(f.ctx, func(q db.Querier) error {
				_, err := f.links.Create(f.ctx, q, "reset", owner, time.Hour)
				return err
			})
		}()
	}
	f.d.WaitForLockWaiters(t, 2)
	if err := holder.Rollback(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Errorf("a concurrent Create failed: %v (spec §5.2: both answer normally)", err)
		}
	}
	if live, all := f.count(t, `SELECT count(*) FROM auth_tokens WHERE owner_id = $1 AND revoked_at IS NULL`, owner),
		f.count(t, `SELECT count(*) FROM auth_tokens WHERE owner_id = $1`, owner); live != 1 || all != 2 {
		t.Fatalf("%d live of %d rows, want 1 of 2", live, all)
	}
}

func TestCreateLeavesClosedLinksAlone(t *testing.T) {
	f := setup(t)
	owner := f.d.NewPrincipal(t, "ada@example.invalid")
	spent := f.mustMint(t, f.create(t, "reset", owner, time.Hour))
	if _, err := f.spend(spent.Raw, "reset"); err != nil {
		t.Fatal(err)
	}
	invite := f.d.NewPrincipal(t, "bob@example.invalid")
	revoked := f.mustMint(t, f.create(t, "invite-test", invite, time.Hour))
	if err := f.d.InAuthTx(f.ctx, func(q db.Querier) error { return f.links.Revoke(f.ctx, q, "invite-test", invite) }); err != nil {
		t.Fatal(err)
	}
	f.create(t, "reset", owner, time.Hour)
	f.create(t, "invite-test", invite, time.Hour)
	for raw, want := range map[string]onetime.State{spent.Raw: onetime.StateUsed, revoked.Raw: onetime.StateRevoked} {
		if tok, err := f.peek(t, raw); err != nil || tok.State != want {
			t.Errorf("after a new Create, a closed link = %v, %v; want %s", tok.State, err, want)
		}
	}
}

func TestMintStoresTheHashAndRestartsTheExpiry(t *testing.T) {
	f := setup(t)
	owner := f.d.NewPrincipal(t, "ada@example.invalid")
	id := f.create(t, "invite-test", owner, 7*24*time.Hour)
	f.clock.Advance(3 * time.Hour)
	m, err := f.mint(t, id)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != id || m.Purpose != "invite-test" || m.Owner != owner || len(m.Raw) != 43 || !m.ExpiresAt.Equal(f.clock.Now().Add(7*24*time.Hour)) {
		t.Fatalf("minted = %+v", m)
	}
	if n := f.count(t, `SELECT count(*) FROM auth_tokens WHERE id = $1 AND token_hash = sha256(convert_to($2, 'UTF8'))`, id, m.Raw); n != 1 {
		t.Fatal("the stored hash is not sha256 of the raw token (spec §8.8)")
	}
	again, err := f.mint(t, id)
	if err != nil || again.Raw == m.Raw {
		t.Fatalf("a re-mint = %v, %v; want a new token", again.Raw, err)
	}
	if _, err := f.peek(t, m.Raw); !errors.Is(err, onetime.ErrUnknown) {
		t.Fatalf("the re-minted row's earlier link = %v, want ErrUnknown", err)
	}
}

func TestMintRefusesAnUnknownOrClosedRow(t *testing.T) {
	f := setup(t)
	owner := f.d.NewPrincipal(t, "ada@example.invalid")
	if _, err := f.mint(t, uuid.New()); !errors.Is(err, onetime.ErrUnknown) {
		t.Fatalf("an unknown id = %v, want ErrUnknown", err)
	}
	used := f.create(t, "reset", owner, time.Hour)
	m := f.mustMint(t, used)
	if _, err := f.spend(m.Raw, "reset"); err != nil {
		t.Fatal(err)
	}
	var gone onetime.ErrGone
	if _, err := f.mint(t, used); !errors.As(err, &gone) || gone.State != onetime.StateUsed {
		t.Fatalf("minting a spent row = %v, want ErrGone{used}", err)
	}
}

// TestMintQueuesBehindASupersede: a resend that supersedes the row while the
// worker mints it wins, and the worker skips the old mail.
func TestMintQueuesBehindASupersede(t *testing.T) {
	f := setup(t)
	owner := f.d.NewPrincipal(t, "ada@example.invalid")
	id := f.create(t, "reset", owner, time.Hour)
	holder, err := f.d.App.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := f.links.Create(f.ctx, sqldb.Tx(holder), "reset", owner, time.Hour); err != nil {
		t.Fatal(err)
	}
	minted := make(chan error, 1)
	go func() { _, err := f.mint(t, id); minted <- err }()
	f.d.WaitForLockWaiters(t, 1)
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	var gone onetime.ErrGone
	if err := <-minted; !errors.As(err, &gone) || gone.State != onetime.StateRevoked {
		t.Fatalf("a mint racing a supersede = %v, want ErrGone{revoked}", err)
	}
}

func TestPeekReportsEveryState(t *testing.T) {
	f := setup(t)
	link := func(purpose string, ttl time.Duration) (uuid.UUID, string) {
		owner := f.d.NewPrincipal(t, uuid.NewString()+"@example.invalid")
		id := f.create(t, purpose, owner, ttl)
		m, err := f.mint(t, id)
		if err != nil {
			t.Fatal(err)
		}
		return owner, m.Raw
	}
	_, live := link("reset", time.Hour)
	_, used := link("reset", time.Hour)
	revokedOwner, revoked := link("invite-test", time.Hour)
	_, expired := link("reset", time.Minute)
	if _, err := f.spend(used, "reset"); err != nil {
		t.Fatal(err)
	}
	if err := f.d.InAuthTx(f.ctx, func(q db.Querier) error { return f.links.Revoke(f.ctx, q, "invite-test", revokedOwner) }); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(2 * time.Minute)
	for raw, want := range map[string]onetime.State{live: onetime.StateLive, used: onetime.StateUsed, revoked: onetime.StateRevoked, expired: onetime.StateExpired} {
		if tok, err := f.peek(t, raw); err != nil || tok.State != want {
			t.Errorf("Peek = %v, %v; want %s", tok.State, err, want)
		}
	}
	if _, err := f.peek(t, "not-a-token"); !errors.Is(err, onetime.ErrUnknown) {
		t.Errorf("an unknown token = %v, want ErrUnknown", err)
	}
}

func TestSpendIsSingleUse(t *testing.T) {
	f := setup(t)
	owner := f.d.NewPrincipal(t, "ada@example.invalid")
	m := f.mustMint(t, f.create(t, "reset", owner, time.Hour))
	tok, err := f.spend(m.Raw, "reset")
	if err != nil || tok.Owner != owner || tok.ID != m.ID {
		t.Fatalf("first spend = %+v, %v", tok, err)
	}
	var gone onetime.ErrGone
	if _, err := f.spend(m.Raw, "reset"); !errors.As(err, &gone) || gone.State != onetime.StateUsed {
		t.Fatalf("second spend = %v, want ErrGone{used} (410)", err)
	}
}

// TestSpendConcurrentOnlyOneWins is spec §8.2 (†). A holder locks the row
// first, so all 16 spends queue on it and race the moment it lets go.
func TestSpendConcurrentOnlyOneWins(t *testing.T) {
	f := setup(t)
	owner := f.d.NewPrincipal(t, "ada@example.invalid")
	m := f.mustMint(t, f.create(t, "reset", owner, time.Hour))
	holder, err := f.d.Owner.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(f.ctx, `SELECT 1 FROM auth_tokens WHERE id = $1 FOR UPDATE`, m.ID); err != nil {
		t.Fatal(err)
	}
	const n = 16
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			_, err := f.spend(m.Raw, "reset")
			errs <- err
		})
	}
	f.d.WaitForLockWaiters(t, n)
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(errs)
	won, gone := 0, 0
	for err := range errs {
		var g onetime.ErrGone
		switch {
		case err == nil:
			won++
		case errors.As(err, &g) && g.State == onetime.StateUsed:
			gone++
		default:
			t.Errorf("a spend failed: %v", err)
		}
	}
	if won != 1 || gone != n-1 {
		t.Fatalf("%d spends won and %d were refused, want 1 and %d (spec §8.2)", won, gone, n-1)
	}
}

func TestSpendRefusals(t *testing.T) {
	f := setup(t)
	owner := f.d.NewPrincipal(t, "ada@example.invalid")
	m := f.mustMint(t, f.create(t, "reset", owner, time.Minute))
	if _, err := f.spend(m.Raw, "invite"); !errors.Is(err, onetime.ErrUnknown) {
		t.Fatalf("a token of another purpose = %v, want ErrUnknown (404, not 410)", err)
	}
	if _, err := f.spend("not-a-token", "reset"); !errors.Is(err, onetime.ErrUnknown) {
		t.Fatalf("an unknown token = %v, want ErrUnknown", err)
	}
	f.clock.Advance(2 * time.Minute)
	var gone onetime.ErrGone
	if _, err := f.spend(m.Raw, "reset"); !errors.As(err, &gone) || gone.State != onetime.StateExpired {
		t.Fatalf("an expired token = %v, want ErrGone{expired}", err)
	}
	if n := f.count(t, `SELECT count(*) FROM auth_tokens WHERE id = $1 AND used_at IS NULL`, m.ID); n != 1 {
		t.Fatal("a refused spend wrote")
	}
}

func TestSpendRefusesARevokedLink(t *testing.T) {
	f := setup(t)
	owner := f.d.NewPrincipal(t, "ada@example.invalid")
	m := f.mustMint(t, f.create(t, "invite-test", owner, time.Hour))
	if err := f.d.InAuthTx(f.ctx, func(q db.Querier) error { return f.links.Revoke(f.ctx, q, "invite-test", owner) }); err != nil {
		t.Fatal(err)
	}
	var gone onetime.ErrGone
	if _, err := f.spend(m.Raw, "invite-test"); !errors.As(err, &gone) || gone.State != onetime.StateRevoked {
		t.Fatalf("spending a revoked link = %v, want ErrGone{revoked} (410)", err)
	}
	if n := f.count(t, `SELECT count(*) FROM auth_tokens WHERE id = $1 AND used_at IS NULL`, m.ID); n != 1 {
		t.Fatal("a refused spend of a revoked link wrote")
	}
}

func TestSpendAndPeekAgreeAtTheExpiryInstant(t *testing.T) {
	f := setup(t)
	owner := f.d.NewPrincipal(t, "ada@example.invalid")
	m := f.mustMint(t, f.create(t, "reset", owner, time.Minute))
	f.clock.Advance(time.Minute)
	var gone onetime.ErrGone
	if _, err := f.spend(m.Raw, "reset"); !errors.As(err, &gone) || gone.State != onetime.StateExpired {
		t.Fatalf("a spend at expires_at = %v, want ErrGone{expired}", err)
	}
	if tok, err := f.peek(t, m.Raw); err != nil || tok.State != onetime.StateExpired {
		t.Fatalf("Peek at expires_at = %v, %v; want expired", tok.State, err)
	}
}

// TestSpendDecidesOnOneInstant is P3: a clock that steps back between the
// guarded UPDATE and the fallback must not turn an expiry refusal into "live".
func TestSpendDecidesOnOneInstant(t *testing.T) {
	f := setup(t)
	owner := f.d.NewPrincipal(t, "ada@example.invalid")
	m := f.mustMint(t, f.create(t, "reset", owner, time.Hour))
	reads := []time.Time{m.ExpiresAt, m.ExpiresAt.Add(-time.Second)}
	stepping := onetime.New(func() time.Time {
		now := reads[0]
		if len(reads) > 1 {
			reads = reads[1:]
		}
		return now
	}, authkittest.Rand(2))
	var gone onetime.ErrGone
	err := f.d.InAuthTx(f.ctx, func(q db.Querier) error { _, err := stepping.Spend(f.ctx, q, m.Raw, "reset"); return err })
	if !errors.As(err, &gone) || gone.State != onetime.StateExpired {
		t.Fatalf("a refused spend = %v, want ErrGone{expired}", err)
	}
}

func TestRevokeKeepsTheHash(t *testing.T) {
	f := setup(t)
	owner := f.d.NewPrincipal(t, "ada@example.invalid")
	m := f.mustMint(t, f.create(t, "invite-test", owner, time.Hour))
	if err := f.d.InAuthTx(f.ctx, func(q db.Querier) error { return f.links.Revoke(f.ctx, q, "invite-test", owner) }); err != nil {
		t.Fatal(err)
	}
	if tok, err := f.peek(t, m.Raw); err != nil || tok.State != onetime.StateRevoked || tok.Owner != owner {
		t.Fatalf("a revoked link = %+v, %v; want revoked (410)", tok, err)
	}
}

func TestInviteLinksFollowTheInvitePolicy(t *testing.T) {
	f := setup(t)
	scope := uuid.New()
	invite := f.d.NewInvite(t, scope)
	staff := f.d.Pinned(t, f.d.NewPrincipal(t, "staff@example.invalid"), scope, "staff")
	var id uuid.UUID
	if err := authkittest.InConnTx(f.ctx, staff, func(q db.Querier) error {
		var err error
		id, err = f.links.Create(f.ctx, q, "invite", invite, 7*24*time.Hour)
		return err
	}); err != nil {
		t.Fatalf("staff creates the invite link on its pinned connection: %v", err)
	}
	var raw string
	if err := f.d.InSystemTx(f.ctx, scope, func(q db.Querier) error {
		m, err := f.links.Mint(f.ctx, q, id)
		raw = m.Raw
		return err
	}); err != nil {
		t.Fatalf("the worker mints it as the workspace's system principal: %v", err)
	}
	for name, conn := range map[string]*sql.Conn{
		"another workspace's staff": f.d.Pinned(t, f.d.NewPrincipal(t, "outsider@example.invalid"), uuid.New(), "staff"),
		"a client of the workspace": f.d.Pinned(t, f.d.NewPrincipal(t, "client@example.invalid"), scope, "client"),
	} {
		if err := authkittest.InConnTx(f.ctx, conn, func(q db.Querier) error { _, err := f.links.Peek(f.ctx, q, raw); return err }); !errors.Is(err, onetime.ErrUnknown) {
			t.Errorf("%s reads the link: %v", name, err)
		}
	}
	if err := authkittest.InConnTx(f.ctx, staff, func(q db.Querier) error { return f.links.Revoke(f.ctx, q, "invite", invite) }); err != nil {
		t.Fatal(err)
	}
	if tok, err := f.peek(t, raw); err != nil || tok.State != onetime.StateRevoked {
		t.Fatalf("after the staff revoke = %+v, %v", tok, err)
	}
}

// TestPruneDropsEachKindOfDeadRow starts a year ahead, so a wall-clock
// timestamp would sit far behind the fake clock and be pruned too early.
func TestPruneDropsEachKindOfDeadRow(t *testing.T) {
	f := setup(t)
	const year = 365 * 24 * time.Hour
	f.clock.Advance(year)
	link := func(purpose string, ttl time.Duration) (uuid.UUID, onetime.Minted) {
		owner := f.d.NewPrincipal(t, uuid.NewString()+"@example.invalid")
		return owner, f.mustMint(t, f.create(t, purpose, owner, ttl))
	}
	_, used := link("reset", year)
	revokedOwner, _ := link("invite-test", year)
	link("reset", time.Hour)
	_, live := link("reset", year)
	if _, err := f.spend(used.Raw, "reset"); err != nil {
		t.Fatal(err)
	}
	if err := f.d.InAuthTx(f.ctx, func(q db.Querier) error { return f.links.Revoke(f.ctx, q, "invite-test", revokedOwner) }); err != nil {
		t.Fatal(err)
	}
	prune := func() int64 {
		var n int64
		if err := f.d.InAuthTx(f.ctx, func(q db.Querier) error {
			var err error
			n, err = f.links.Prune(f.ctx, q, f.clock.Now().Add(-30*24*time.Hour))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	f.clock.Advance(29 * 24 * time.Hour)
	if n := prune(); n != 0 {
		t.Fatalf("Prune 29 days on = %d, want 0", n)
	}
	f.clock.Advance(2 * 24 * time.Hour)
	if n := prune(); n != 3 {
		t.Fatalf("Prune 31 days on = %d, want the spent, revoked and expired rows", n)
	}
	if c := f.count(t, `SELECT count(*) FROM auth_tokens WHERE id = $1`, live.ID); c != 1 {
		t.Fatal("Prune deleted a live row")
	}
}
