package throttle_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/throttle"
)

func TestAFailureAfterTheWindowStartsOverAndPruneClears(t *testing.T) {
	d := authkittest.NewDB(t)
	ctx := context.Background()
	rules := throttle.Rules{Failures: 3, Window: time.Minute, Lockout: 2 * time.Minute}
	t0 := authkittest.NewClock().Now()
	run := func(fn func(q db.Querier) error) {
		t.Helper()
		if err := d.InAuthTx(ctx, fn); err != nil {
			t.Fatal(err)
		}
	}
	fail := func(at time.Time) {
		run(func(q db.Querier) error { return throttle.Fail(ctx, q, "ada", "staff", at, rules) })
	}
	fail(t0)
	fail(t0.Add(10 * time.Second))
	fail(t0.Add(2 * time.Minute))
	var failures int
	if err := d.Row(t, `SELECT failures FROM auth_throttle WHERE login = 'ada'`).Scan(&failures); err != nil || failures != 1 {
		t.Fatalf("failures after the window = %d (%v), want a fresh window of 1", failures, err)
	}
	fail(t0.Add(2*time.Minute + time.Second))
	fail(t0.Add(2*time.Minute + 2*time.Second))
	lockedAt := t0.Add(2*time.Minute + 2*time.Second)
	run(func(q db.Querier) error {
		until, locked, err := throttle.Locked(ctx, q, "ada", "staff", lockedAt.Add(time.Minute))
		if err != nil || !locked || !until.Equal(lockedAt.Add(2*time.Minute)) {
			t.Errorf("Locked = %v, %v, %v; want locked until %v", until, locked, err, lockedAt.Add(2*time.Minute))
		}
		return err
	})
	run(func(q db.Querier) error {
		n, err := throttle.Prune(ctx, q, lockedAt.Add(time.Minute), rules)
		if err != nil || n != 0 {
			t.Errorf("Prune during the lock = %d, %v; want nothing", n, err)
		}
		n, err = throttle.Prune(ctx, q, lockedAt.Add(3*time.Minute), rules)
		if err != nil || n != 1 {
			t.Errorf("Prune after window and lock = %d, %v; want 1", n, err)
		}
		return err
	})
}

func TestConcurrentFailuresCountExactly(t *testing.T) {
	d := authkittest.NewDB(t)
	ctx := context.Background()
	rules := throttle.Rules{Failures: 10, Window: time.Hour, Lockout: 15 * time.Minute}
	t0 := authkittest.NewClock().Now()
	const n = 20
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, n)
	for range n {
		wg.Go(func() {
			<-start
			errs <- d.InAuthTx(ctx, func(q db.Querier) error { return throttle.Fail(ctx, q, "ada", "staff", t0, rules) })
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("a concurrent Fail: %v", err)
		}
	}
	var failures int
	var until time.Time
	if err := d.Row(t, `SELECT failures, locked_until FROM auth_throttle WHERE login = 'ada'`).Scan(&failures, &until); err != nil || failures != n || !until.Equal(t0.Add(rules.Lockout)) {
		t.Fatalf("after %d concurrent failures: failures %d, locked_until %v (%v); want %d and %v", n, failures, until, err, n, t0.Add(rules.Lockout))
	}
}

func TestALimitOfOneLocksAtOnceAndTheLockEndsAtItsInstant(t *testing.T) {
	d := authkittest.NewDB(t)
	ctx := context.Background()
	rules := throttle.Rules{Failures: 1, Window: time.Minute, Lockout: 2 * time.Minute}
	t0 := authkittest.NewClock().Now()
	if err := d.InAuthTx(ctx, func(q db.Querier) error { return throttle.Fail(ctx, q, "ada", "staff", t0, rules) }); err != nil {
		t.Fatal(err)
	}
	for at, want := range map[time.Time]bool{t0: true, t0.Add(2*time.Minute - time.Microsecond): true, t0.Add(2 * time.Minute): false} {
		if err := d.InAuthTx(ctx, func(q db.Querier) error {
			_, locked, err := throttle.Locked(ctx, q, "ada", "staff", at)
			if locked != want {
				t.Errorf("Locked at %v = %v, want %v (a limit of 1 locks at the first failure; the lock ends at locked_until)", at.Sub(t0), locked, want)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTheAudienceIsPartOfTheKey(t *testing.T) {
	d := authkittest.NewDB(t)
	ctx := context.Background()
	rules := throttle.Rules{Failures: 2, Window: time.Minute, Lockout: time.Minute}
	t0 := authkittest.NewClock().Now()
	run := func(fn func(q db.Querier) error) {
		t.Helper()
		if err := d.InAuthTx(ctx, fn); err != nil {
			t.Fatal(err)
		}
	}
	locked := func(aud string) bool {
		t.Helper()
		var l bool
		run(func(q db.Querier) error {
			var err error
			_, l, err = throttle.Locked(ctx, q, "ada", aud, t0)
			return err
		})
		return l
	}
	run(func(q db.Querier) error { return throttle.Fail(ctx, q, "ada", "staff", t0, rules) })
	run(func(q db.Querier) error { return throttle.Fail(ctx, q, "ada", "staff", t0, rules) })
	if !locked("staff") || locked("client") {
		t.Fatal("a staff lock must lock staff only")
	}
	run(func(q db.Querier) error { return throttle.Fail(ctx, q, "ada", "client", t0, rules) })
	if locked("client") {
		t.Fatal("one client failure under a limit of 2 locked client")
	}
	run(func(q db.Querier) error { return throttle.Clear(ctx, q, "ada", "client") })
	var staff, client int
	if err := d.Row(t, `SELECT count(*) FILTER (WHERE audience = 'staff'), count(*) FILTER (WHERE audience = 'client') FROM auth_throttle WHERE login = 'ada'`).Scan(&staff, &client); err != nil || staff != 1 || client != 0 {
		t.Fatalf("after Clear(client): staff %d, client %d (%v); want 1 and 0", staff, client, err)
	}
}

func TestFailNeedsATransaction(t *testing.T) {
	d := authkittest.NewDB(t)
	ctx := context.Background()
	conn, err := d.App.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	err = throttle.Fail(ctx, sqldb.Conn(conn), "ada", "staff", authkittest.NewClock().Now(), throttle.Rules{Failures: 1, Window: time.Minute, Lockout: time.Minute})
	if !errors.Is(err, db.ErrTxRequired) {
		t.Fatalf("Fail on a bare connection = %v, want db.ErrTxRequired", err)
	}
}

func TestPruneKeepsALiveWindowWithoutALock(t *testing.T) {
	d := authkittest.NewDB(t)
	ctx := context.Background()
	rules := throttle.Rules{Failures: 5, Window: 10 * time.Minute, Lockout: time.Minute}
	t0 := authkittest.NewClock().Now()
	if err := d.InAuthTx(ctx, func(q db.Querier) error {
		if err := throttle.Fail(ctx, q, "ada", "staff", t0, rules); err != nil {
			return err
		}
		n, err := throttle.Prune(ctx, q, t0.Add(5*time.Minute), rules)
		if n != 0 {
			t.Errorf("Prune inside an unlocked live window = %d, want 0", n)
		}
		if err != nil {
			return err
		}
		if n, err = throttle.Prune(ctx, q, t0.Add(10*time.Minute), rules); n != 1 {
			t.Errorf("Prune at the window's end = %d, want 1", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// TestCountJudgesTheLimitAndLocksTheNext is spec §3.2: r.Failures attempts
// pass, the next is locked; a running lockout is kept, not extended; a lapsed
// one starts a fresh window.
func TestCountJudgesTheLimitAndLocksTheNext(t *testing.T) {
	d := authkittest.NewDB(t)
	ctx := context.Background()
	rules := throttle.Rules{Failures: 3, Window: 10 * time.Minute, Lockout: 2 * time.Minute}
	t0 := authkittest.NewClock().Now()
	count := func(at time.Time) (time.Time, bool) {
		t.Helper()
		var until time.Time
		var locked bool
		if err := d.InAuthTx(ctx, func(q db.Querier) error {
			var err error
			until, locked, err = throttle.Count(ctx, q, "ada", "staff", at, rules)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return until, locked
	}
	for i := range 3 {
		if _, locked := count(t0.Add(time.Duration(i) * time.Second)); locked {
			t.Fatalf("attempt %d of 3 is locked", i+1)
		}
	}
	lockedAt := t0.Add(3 * time.Second)
	if until, locked := count(lockedAt); !locked || !until.Equal(lockedAt.Add(2*time.Minute)) {
		t.Fatalf("the fourth attempt = %v, %v; want locked until %v", until, locked, lockedAt.Add(2*time.Minute))
	}
	if until, locked := count(lockedAt.Add(time.Minute)); !locked || !until.Equal(lockedAt.Add(2*time.Minute)) {
		t.Fatalf("an attempt during the lockout = %v, %v; want the lockout kept as it was", until, locked)
	}
	if _, locked := count(lockedAt.Add(2 * time.Minute)); locked {
		t.Fatal("the attempt after the lockout is locked: a lapsed lockout starts a fresh window")
	}
	var failures int
	if err := d.Row(t, `SELECT failures FROM auth_throttle WHERE login = 'ada'`).Scan(&failures); err != nil || failures != 1 {
		t.Fatalf("failures after the lockout = %d (%v), want a fresh window of 1", failures, err)
	}
}

func TestConcurrentCountsLockExactlyPastTheLimit(t *testing.T) {
	d := authkittest.NewDB(t)
	ctx := context.Background()
	rules := throttle.Rules{Failures: 10, Window: time.Hour, Lockout: 15 * time.Minute}
	t0 := authkittest.NewClock().Now()
	const n = 20
	var wg sync.WaitGroup
	start := make(chan struct{})
	locked := make(chan bool, n)
	for range n {
		wg.Go(func() {
			<-start
			if err := d.InAuthTx(ctx, func(q db.Querier) error {
				_, l, err := throttle.Count(ctx, q, "ada", "staff", t0, rules)
				locked <- l
				return err
			}); err != nil {
				t.Errorf("a concurrent Count: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	close(locked)
	n0 := 0
	for l := range locked {
		if !l {
			n0++
		}
	}
	if n0 != 10 {
		t.Fatalf("%d of %d concurrent attempts passed, want exactly 10", n0, n)
	}
}

func TestCountNeedsATransaction(t *testing.T) {
	d := authkittest.NewDB(t)
	ctx := context.Background()
	conn, err := d.App.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _, err = throttle.Count(ctx, sqldb.Conn(conn), "ada", "staff", authkittest.NewClock().Now(), throttle.Rules{Failures: 1, Window: time.Minute, Lockout: time.Minute})
	if !errors.Is(err, db.ErrTxRequired) {
		t.Fatalf("Count on a bare connection = %v, want db.ErrTxRequired", err)
	}
}
