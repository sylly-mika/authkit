package emailchange_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/emailchange"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/onetime"
)

func TestNewRefuses(t *testing.T) {
	w := kittest.New(t)
	change := func(context.Context, db.Querier, authkit.Principal, string) error { return nil }
	if _, err := emailchange.New(w.Svc.Service, emailchange.Rules{}); err == nil || err.Error() != "emailchange: Rules.Change is nil" {
		t.Fatalf("New without Change = %v; want Rules.Change is nil", err)
	}
	if _, err := emailchange.New(w.Svc.Service, emailchange.Rules{Change: change, TTL: -time.Second}); err == nil {
		t.Fatal("New with a negative TTL succeeded")
	}
	if _, err := emailchange.New(w.Svc.Service, emailchange.Rules{Change: change}); err != nil {
		t.Fatalf("New after the refusals: %v", err)
	}
}

func TestStart(t *testing.T) {
	f := newFixture(t)
	t0 := f.Clock.Now()
	cl := f.session()
	st := f.start(cl, "  Ada.New@Example.invalid ")
	if st.Refusal != nil {
		t.Fatalf("Start refused: %v", st.Refusal)
	}
	if st.TokenID == nil {
		t.Fatal("Start gave no TokenID")
	}
	if st.Old != ada || st.Principal.ID != f.ID {
		t.Fatalf("Start = Old %q, principal %v; want %q, %v", st.Old, st.Principal.ID, ada, f.ID)
	}
	var audience, oldEmail, newEmail string
	var sessionID uuid.UUID
	var createdAt, expiresAt time.Time
	if err := f.D.Row(f.T, `SELECT audience, old_email, new_email, session_id, created_at, expires_at FROM auth_email_changes WHERE principal_id = $1`, f.ID).
		Scan(&audience, &oldEmail, &newEmail, &sessionID, &createdAt, &expiresAt); err != nil {
		t.Fatal(err)
	}
	if audience != "staff" || oldEmail != ada || newEmail != addr || sessionID != cl.SessionID {
		t.Fatalf("change row = audience %q, old %q, new %q, session %v", audience, oldEmail, newEmail, sessionID)
	}
	if !createdAt.Equal(t0) || !expiresAt.Equal(t0.Add(24*time.Hour)) {
		t.Fatalf("change row times = created %v, expires %v; want %v, %v", createdAt, expiresAt, t0, t0.Add(24*time.Hour))
	}
	var purpose string
	var owner uuid.UUID
	var tokenExpires time.Time
	var hashNull bool
	if err := f.D.Row(f.T, `SELECT purpose, owner_id, expires_at, token_hash IS NULL FROM auth_tokens WHERE id = $1`, *st.TokenID).
		Scan(&purpose, &owner, &tokenExpires, &hashNull); err != nil {
		t.Fatal(err)
	}
	if purpose != "email_change" || owner != f.ID || !tokenExpires.Equal(t0.Add(24*time.Hour)) || !hashNull {
		t.Fatalf("token row = purpose %q, owner %v, expires %v, hash null %v", purpose, owner, tokenExpires, hashNull)
	}
	if f.login() != ada || f.changes != 0 {
		t.Fatalf("login %q, Change calls %d; want %q and none", f.login(), f.changes, ada)
	}
}

func TestStartStale(t *testing.T) {
	t.Run("stale", func(t *testing.T) {
		f := newFixture(t)
		cl := f.session()
		f.Clock.Advance(5*time.Minute + time.Second)
		st := f.start(cl, addr)
		if !errors.Is(st.Refusal, authkit.ErrReauthRequired) {
			t.Fatalf("Start on a stale session = %v; want ErrReauthRequired", st.Refusal)
		}
		if st.TokenID != nil || f.rows() != 0 || f.links() != 0 {
			t.Fatalf("stale Start wrote: token %v, rows %d, links %d", st.TokenID, f.rows(), f.links())
		}
	})
	t.Run("ended", func(t *testing.T) {
		f := newFixture(t)
		cl := f.session()
		if err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
			_, err := f.Svc.Logout(f.Ctx, q, cl, authkit.Meta{})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		st := f.start(cl, addr)
		if !errors.Is(st.Refusal, authkit.ErrSessionEnded) {
			t.Fatalf("Start on an ended session = %v; want ErrSessionEnded", st.Refusal)
		}
		if st.TokenID != nil || f.rows() != 0 || f.links() != 0 {
			t.Fatalf("ended Start wrote: token %v, rows %d, links %d", st.TokenID, f.rows(), f.links())
		}
	})
	t.Run("reverified", func(t *testing.T) {
		f := newFixture(t)
		cl := f.session()
		f.Clock.Advance(5*time.Minute + time.Second)
		f.D.Exec(f.T, `UPDATE auth_sessions SET authenticated_at = $1 WHERE id = $2`, f.Clock.Now(), cl.SessionID)
		st := f.start(cl, addr)
		if st.Refusal != nil {
			t.Fatalf("Start after a re-verify refused: %v", st.Refusal)
		}
		if f.links() != 1 {
			t.Fatalf("links = %d; want 1", f.links())
		}
	})
}

func TestStartSame(t *testing.T) {
	f := newFixture(t)
	st := f.start(f.session(), " ADA@Example.invalid")
	if st.Refusal != emailchange.ErrSameAddress {
		t.Fatalf("Start to the current address = %v; want ErrSameAddress", st.Refusal)
	}
	if st.TokenID != nil || f.rows() != 0 || f.links() != 0 {
		t.Fatalf("same-address Start wrote: token %v, rows %d, links %d", st.TokenID, f.rows(), f.links())
	}
}

func TestStartHeld(t *testing.T) {
	f := newFixture(t)
	f.User("bob@example.invalid", "")
	cl := f.session()
	held := f.start(cl, "Bob@example.invalid")
	if !held.AddressHeld || held.TokenID != nil || held.Refusal != nil || held.Old != ada {
		t.Fatalf("Start to a held address = %+v", held)
	}
	if f.rows() != 0 || f.links() != 0 {
		t.Fatalf("held Start wrote: rows %d, links %d", f.rows(), f.links())
	}
	ok := f.start(cl, addr)
	ok.TokenID, ok.AddressHeld = nil, true
	if !reflect.DeepEqual(held, ok) {
		t.Fatalf("held Start %+v differs from a success %+v", held, ok)
	}
}

func TestStartCap(t *testing.T) {
	f := newFixture(t)
	cl := f.session()
	addrs := []string{"a1@example.invalid", "a2@example.invalid", "a3@example.invalid"}
	for i, a := range addrs {
		if i > 0 {
			f.Clock.Advance(time.Minute)
		}
		if st := f.start(cl, a); st.TokenID == nil {
			t.Fatalf("start %d to %s: no TokenID", i+1, a)
		}
	}
	f.Clock.Advance(time.Minute)
	st := f.start(cl, "a4@example.invalid")
	if st.TokenID != nil || st.RetryAfter != 57*time.Minute || st.Refusal != nil {
		t.Fatalf("4th start in the hour = token %v, retry %v, refusal %v; want nil, 57m, nil", st.TokenID, st.RetryAfter, st.Refusal)
	}
	if f.links() != 3 {
		t.Fatalf("links = %d; want 3", f.links())
	}
	if n := f.Count("SELECT count(*) FROM auth_email_changes WHERE principal_id = $1 AND new_email = $2", f.ID, addrs[2]); n != 1 {
		t.Fatal("the capped start replaced the pending change")
	}
	f.Clock.Advance(58 * time.Minute)
	if st := f.start(f.session(), "a5@example.invalid"); st.TokenID == nil {
		t.Fatal("a start after the hour has no TokenID")
	}
}

func TestStartCapRace(t *testing.T) {
	f := newFixture(t)
	c1, c2 := f.session(), f.session()
	f.start(c1, "a1@example.invalid")
	f.start(c1, "a2@example.invalid")
	holder, err := f.D.App.BeginTx(f.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(f.Ctx, `SELECT pg_advisory_xact_lock(hashtext('email_change'), hashtext($1::text))`, f.ID); err != nil {
		t.Fatal(err)
	}
	type result struct {
		st  emailchange.Started
		err error
	}
	run := func(cl *authkit.Claims, email string) <-chan result {
		ch := make(chan result, 1)
		go func() {
			var st emailchange.Started
			err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
				var err error
				st, err = f.EC.Start(f.Ctx, q, cl, email)
				return err
			})
			ch <- result{st, err}
		}()
		return ch
	}
	r1 := run(c1, "a3@example.invalid")
	r2 := run(c2, "a4@example.invalid")
	f.D.WaitForLockWaiters(t, 2)
	if err := holder.Rollback(); err != nil {
		t.Fatal(err)
	}
	got := []result{<-r1, <-r2}
	won, lost := 0, 0
	for _, r := range got {
		if r.err != nil {
			t.Fatal(r.err)
		}
		switch {
		case r.st.TokenID != nil:
			won++
		case r.st.RetryAfter == time.Hour:
			lost++
		default:
			t.Fatalf("a start = token %v, retry %v; want a token or 1h", r.st.TokenID, r.st.RetryAfter)
		}
	}
	if won != 1 || lost != 1 {
		t.Fatalf("won %d, lost %d; want 1 and 1", won, lost)
	}
	if f.links() != 3 {
		t.Fatalf("links = %d; want 3", f.links())
	}
}

func TestStartForNoRecent(t *testing.T) {
	f := newFixture(t)
	f.Clock.Advance(time.Hour)
	st := f.startFor("caller@example.invalid", addr)
	if st.TokenID == nil {
		t.Fatal("StartFor gave no TokenID")
	}
	if st.Old != ada {
		t.Fatalf("Old = %q; want %q from the table, not the caller", st.Old, ada)
	}
	if n := f.Count("SELECT count(*) FROM auth_email_changes WHERE principal_id = $1 AND session_id IS NULL", f.ID); n != 1 {
		t.Fatalf("rows with a NULL session = %d; want 1", n)
	}
	if f.login() != ada || f.changes != 0 {
		t.Fatalf("login %q, Change calls %d; want %q and none", f.login(), f.changes, ada)
	}
	p := f.pending()
	if p == nil || p.New != addr {
		t.Fatalf("pending = %+v; want New %q", p, addr)
	}
}

func TestPending(t *testing.T) {
	f := newFixture(t)
	t0 := f.Clock.Now()
	if p := f.pending(); p != nil {
		t.Fatalf("pending before a start = %+v; want nil", p)
	}
	f.start(f.session(), addr)
	p := f.pending()
	if p == nil || p.Old != ada || p.New != addr || !p.ExpiresAt.Equal(t0.Add(24*time.Hour)) {
		t.Fatalf("pending = %+v; want old %q, new %q, expires %v", p, ada, addr, t0.Add(24*time.Hour))
	}
	f.Clock.Advance(24*time.Hour + time.Second)
	if p := f.pending(); p != nil {
		t.Fatalf("pending after expiry = %+v; want nil", p)
	}
}

func TestStartReplaces(t *testing.T) {
	f := newFixture(t)
	cl := f.session()
	s1 := f.start(cl, "a1@example.invalid")
	s2 := f.start(cl, addr)
	if f.rows() != 1 || f.Count("SELECT count(*) FROM auth_email_changes WHERE principal_id = $1 AND new_email = $2", f.ID, addr) != 1 {
		t.Fatalf("rows = %d; want one row for %q", f.rows(), addr)
	}
	if _, err := f.mint(*s1.TokenID); err != emailchange.ErrNothingToSend {
		t.Fatalf("mint the replaced link = %v; want ErrNothingToSend", err)
	}
	mail, err := f.mint(*s2.TokenID)
	if err != nil || mail.To != addr {
		t.Fatalf("mint the current link = %+v, %v; want To %q", mail, err, addr)
	}
}

func TestMintCaps(t *testing.T) {
	f := newFixture(t)
	t0 := f.Clock.Now()
	st := f.start(f.session(), addr)
	f.Clock.Advance(2 * time.Hour)
	mail, err := f.mint(*st.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	if mail.To != addr || mail.Old != ada || mail.Raw == "" {
		t.Fatalf("mail = to %q, old %q, raw empty %v; want %q, %q", mail.To, mail.Old, mail.Raw == "", addr, ada)
	}
	if !mail.ExpiresAt.Equal(t0.Add(24 * time.Hour)) {
		t.Fatalf("mail expires %v; want the change's expiry %v", mail.ExpiresAt, t0.Add(24*time.Hour))
	}
	if tok := f.peek(mail.Raw); tok.Purpose != "email_change" || tok.State != onetime.StateLive {
		t.Fatalf("minted token = purpose %q, state %q; want email_change, live", tok.Purpose, tok.State)
	}
}

func TestMintNothing(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		f := newFixture(t)
		id := uuid.New()
		_, err := f.mint(id)
		requireNothingToSend(t, err, id)
	})
	t.Run("other purpose", func(t *testing.T) {
		f := newFixture(t)
		f.start(f.session(), addr)
		var id uuid.UUID
		if err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
			var err error
			id, err = f.Svc.OneTime().Create(f.Ctx, q, "reset", f.ID, time.Hour)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		_, err := f.mint(id)
		requireNothingToSend(t, err, id)
		if n := f.Count("SELECT count(*) FROM auth_tokens WHERE id = $1 AND token_hash IS NULL", id); n != 1 {
			t.Fatal("the reset link was minted by the email change")
		}
	})
	t.Run("superseded", func(t *testing.T) {
		f := newFixture(t)
		cl := f.session()
		first := f.start(cl, "a1@example.invalid")
		f.start(cl, addr)
		_, err := f.mint(*first.TokenID)
		requireNothingToSend(t, err, *first.TokenID)
	})
	t.Run("spent", func(t *testing.T) {
		f := newFixture(t)
		st := f.start(f.session(), addr)
		mail, err := f.mint(*st.TokenID)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
			_, err := f.Svc.OneTime().Spend(f.Ctx, q, mail.Raw, "email_change")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		_, err = f.mint(*st.TokenID)
		requireNothingToSend(t, err, *st.TokenID)
	})
	t.Run("expired", func(t *testing.T) {
		f := newFixture(t)
		st := f.start(f.session(), addr)
		f.Clock.Advance(24*time.Hour + time.Second)
		_, err := f.mint(*st.TokenID)
		requireNothingToSend(t, err, *st.TokenID)
		if n := f.Count("SELECT count(*) FROM auth_tokens WHERE id = $1 AND token_hash IS NULL", *st.TokenID); n != 1 {
			t.Fatal("the expired change's link was minted")
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		f := newFixture(t)
		st := f.start(f.session(), addr)
		f.cancel()
		_, err := f.mint(*st.TokenID)
		requireNothingToSend(t, err, *st.TokenID)
	})
}

func requireNothingToSend(t *testing.T, err error, id uuid.UUID) {
	t.Helper()
	if err != emailchange.ErrNothingToSend {
		t.Fatalf("mint = %v; want the bare ErrNothingToSend", err)
	}
	if strings.Contains(err.Error(), id.String()) {
		t.Fatalf("error text %q carries the token id", err.Error())
	}
}

func TestCancel(t *testing.T) {
	f := newFixture(t)
	st := f.start(f.session(), addr)
	mail, err := f.mint(*st.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	f.cancel()
	if p := f.pending(); p != nil {
		t.Fatalf("pending after cancel = %+v; want nil", p)
	}
	if n := f.rows(); n != 0 {
		t.Fatalf("change rows after cancel = %d; want 0", n)
	}
	if tok := f.peek(mail.Raw); tok.State != onetime.StateRevoked {
		t.Fatalf("link state after cancel = %q; want revoked", tok.State)
	}
	f.cancel()
}
