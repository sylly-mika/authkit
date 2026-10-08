package pgxdb_test

import (
	"context"
	crand "crypto/rand"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/pgxdb"
	"github.com/sylly-mika/authkit/password"
)

func pool(t *testing.T, d *authkittest.DB) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), d.DSN(authkittest.AppRole))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// inTx runs fn in a pgx transaction and commits whatever a refusal wrote.
func inTx(t *testing.T, p *pgxpool.Pool, fn func(q db.Querier) (authkit.Result, error)) authkit.Result {
	t.Helper()
	ctx := context.Background()
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	res, err := fn(pgxdb.Tx(tx))
	if err != nil {
		t.Fatalf("authkit over pgx: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return res
}

func TestOnlyTxIsATransaction(t *testing.T) {
	d := authkittest.NewDB(t)
	p, ctx := pool(t, d), context.Background()
	conn, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if pgxdb.Conn(conn).InTx() || pgxdb.Pool(p).InTx() || !pgxdb.Tx(tx).InTx() {
		t.Fatal("want InTx true for Tx alone")
	}
	if got, ok := pgxdb.Unwrap(pgxdb.Tx(tx)); !ok || got != tx {
		t.Fatalf("Unwrap(Tx) = %v, %v; want the pgx.Tx it wraps", got, ok)
	}
	for name, q := range map[string]db.Querier{"Conn": pgxdb.Conn(conn), "Pool": pgxdb.Pool(p), "nil": nil} {
		if _, ok := pgxdb.Unwrap(q); ok {
			t.Errorf("Unwrap(%s) reported a transaction", name)
		}
	}
	if pgxdb.Tx(nil) != nil || pgxdb.Conn(nil) != nil || pgxdb.Pool(nil) != nil || !errors.Is(db.RequireTx(pgxdb.Tx(nil)), db.ErrTxRequired) {
		t.Fatal("a nil handle is not a nil Querier")
	}
}

func TestQueryRowMapsNoRowsAndExecCountsRows(t *testing.T) {
	d := authkittest.NewDB(t)
	p := pool(t, d)
	ctx := context.Background()
	inTx(t, p, func(q db.Querier) (authkit.Result, error) {
		var id uuid.UUID
		if err := q.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, "nobody@example.invalid").Scan(&id); !errors.Is(err, db.ErrNoRows) {
			t.Errorf("an empty QueryRow = %v, want db.ErrNoRows", err)
		}
		n, err := q.Exec(ctx, `INSERT INTO users (id, email) VALUES ($1, $2), ($3, $4)`, uuid.New(), "one@example.invalid", uuid.New(), "two@example.invalid")
		if err != nil || n != 2 {
			t.Errorf("Exec = %d, %v; want 2 rows", n, err)
		}
		rows, err := q.Query(ctx, `SELECT email FROM users ORDER BY email`)
		if err != nil {
			return authkit.Result{}, err
		}
		var got []string
		for rows.Next() {
			var e string
			if err := rows.Scan(&e); err != nil {
				return authkit.Result{}, err
			}
			got = append(got, e)
		}
		if err := rows.Close(); err != nil || rows.Err() != nil || !slices.Equal(got, []string{"one@example.invalid", "two@example.invalid"}) {
			t.Errorf("Query = %v (%v, %v)", got, err, rows.Err())
		}
		return authkit.Result{}, nil
	})
}

// TestTheServiceRunsOverPgx drives every kind of statement authkit sends
// (uuid, nullable uuid, bytea, timestamptz, interval, text arrays, UPDATE …
// RETURNING, the throttle upsert) through pgx, in Session mode as BMParts
// runs it, with an OnEvent that writes through Unwrap.
func TestTheServiceRunsOverPgx(t *testing.T) {
	d := authkittest.NewDB(t)
	p, ctx := pool(t, d), context.Background()
	clock := authkittest.NewClock()
	cheap := password.Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}
	d.Exec(t, `CREATE TABLE event_mirror (id uuid PRIMARY KEY, result text NOT NULL)`)
	d.Exec(t, `GRANT SELECT, INSERT ON event_mirror TO authkit_app`)
	svc, err := authkit.New(authkit.Config{Transport: authkit.TransportSession, Hashing: cheap, Clock: clock, Rand: authkittest.Rand(11),
		OnEvent: func(ctx context.Context, q db.Querier, e authkit.Event) error {
			tx, ok := pgxdb.Unwrap(q)
			if !ok {
				return errors.New("OnEvent ran outside the method's transaction")
			}
			_, err := tx.Exec(ctx, `INSERT INTO event_mirror (id, result) VALUES ($1, $2)`, e.ID, e.Result)
			return err
		}}, authkittest.NewPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	id := d.NewPrincipal(t, "ada@example.invalid")
	hash, err := password.Encode(cheap, crand.Reader, "the old password")
	if err != nil {
		t.Fatal(err)
	}
	d.Exec(t, `INSERT INTO auth_credentials (principal_id, password_hash, changed_at) VALUES ($1, $2, $3)`, id, hash, clock.Now())
	meta := authkit.Meta{IP: "192.0.2.8", UserAgent: "authkit-test"}

	if res := inTx(t, p, func(q db.Querier) (authkit.Result, error) {
		return svc.Login(ctx, q, "staff", "ada@example.invalid", "a wrong password", meta)
	}); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("a wrong password over pgx = %v", res.Refusal)
	}
	signed := inTx(t, p, func(q db.Querier) (authkit.Result, error) {
		return svc.Login(ctx, q, "staff", "ada@example.invalid", "the old password", meta)
	})
	if signed.Refusal != nil || signed.SessionToken == "" {
		t.Fatalf("Login over pgx = %+v", signed)
	}
	clock.Advance(15 * time.Minute)
	rotated := inTx(t, p, func(q db.Querier) (authkit.Result, error) {
		return svc.AuthenticateSession(ctx, q, "staff", signed.SessionToken, meta)
	})
	if rotated.Refusal != nil || rotated.SessionToken == "" || rotated.Admission == nil {
		t.Fatalf("AuthenticateSession over pgx = %+v; want admitted and rotated", rotated)
	}
	reset := inTx(t, p, func(q db.Querier) (authkit.Result, error) {
		return svc.RequestReset(ctx, q, "staff", "ada@example.invalid")
	})
	var raw string
	inTx(t, p, func(q db.Querier) (authkit.Result, error) {
		m, err := svc.OneTime().Mint(ctx, q, *reset.TokenID)
		raw = m.Raw
		return authkit.Result{}, err
	})
	fresh := inTx(t, p, func(q db.Querier) (authkit.Result, error) {
		return svc.CompleteReset(ctx, q, "staff", raw, "the new password", meta)
	})
	if fresh.Refusal != nil || fresh.SessionToken == "" {
		t.Fatalf("CompleteReset over pgx = %+v", fresh)
	}
	list, total, err := svc.ListSessions(ctx, pgxdb.Pool(p), fresh.Claims(), 10, 0)
	if err != nil || total != 1 || !list[0].Current {
		t.Fatalf("ListSessions over the pool = %+v, %d, %v", list, total, err)
	}
	inTx(t, p, func(q db.Querier) (authkit.Result, error) {
		return svc.RevokeAllSessions(ctx, q, id, authkit.ReasonAdmin, meta)
	})
	if has, err := svc.HasCredential(ctx, pgxdb.Pool(p), id); err != nil || !has {
		t.Fatalf("HasCredential over the pool = %v, %v", has, err)
	}
	events, total, err := svc.ListEvents(ctx, pgxdb.Pool(p), id, []string{authkit.ResultBadPassword}, 10, 0)
	want := []string{"password_reset", "revoked", "signed_in", "signed_in"}
	var got []string
	for _, e := range events {
		got = append(got, e.Result)
	}
	slices.Sort(got)
	if err != nil || total != 4 || !slices.Equal(got, want) {
		t.Fatalf("ListEvents over the pool = %v, %d, %v; want %v", got, total, err, want)
	}
	var mirrored int
	if err := p.QueryRow(ctx, `SELECT count(*) FROM event_mirror`).Scan(&mirrored); err != nil || mirrored != 5 {
		t.Fatalf("event_mirror = %d (%v), want the 5 events OnEvent wrote through Unwrap", mirrored, err)
	}
	clock.Advance(91 * 24 * time.Hour)
	inTx(t, p, func(q db.Querier) (authkit.Result, error) { return authkit.Result{}, svc.Prune(ctx, q) })
	if _, total, err := svc.ListEvents(ctx, pgxdb.Pool(p), id, nil, 10, 0); err != nil || total != 0 {
		t.Fatalf("after Prune = %d, %v; want every event past EventRetention gone", total, err)
	}
}
