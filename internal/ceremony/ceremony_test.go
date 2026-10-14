package ceremony_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/internal/ceremony"
)

type fixture struct {
	d     *authkittest.DB
	clock *authkittest.Clock
	rnd   io.Reader
	ctx   context.Context
}

func setup(t *testing.T) *fixture {
	return &fixture{
		d:     authkittest.NewDB(t),
		clock: authkittest.NewClock(),
		rnd:   authkittest.Rand(1),
		ctx:   context.Background(),
	}
}

func (f *fixture) session(t *testing.T, principal uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	now := f.clock.Now()
	f.d.Exec(t, `INSERT INTO auth_sessions (id, principal_id, audience, token_hash, authenticated_at, created_at, expires_at) VALUES ($1, $2, 'staff', $3, $4, $4, $5)`,
		id, principal, id[:], now, now.Add(time.Hour))
	return id
}

func data(challenge string) webauthn.SessionData {
	return webauthn.SessionData{Challenge: challenge, RelyingPartyID: "localhost", UserVerification: protocol.VerificationRequired}
}

func (f *fixture) create(t *testing.T, kind ceremony.Kind, aud string, principal, session *uuid.UUID, ttl time.Duration) (string, time.Time) {
	t.Helper()
	var id string
	var exp time.Time
	err := f.d.InAuthTx(f.ctx, func(q db.Querier) error {
		var err error
		id, exp, err = ceremony.Create(f.ctx, q, f.rnd, kind, aud, principal, session, data("c"), f.clock.Now(), ttl)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id, exp
}

func (f *fixture) spend(t *testing.T, kind ceremony.Kind, aud, id string, principal, session *uuid.UUID) (webauthn.SessionData, bool) {
	t.Helper()
	var out webauthn.SessionData
	var ok bool
	err := f.d.InAuthTx(f.ctx, func(q db.Querier) error {
		var err error
		out, ok, err = ceremony.Spend(f.ctx, q, kind, aud, id, principal, session, f.clock.Now())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out, ok
}

func hashOf(id string) []byte {
	sum := sha256.Sum256([]byte(id))
	return sum[:]
}

func ptr(u uuid.UUID) *uuid.UUID { return &u }

func (f *fixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := f.d.Row(t, query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *fixture) assertLive(t *testing.T, id string) {
	t.Helper()
	if n := f.count(t, `SELECT count(*) FROM auth_passkey_ceremonies WHERE ceremony_hash = $1 AND used_at IS NULL`, hashOf(id)); n != 1 {
		t.Fatalf("a refused spend burned the ceremony <redacted>: %d live rows, want 1", n)
	}
}

func TestCreateStoresOnlyTheHash(t *testing.T) {
	f := setup(t)
	A := f.d.NewPrincipal(t, "ada@example.invalid")
	S := f.session(t, A)
	id, exp := f.create(t, ceremony.KindRegister, "staff", ptr(A), ptr(S), 2*time.Minute)
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if len(id) != 43 || err != nil || len(raw) != 32 {
		t.Fatalf("ceremony id is not 32 random bytes as base64url: length %d", len(id))
	}
	if !exp.Equal(f.clock.Now().Add(2 * time.Minute)) {
		t.Fatalf("expiry %v, want %v", exp, f.clock.Now().Add(2*time.Minute))
	}
	if n := f.count(t, `SELECT count(*) FROM auth_passkey_ceremonies WHERE ceremony_hash = $1 AND kind = 'register' AND audience = 'staff' AND principal_id = $2 AND session_id = $3 AND expires_at = $4 AND used_at IS NULL`,
		hashOf(id), A, S, exp); n != 1 {
		t.Fatalf("stored row does not match the register ceremony: %d rows, want 1", n)
	}
	if n := f.count(t, `SELECT count(*) FROM auth_passkey_ceremonies WHERE ceremony_hash = convert_to($1, 'UTF8') OR strpos(data::text, $1) > 0`, id); n != 0 {
		t.Fatalf("the raw ceremony id <redacted> is stored: %d rows", n)
	}
}

func TestSpendRefusesAnotherKind(t *testing.T) {
	f := setup(t)
	A := f.d.NewPrincipal(t, "ada@example.invalid")
	S := f.session(t, A)
	id, _ := f.create(t, ceremony.KindRegister, "staff", ptr(A), ptr(S), 2*time.Minute)
	if _, ok := f.spend(t, ceremony.KindLogin, "staff", id, nil, nil); ok {
		t.Fatal("a register ceremony was spent as a login")
	}
	f.assertLive(t, id)
	if _, ok := f.spend(t, ceremony.KindRegister, "staff", id, ptr(A), ptr(S)); !ok {
		t.Fatal("the register ceremony was refused for its own kind after a refused spend")
	}

	lid, _ := f.create(t, ceremony.KindLogin, "staff", nil, nil, 2*time.Minute)
	if _, ok := f.spend(t, ceremony.KindRegister, "staff", lid, nil, nil); ok {
		t.Fatal("a login ceremony was spent as a register")
	}
	f.assertLive(t, lid)
	if _, ok := f.spend(t, ceremony.KindLogin, "staff", lid, nil, nil); !ok {
		t.Fatal("the login ceremony was refused for its own kind after a refused spend")
	}
}

func TestSpendRefusesAnotherAudience(t *testing.T) {
	f := setup(t)
	A := f.d.NewPrincipal(t, "ada@example.invalid")
	S := f.session(t, A)
	id, _ := f.create(t, ceremony.KindRegister, "staff", ptr(A), ptr(S), 2*time.Minute)
	if _, ok := f.spend(t, ceremony.KindRegister, "client", id, ptr(A), ptr(S)); ok {
		t.Fatal("a staff ceremony was spent for the client audience")
	}
	f.assertLive(t, id)
	if _, ok := f.spend(t, ceremony.KindRegister, "staff", id, ptr(A), ptr(S)); !ok {
		t.Fatal("the staff ceremony was refused for its own audience after a refused spend")
	}

	lid, _ := f.create(t, ceremony.KindLogin, "staff", nil, nil, 2*time.Minute)
	if _, ok := f.spend(t, ceremony.KindLogin, "client", lid, nil, nil); ok {
		t.Fatal("a staff login ceremony was spent for the client audience")
	}
	f.assertLive(t, lid)
	if _, ok := f.spend(t, ceremony.KindLogin, "staff", lid, nil, nil); !ok {
		t.Fatal("the staff login ceremony was refused for its own audience after a refused spend")
	}
}

func TestSpendRefusesAnotherPrincipal(t *testing.T) {
	f := setup(t)
	A := f.d.NewPrincipal(t, "ada@example.invalid")
	B := f.d.NewPrincipal(t, "bob@example.invalid")
	S := f.session(t, A)
	id, _ := f.create(t, ceremony.KindRegister, "staff", ptr(A), ptr(S), 2*time.Minute)
	if _, ok := f.spend(t, ceremony.KindRegister, "staff", id, ptr(B), ptr(S)); ok {
		t.Fatal("a ceremony of one principal was spent for another")
	}
	f.assertLive(t, id)
	if _, ok := f.spend(t, ceremony.KindRegister, "staff", id, nil, ptr(S)); ok {
		t.Fatal("a ceremony with a principal was spent with no principal")
	}
	f.assertLive(t, id)
	if _, ok := f.spend(t, ceremony.KindRegister, "staff", id, ptr(A), ptr(S)); !ok {
		t.Fatal("the ceremony was refused for its own principal after refused spends")
	}
}

func TestSpendRefusesAnotherSession(t *testing.T) {
	f := setup(t)
	A := f.d.NewPrincipal(t, "ada@example.invalid")
	S1 := f.session(t, A)
	S2 := f.session(t, A)
	id, _ := f.create(t, ceremony.KindRegister, "staff", ptr(A), ptr(S1), 2*time.Minute)
	if _, ok := f.spend(t, ceremony.KindRegister, "staff", id, ptr(A), ptr(S2)); ok {
		t.Fatal("a ceremony of one session was spent in another")
	}
	f.assertLive(t, id)
	if _, ok := f.spend(t, ceremony.KindRegister, "staff", id, ptr(A), nil); ok {
		t.Fatal("a ceremony with a session was spent with no session")
	}
	f.assertLive(t, id)
	if _, ok := f.spend(t, ceremony.KindRegister, "staff", id, ptr(A), ptr(S1)); !ok {
		t.Fatal("the ceremony was refused for its own session after refused spends")
	}
}

func TestSpendIsOnce(t *testing.T) {
	f := setup(t)
	A := f.d.NewPrincipal(t, "ada@example.invalid")
	S := f.session(t, A)
	id, _ := f.create(t, ceremony.KindRegister, "staff", ptr(A), ptr(S), 2*time.Minute)
	if _, ok := f.spend(t, ceremony.KindRegister, "staff", id, ptr(A), ptr(S)); !ok {
		t.Fatal("the first spend was refused")
	}
	if _, ok := f.spend(t, ceremony.KindRegister, "staff", id, ptr(A), ptr(S)); ok {
		t.Fatal("a spent ceremony was spent again")
	}
	if n := f.count(t, `SELECT count(*) FROM auth_passkey_ceremonies WHERE ceremony_hash = $1 AND used_at = $2`, hashOf(id), f.clock.Now()); n != 1 {
		t.Fatalf("the spend did not record used_at: %d rows, want 1", n)
	}

	lid, _ := f.create(t, ceremony.KindLogin, "staff", nil, nil, 2*time.Minute)
	if _, ok := f.spend(t, ceremony.KindLogin, "staff", lid, nil, nil); !ok {
		t.Fatal("the first login spend was refused")
	}
	if _, ok := f.spend(t, ceremony.KindLogin, "staff", lid, nil, nil); ok {
		t.Fatal("a spent login ceremony was spent again")
	}
}

func TestSpendMatchesALoginCeremonyWithNoOwner(t *testing.T) {
	f := setup(t)
	A := f.d.NewPrincipal(t, "ada@example.invalid")
	first, _ := f.create(t, ceremony.KindLogin, "staff", nil, nil, 2*time.Minute)
	if _, ok := f.spend(t, ceremony.KindLogin, "staff", first, nil, nil); !ok {
		t.Fatal("a login ceremony with no owner was refused for no owner")
	}
	second, _ := f.create(t, ceremony.KindLogin, "staff", nil, nil, 2*time.Minute)
	if _, ok := f.spend(t, ceremony.KindLogin, "staff", second, ptr(A), nil); ok {
		t.Fatal("a login ceremony with no owner was spent for a principal")
	}
	f.assertLive(t, second)
}

func TestSpendHonoursTheTTLOnTheInjectedClock(t *testing.T) {
	f := setup(t)
	a, _ := f.create(t, ceremony.KindLogin, "staff", nil, nil, 2*time.Minute)
	b, _ := f.create(t, ceremony.KindLogin, "staff", nil, nil, 2*time.Minute)
	c, _ := f.create(t, ceremony.KindLogin, "staff", nil, nil, 2*time.Minute)
	f.clock.Advance(2*time.Minute - time.Second)
	if _, ok := f.spend(t, ceremony.KindLogin, "staff", a, nil, nil); !ok {
		t.Fatal("a ceremony one second before its expiry was refused")
	}
	f.clock.Advance(time.Second)
	if _, ok := f.spend(t, ceremony.KindLogin, "staff", b, nil, nil); ok {
		t.Fatal("a ceremony at exactly its expiry was spent")
	}
	f.clock.Advance(time.Second)
	if _, ok := f.spend(t, ceremony.KindLogin, "staff", c, nil, nil); ok {
		t.Fatal("a ceremony one second past its expiry was spent")
	}
	if n := f.count(t, `SELECT count(*) FROM auth_passkey_ceremonies WHERE used_at IS NULL`); n != 2 {
		t.Fatalf("%d ceremonies are unspent, want 2", n)
	}
}

func TestSpendConcurrentOnlyOneWins(t *testing.T) {
	f := setup(t)
	id, _ := f.create(t, ceremony.KindLogin, "staff", nil, nil, 2*time.Minute)
	// WHY: a holder locks the row first, so all 16 spends queue on it and race when it lets go.
	holder, err := f.d.Owner.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(f.ctx, `SELECT 1 FROM auth_passkey_ceremonies FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	const n = 16
	type answer struct {
		ok  bool
		err error
	}
	answers := make(chan answer, n)
	var wg sync.WaitGroup
	now := f.clock.Now()
	for range n {
		wg.Go(func() {
			var ok bool
			err := f.d.InAuthTx(f.ctx, func(q db.Querier) error {
				var err error
				_, ok, err = ceremony.Spend(f.ctx, q, ceremony.KindLogin, "staff", id, nil, nil, now)
				return err
			})
			answers <- answer{ok, err}
		})
	}
	f.d.WaitForLockWaiters(t, n)
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(answers)
	won, lost := 0, 0
	for a := range answers {
		switch {
		case a.err != nil:
			t.Errorf("a spend failed: %v", a.err)
		case a.ok:
			won++
		default:
			lost++
		}
	}
	if won != 1 || lost != n-1 {
		t.Fatalf("%d spends won and %d were refused, want 1 and %d", won, lost, n-1)
	}
}

func TestSpendReturnsTheStoredSessionData(t *testing.T) {
	f := setup(t)
	A := f.d.NewPrincipal(t, "ada@example.invalid")
	S := f.session(t, A)
	user := make([]byte, len(A))
	copy(user, A[:])
	in := webauthn.SessionData{
		Challenge:            "Y2VyZW1vbnktY2hhbGxlbmdlLTAx",
		RelyingPartyID:       "localhost",
		UserID:               user,
		AllowedCredentialIDs: [][]byte{{1, 2, 3}},
		UserVerification:     protocol.VerificationRequired,
		Expires:              f.clock.Now().Add(2 * time.Minute),
	}
	var id string
	if err := f.d.InAuthTx(f.ctx, func(q db.Querier) error {
		var err error
		id, _, err = ceremony.Create(f.ctx, q, f.rnd, ceremony.KindRegister, "staff", ptr(A), ptr(S), in, f.clock.Now(), 2*time.Minute)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	out, ok := f.spend(t, ceremony.KindRegister, "staff", id, ptr(A), ptr(S))
	if !ok {
		t.Fatal("the stored ceremony was refused")
	}
	if out.Challenge != in.Challenge {
		t.Errorf("Challenge differs: <redacted>")
	}
	if out.RelyingPartyID != in.RelyingPartyID {
		t.Errorf("RelyingPartyID differs")
	}
	if out.UserVerification != in.UserVerification {
		t.Errorf("UserVerification differs")
	}
	if !bytes.Equal(out.UserID, in.UserID) {
		t.Errorf("UserID differs")
	}
	if len(out.AllowedCredentialIDs) != 1 || !bytes.Equal(out.AllowedCredentialIDs[0], []byte{1, 2, 3}) {
		t.Errorf("AllowedCredentialIDs differs: %v", out.AllowedCredentialIDs)
	}
	if !out.Expires.Equal(in.Expires) {
		t.Errorf("Expires differs: %v, want %v", out.Expires, in.Expires)
	}
}

func TestCeremonyNeedsATransaction(t *testing.T) {
	f := setup(t)
	conn, err := f.d.App.Conn(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	q := sqldb.Conn(conn)
	now := f.clock.Now()
	if _, _, err := ceremony.Create(f.ctx, q, f.rnd, ceremony.KindLogin, "staff", nil, nil, data("c"), now, time.Minute); !errors.Is(err, db.ErrTxRequired) {
		t.Errorf("Create on a bare connection: %v, want ErrTxRequired", err)
	}
	if _, _, err := ceremony.Spend(f.ctx, q, ceremony.KindLogin, "staff", "x", nil, nil, now); !errors.Is(err, db.ErrTxRequired) {
		t.Errorf("Spend on a bare connection: %v, want ErrTxRequired", err)
	}
	if _, err := ceremony.Prune(f.ctx, q, now); !errors.Is(err, db.ErrTxRequired) {
		t.Errorf("Prune on a bare connection: %v, want ErrTxRequired", err)
	}
	if n := f.count(t, `SELECT count(*) FROM auth_passkey_ceremonies`); n != 0 {
		t.Fatalf("a bare connection wrote %d rows, want 0", n)
	}
}
