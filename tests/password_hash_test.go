package tests

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/password"
)

func (w *world) hash(pw string) password.Hash {
	w.T.Helper()
	h, err := w.Svc.Password.Hash(w.Ctx, pw)
	if err != nil {
		w.T.Fatal(err)
	}
	return h
}

func (w *world) setHash(id uuid.UUID, h password.Hash) error {
	return w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		return w.Svc.Password.SetHash(w.Ctx, q, authkit.Principal{ID: id}, h)
	})
}

func TestHashPolicy(t *testing.T) {
	w := newWorld(t, func(r *kittest.Rules) { r.Password.Password = password.Policy{MinRunes: 12, MaxRunes: 256} })
	short := password.PolicyError{MinRunes: 12, MaxRunes: 256}
	long := password.PolicyError{MinRunes: 12, MaxRunes: 256, TooLong: true}
	for _, tc := range []struct {
		name string
		pw   string
		want *password.PolicyError
	}{
		{"short", strings.Repeat("a", 11), &short},
		{"too long", strings.Repeat("a", 257), &long},
		{"short in NFC runes", strings.Repeat("é", 11), &short},
		{"at the minimum", strings.Repeat("é", 12), nil},
		{"at the maximum", strings.Repeat("a", 256), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := w.Svc.Password.Hash(w.Ctx, tc.pw)
			if tc.want == nil {
				if err != nil || h == (password.Hash{}) {
					t.Fatalf("Hash = (zero %v, %v); want a hash", h == (password.Hash{}), err)
				}
				return
			}
			var pe password.PolicyError
			if !errors.As(err, &pe) || pe != *tc.want {
				t.Fatalf("Hash error = %v; want PolicyError %+v", err, *tc.want)
			}
			if h != (password.Hash{}) {
				t.Fatal("Hash returned a hash with the refusal; want the zero Hash")
			}
		})
	}
}

func TestHashBusy(t *testing.T) {
	w := newWorld(t, func(r *kittest.Rules) { r.Password.HashConcurrency = 1 })
	held, release, res, err := w.Svc.Password.AcquireHashSlot(w.Ctx)
	if err != nil || res.Refusal != nil {
		t.Fatalf("AcquireHashSlot = refusal %v, error %v; want the slot", res.Refusal, err)
	}
	defer release()
	start := time.Now()
	h, err := w.Svc.Password.Hash(w.Ctx, "a long enough password")
	if !errors.Is(err, password.ErrBusy) || h != (password.Hash{}) {
		t.Fatalf("Hash with the only slot taken = zero %v, error %v; want ErrBusy and the zero Hash", h == (password.Hash{}), err)
	}
	if d := time.Since(start); d < w.Cfg.Password.HashWait {
		t.Fatalf("Hash refused after %v; want it to wait HashWait %v first", d, w.Cfg.Password.HashWait)
	}
	if _, err := w.Svc.Password.Hash(held, "a long enough password"); err != nil {
		t.Fatalf("Hash under the held slot: %v", err)
	}
	release()
	if _, err := w.Svc.Password.Hash(w.Ctx, "a long enough password"); err != nil {
		t.Fatalf("Hash after release: %v", err)
	}
}

func TestHashNFC(t *testing.T) {
	w := newWorld(t)
	const ada = "ada@example.invalid"
	id := w.User(ada, "")
	if err := w.setHash(id, w.hash("café au lait")); err != nil {
		t.Fatalf("SetHash: %v", err)
	}
	if res := w.Login("staff", ada, "café au lait"); res.Refusal != nil || res.Session == nil {
		t.Fatalf("Login with the composed form refused (%v); want the password accepted", res.Refusal)
	}
	if res := w.Login("staff", ada, "café au lait"); res.Refusal != nil {
		t.Fatalf("Login with the decomposed form refused (%v); want the password accepted", res.Refusal)
	}
}

func TestHashUsesTheModuleHasher(t *testing.T) {
	w := newWorld(t, func(r *kittest.Rules) {
		r.Password.Hashing = password.Params{Memory: 128, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}
	})
	const ada = "ada@example.invalid"
	id := w.User(ada, "")
	if err := w.setHash(id, w.hash("a long enough password")); err != nil {
		t.Fatalf("SetHash: %v", err)
	}
	before := w.StoredHash(id)
	if !strings.HasPrefix(before, "$argon2id$v=19$m=128,t=1,p=1$") {
		t.Fatal("the stored hash is not under the module's parameters m=128,t=1,p=1")
	}
	if res := w.SignIn(ada, "a long enough password"); res.Refusal != nil {
		t.Fatalf("SignIn refused: %v", res.Refusal)
	}
	if w.StoredHash(id) != before {
		t.Fatal("the stored hash changed at sign-in; want no rehash under the module's parameters")
	}
}

func TestSetHashOnce(t *testing.T) {
	w := newWorld(t)
	const ada = "ada@example.invalid"
	id := w.User(ada, "")
	if err := w.setHash(id, w.hash("the first password")); err != nil {
		t.Fatalf("first SetHash: %v", err)
	}
	if got := w.Results(id); len(got) != 0 {
		t.Fatalf("SetHash recorded events %v; want none", got)
	}
	if n := w.Count("SELECT count(*) FROM auth_credentials WHERE principal_id = $1 AND changed_at = $2", id, w.Clock.Now()); n != 1 {
		t.Fatalf("credential rows changed at the clock = %d; want 1", n)
	}
	before := w.StoredHash(id)
	var setErr error
	var has bool
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		setErr = w.Svc.Password.SetHash(w.Ctx, q, authkit.Principal{ID: id}, w.hash("the second password"))
		var err error
		has, err = w.Svc.Password.HasCredential(w.Ctx, q, id)
		return err
	}); err != nil {
		t.Fatalf("the transaction after the refused SetHash: %v", err)
	}
	if !errors.Is(setErr, password.ErrCredentialExists) {
		t.Fatalf("second SetHash = %v; want ErrCredentialExists", setErr)
	}
	if !has {
		t.Fatal("HasCredential = false after the refused SetHash; want true")
	}
	if w.StoredHash(id) != before {
		t.Fatal("the stored hash changed by the refused SetHash")
	}
	if res := w.SignIn(ada, "the first password"); res.Refusal != nil {
		t.Fatalf("SignIn with the first password refused: %v", res.Refusal)
	}
	if res := w.Login("staff", ada, "the second password"); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("Login with the second password = %v; want ErrInvalidCredentials", res.Refusal)
	}
}

func TestSetHashRace(t *testing.T) {
	w := newWorld(t)
	const ada = "ada@example.invalid"
	id := w.User(ada, "")
	first, second := w.hash("the first password"), w.hash("the second password")
	holder, err := w.D.App.BeginTx(w.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if err := w.Svc.Password.SetHash(w.Ctx, sqldb.Tx(holder), authkit.Principal{ID: id}, first); err != nil {
		t.Fatalf("SetHash in the holder transaction: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- w.setHash(id, second) }()
	w.D.WaitForLockWaiters(t, 1)
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, password.ErrCredentialExists) {
		t.Fatalf("SetHash that waited for the first = %v; want ErrCredentialExists", err)
	}
	if res := w.SignIn(ada, "the first password"); res.Refusal != nil {
		t.Fatalf("SignIn with the first password refused: %v", res.Refusal)
	}
	if res := w.Login("staff", ada, "the second password"); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("Login with the second password = %v; want ErrInvalidCredentials", res.Refusal)
	}
}

func TestSetHashZero(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "")
	if err := w.setHash(id, password.Hash{}); !errors.Is(err, password.ErrNoHash) {
		t.Fatalf("SetHash with the zero Hash = %v; want ErrNoHash", err)
	}
	if n := w.Count("SELECT count(*) FROM auth_credentials WHERE principal_id = $1", id); n != 0 {
		t.Fatalf("credential rows after the refused SetHash = %d; want 0", n)
	}
}

func TestSetHashNeedsTx(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "")
	h := w.hash("a long enough password")
	var n int
	q := counted{Querier: sqldb.Conn(w.Pinned(id)), n: &n}
	if err := w.Svc.Password.SetHash(w.Ctx, q, authkit.Principal{ID: id}, h); !errors.Is(err, db.ErrTxRequired) {
		t.Fatalf("SetHash on a bare connection = %v; want db.ErrTxRequired", err)
	}
	if n != 0 {
		t.Fatalf("SetHash on a bare connection ran %d statements; want none", n)
	}
	if c := w.Count("SELECT count(*) FROM auth_credentials WHERE principal_id = $1", id); c != 0 {
		t.Fatalf("credential rows after the bare SetHash = %d; want 0", c)
	}
}
