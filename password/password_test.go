package password_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sylly-mika/authkit/password"
)

var cheap = password.Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

func hasher(t *testing.T, p password.Params, slots int, wait time.Duration) *password.Hasher {
	t.Helper()
	h, err := password.NewHasher(p, slots, wait, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestTheDefaultsAreTheSpecParameters(t *testing.T) {
	if want := (password.Params{Memory: 19456, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}); password.Default != want {
		t.Fatalf("Default = %+v, want %+v (spec §8.7)", password.Default, want)
	}
	h, err := password.Encode(password.Default, rand.Reader, "a password")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(h, "$")
	if len(parts) != 6 || !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash %q is not an argon2id PHC string with the spec parameters", h)
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	key, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) != 16 || len(key) != 32 {
		t.Fatalf("salt %d bytes, key %d bytes (%v, %v); want 16 and 32", len(salt), len(key), err1, err2)
	}
}

func TestTheDummyUsesTheHashersParameters(t *testing.T) {
	p := password.Params{Memory: 256, Time: 3, Threads: 2, SaltLen: 24, KeyLen: 48}
	got, err := password.DummyParams(hasher(t, p, 1, time.Second))
	if err != nil || got != p {
		t.Fatalf("the dummy is hashed under %+v (%v), want the hasher's %+v (spec §8.6)", got, err, p)
	}
}

func TestVerifyAcceptsOnlyTheRightPassword(t *testing.T) {
	h := hasher(t, cheap, 4, time.Second)
	ctx := context.Background()
	stored, err := h.Hash(ctx, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := h.Verify(ctx, stored, "correct horse battery"); !ok || err != nil {
		t.Fatalf("the right password = %v, %v", ok, err)
	}
	if ok, err := h.Verify(ctx, stored, "correct horse batterY"); ok || err != nil {
		t.Fatalf("a wrong password = %v, %v", ok, err)
	}
}

func TestVerifyIgnoresTheUnicodeFormOfThePassword(t *testing.T) {
	h := hasher(t, cheap, 1, time.Second)
	ctx := context.Background()
	stored, err := h.Hash(ctx, "pārole ar čūsku")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := h.Verify(ctx, stored, "pa\u0304role ar c\u030cu\u0304sku"); !ok || err != nil {
		t.Fatalf("the same password in decomposed form = %v, %v", ok, err)
	}
}

func TestVerifyUsesTheStoredParameters(t *testing.T) {
	stored, err := password.Encode(cheap, rand.Reader, "an old password")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := hasher(t, password.Default, 4, time.Second).Verify(context.Background(), stored, "an old password"); !ok || err != nil {
		t.Fatalf("a hash made with other parameters = %v, %v", ok, err)
	}
}

func TestNeedsRehashWhenAParameterRises(t *testing.T) {
	stored, err := password.Encode(cheap, rand.Reader, "a password")
	if err != nil {
		t.Fatal(err)
	}
	if hasher(t, cheap, 1, time.Second).NeedsRehash(stored) {
		t.Fatal("a hash at the current parameters needs a rehash")
	}
	for _, rise := range []func(*password.Params){
		func(p *password.Params) { p.Memory = 128 },
		func(p *password.Params) { p.Time = 2 },
		func(p *password.Params) { p.Threads = 2 },
		func(p *password.Params) { p.KeyLen = 64 },
		func(p *password.Params) { p.SaltLen = 32 },
	} {
		p := cheap
		rise(&p)
		if !hasher(t, p, 1, time.Second).NeedsRehash(stored) {
			t.Errorf("parameters %+v over %+v did not ask for a rehash", p, cheap)
		}
	}
}

func TestVerifyRefusesAMalformedHash(t *testing.T) {
	h := hasher(t, cheap, 1, time.Second)
	for _, bad := range []string{
		"",
		"$2a$12$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234",
		"$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5",
		"$argon2id$v=18$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5",
		"$argon2id$v=19$m=64,t=1,p=0$c2FsdHNhbHRzYWx0$a2V5",
		"$argon2id$v=19$m=64,t=1,p=1$not*base64$a2V5",
		"$argon2id$v=19$m=64,t=1,p=1$$a2V5",
		"$argon2id$v=19$m=64,t=1,p=1junk$c2FsdHNhbHRzYWx0$a2V5",
		"$argon2id$v=19$m=64,t=1,p=1,keyid=x$c2FsdHNhbHRzYWx0$a2V5",
		"$argon2id$v=19$m= 64,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5",
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdHNh\nbHRzYWx0$a2V5",
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$a2V",
		"$argon2id$v=19$m=1048584,t=1,p=1$c2FsdHNhbHRzYWx0$a2V5",
		"$argon2id$v=19$m=64,t=17,p=1$c2FsdHNhbHRzYWx0$a2V5",
	} {
		if _, err := h.Verify(context.Background(), bad, "x"); !errors.Is(err, password.ErrMalformed) {
			t.Errorf("Verify(%q) = %v, want ErrMalformed", bad, err)
		}
	}
}

func TestTheCeilingRefusesAfterTheWait(t *testing.T) {
	h := hasher(t, cheap, 1, 50*time.Millisecond)
	ctx := context.Background()
	release, err := h.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := h.Hash(ctx, "a password"); !errors.Is(err, password.ErrBusy) {
		t.Fatalf("Hash with every slot taken = %v, want ErrBusy (spec §8.7)", err)
	}
	if waited := time.Since(start); waited < 50*time.Millisecond {
		t.Fatalf("ErrBusy after %v, want after the 50 ms wait", waited)
	}
	if err := h.VerifyDummy(ctx, "a password"); !errors.Is(err, password.ErrBusy) {
		t.Fatalf("VerifyDummy with every slot taken = %v, want ErrBusy", err)
	}
	release()
	if _, err := h.Hash(ctx, "a password"); err != nil {
		t.Fatalf("Hash after the release = %v", err)
	}
}

func TestACancelledRequestStopsWaitingForASlot(t *testing.T) {
	h := hasher(t, cheap, 1, time.Minute)
	release, _ := h.Acquire(context.Background())
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Hash(ctx, "a password"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Hash on a cancelled context = %v", err)
	}
}

func TestNewHasherRefusesUnusableParameters(t *testing.T) {
	for _, p := range []password.Params{
		{Memory: 64, Time: 0, Threads: 1, SaltLen: 16, KeyLen: 32},
		{Memory: 64, Time: 1, Threads: 0, SaltLen: 16, KeyLen: 32},
		{Memory: 64, Time: 1, Threads: 1, SaltLen: 0, KeyLen: 32},
		{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 0},
		{Memory: 4, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32},
	} {
		if _, err := password.NewHasher(p, 1, time.Second, rand.Reader); err == nil {
			t.Errorf("NewHasher(%+v) made a hasher whose hashes would not verify", p)
		}
	}
	if _, err := password.NewHasher(cheap, 0, time.Second, rand.Reader); err == nil {
		t.Error("NewHasher with no slots made a hasher")
	}
}

// TestHoldServesTheWorkUnderItsContext is spec §3.2: the slot an app takes
// before its transaction serves the hashing under that context, and no other.
func TestHoldServesTheWorkUnderItsContext(t *testing.T) {
	h := hasher(t, cheap, 1, 50*time.Millisecond)
	ctx := context.Background()
	held, release, err := h.Hold(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Hash(held, "a password"); err != nil {
		t.Fatalf("Hash under the held context = %v, want it to hash on the held slot", err)
	}
	if err := h.VerifyDummy(held, "a password"); err != nil {
		t.Fatalf("VerifyDummy under the held context = %v", err)
	}
	if _, err := h.Hash(ctx, "a password"); !errors.Is(err, password.ErrBusy) {
		t.Fatalf("Hash outside it = %v, want ErrBusy: the one slot is held", err)
	}
	release()
	other, err := h.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire after the release = %v", err)
	}
	if _, err := h.Hash(held, "a password"); !errors.Is(err, password.ErrBusy) {
		t.Fatalf("Hash under a released hold, the ceiling full = %v, want ErrBusy: a released slot is not reused", err)
	}
	release()
	if _, err := h.Acquire(ctx); !errors.Is(err, password.ErrBusy) {
		t.Fatalf("Acquire after a second release = %v, want ErrBusy: release must free its slot once", err)
	}
	other()
}
