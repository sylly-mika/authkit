package tests

import (
	"errors"
	"strings"
	"testing"
	"time"

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
