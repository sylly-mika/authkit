package authkit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// TestAnAppHeldSlotServesTheHashingMethods is spec §3.2: under the context
// AcquireHashSlot returns, the methods hash on its slot, so a ceiling of one
// never refuses them, while a call outside it is Busy.
func TestAnAppHeldSlotServesTheHashingMethods(t *testing.T) {
	for name, tweak := range map[string]func(*authkit.Config){"count-before": defaults, "CountAfterVerify": func(*authkit.Config) {}} {
		w := newWorld(t, tweak, func(c *authkit.Config) { c.HashConcurrency, c.HashWait = 1, 50*time.Millisecond })
		ada := authkit.Principal{ID: w.user("ada@example.invalid", "the right password"), Login: "ada@example.invalid"}
		invited := authkit.Principal{ID: w.user("invited@example.invalid", ""), Login: "invited@example.invalid"}
		held, release, res, err := w.svc.AcquireHashSlot(w.ctx)
		if err != nil || res.Refusal != nil {
			t.Fatalf("%s: AcquireHashSlot = %v, %v", name, res.Refusal, err)
		}
		for call, fn := range map[string]func(ctx context.Context, q db.Querier) (authkit.Result, error){
			"Login": func(ctx context.Context, q db.Querier) (authkit.Result, error) {
				return w.svc.Login(ctx, q, "staff", "ada@example.invalid", "the right password", authkit.Meta{})
			},
			"SetPassword": func(ctx context.Context, q db.Querier) (authkit.Result, error) {
				return w.svc.SetPassword(ctx, q, invited, "staff", "a first password", authkit.Meta{})
			},
			"VerifyPassword": func(ctx context.Context, q db.Querier) (authkit.Result, error) {
				return w.svc.VerifyPassword(ctx, q, ada, "staff", "the right password", authkit.Meta{})
			},
		} {
			if res := w.inAuth(func(q db.Querier) (authkit.Result, error) { return fn(held, q) }); res.Refusal != nil {
				t.Errorf("%s: %s under the held slot = %v", name, call, res.Refusal)
			}
			if res := w.inAuth(func(q db.Querier) (authkit.Result, error) { return fn(w.ctx, q) }); !errors.Is(res.Refusal, authkit.ErrBusy) {
				t.Errorf("%s: %s outside it = %v, want ErrBusy", name, call, res.Refusal)
			}
		}
		release()
	}
}

func TestAcquireHashSlotRefusesBusyAndReturnsTheContextsError(t *testing.T) {
	w := newWorld(t, defaults, func(c *authkit.Config) { c.HashConcurrency, c.HashWait = 1, 50*time.Millisecond })
	_, release, _, err := w.svc.AcquireHashSlot(w.ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctx, noop, res, err := w.svc.AcquireHashSlot(w.ctx)
	if err != nil || !errors.Is(res.Refusal, authkit.ErrBusy) || ctx != w.ctx || noop == nil {
		t.Fatalf("a second slot of one = %v, %v; want the Busy refusal, the caller's context and a release", res.Refusal, err)
	}
	noop()
	cancelled, cancel := context.WithCancel(w.ctx)
	cancel()
	if _, _, res, err := w.svc.AcquireHashSlot(cancelled); !errors.Is(err, context.Canceled) || res.Refusal != nil {
		t.Fatalf("a cancelled wait = %v, %v; want context.Canceled as the error", res.Refusal, err)
	}
	release()
	if _, again, res, err := w.svc.AcquireHashSlot(w.ctx); err != nil || res.Refusal != nil {
		t.Fatalf("after the release = %v, %v", res.Refusal, err)
	} else {
		again()
	}
}
