package factor_test

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/factor"
)

func hashOf(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func TestAcceptStepTakesOnlyALaterStep(t *testing.T) {
	d := authkittest.NewDB(t)
	ctx := context.Background()
	now := authkittest.NewClock().Now()
	A := d.NewPrincipal(t, "ada@example.invalid")
	B := d.NewPrincipal(t, "bob@example.invalid")
	d.Exec(t, `INSERT INTO auth_second_factors (principal_id, kind, secret, last_step, created_at, confirmed_at) VALUES ($1, 'totp', $2, 100, $3, $3)`, A, []byte{1}, now)
	d.Exec(t, `INSERT INTO auth_second_factors (principal_id, kind, secret, last_step, created_at, confirmed_at) VALUES ($1, 'totp', $2, NULL, $3, NULL)`, B, []byte{1}, now)

	accept := func(p uuid.UUID, step int64) bool {
		t.Helper()
		var ok bool
		if err := d.InAuthTx(ctx, func(q db.Querier) error {
			var err error
			ok, err = factor.AcceptStep(ctx, q, p, step)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return ok
	}

	if accept(A, 100) {
		t.Error("AcceptStep took the step it already holds")
	}
	if accept(A, 99) {
		t.Error("AcceptStep took an earlier step")
	}
	if !accept(A, 101) {
		t.Fatal("AcceptStep refused a later step")
	}
	var last int64
	if err := d.Row(t, `SELECT last_step FROM auth_second_factors WHERE principal_id = $1 AND kind = 'totp'`, A).Scan(&last); err != nil {
		t.Fatal(err)
	}
	if last != 101 {
		t.Errorf("last_step = %d, want 101", last)
	}
	if accept(A, 101) {
		t.Error("AcceptStep took the same step twice")
	}
	if accept(B, 5) {
		t.Error("AcceptStep took a step on a pending factor")
	}
}

func TestSpendRecoveryCodeIsOnce(t *testing.T) {
	d := authkittest.NewDB(t)
	ctx := context.Background()
	now := authkittest.NewClock().Now()
	A := d.NewPrincipal(t, "ada@example.invalid")
	B := d.NewPrincipal(t, "bob@example.invalid")
	h1, h2, h3 := hashOf("one"), hashOf("two"), hashOf("three")

	inTx := func(fn func(q db.Querier) error) {
		t.Helper()
		if err := d.InAuthTx(ctx, fn); err != nil {
			t.Fatal(err)
		}
	}
	inTx(func(q db.Querier) error {
		return factor.ReplaceRecoveryCodes(ctx, q, authkittest.Rand(1), A, [][]byte{h1, h2}, now)
	})
	inTx(func(q db.Querier) error {
		return factor.ReplaceRecoveryCodes(ctx, q, authkittest.Rand(2), B, [][]byte{h3}, now)
	})

	spend := func(p uuid.UUID, h []byte) bool {
		t.Helper()
		var ok bool
		inTx(func(q db.Querier) error {
			var err error
			ok, err = factor.SpendRecoveryCode(ctx, q, p, h, now)
			return err
		})
		return ok
	}
	left := func(p uuid.UUID) int {
		t.Helper()
		var n int
		inTx(func(q db.Querier) error {
			var err error
			n, err = factor.RecoveryCodesLeft(ctx, q, p)
			return err
		})
		return n
	}

	if !spend(A, h1) {
		t.Fatal("SpendRecoveryCode refused an unused code")
	}
	if spend(A, h1) {
		t.Error("SpendRecoveryCode spent the same code twice")
	}
	if got := left(A); got != 1 {
		t.Errorf("RecoveryCodesLeft(A) = %d, want 1", got)
	}
	if spend(A, h3) {
		t.Error("SpendRecoveryCode spent another principal's code")
	}
	if got := left(B); got != 1 {
		t.Errorf("RecoveryCodesLeft(B) = %d, want 1", got)
	}
}
