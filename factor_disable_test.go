package authkit_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
)

func TestDisableNeedsARecentSignIn(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	secret, _ := w.setUpTOTP(c)
	w.enrolEmail(c)
	_, before, _ := w.totpRow(ada)
	w.clock.Advance(5*time.Minute + time.Second)

	res := w.disable(c, authkit.FactorTOTP, authkit.FactorProof{Method: authkit.FactorTOTP, Code: totpCode(w.t, secret, w.clock.Now())})
	if !errors.Is(res.Refusal, authkit.ErrReauthRequired) {
		t.Fatalf("DisableSecondFactor after 5m = %v, want ErrReauthRequired", res.Refusal)
	}
	if n := w.count(`SELECT count(*) FROM auth_second_factors WHERE principal_id = $1 AND confirmed_at IS NOT NULL`, ada); n != 2 {
		t.Errorf("confirmed factor rows = %d, want 2", n)
	}
	if _, after, _ := w.totpRow(ada); after != before {
		t.Errorf("totp last_step changed from %v to %v", before, after)
	}
	if n := w.count(`SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1`, ada); n != 10 {
		t.Errorf("recovery rows = %d, want 10", n)
	}
	if n := w.events(ada, "factor_removed"); n != 0 {
		t.Errorf("factor_removed events = %d, want 0", n)
	}
	if n := w.count(`SELECT count(*) FROM auth_throttle`); n != 0 {
		t.Errorf("throttle rows = %d, want 0", n)
	}
}

func TestDisableNeedsACurrentCode(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	secret, _ := w.setUpTOTP(c)
	w.clock.Advance(30 * time.Second)
	for _, proof := range []authkit.FactorProof{
		{Method: authkit.FactorTOTP, Code: w.wrongTOTP(secret)},
		{},
		{Method: authkit.FactorPasskey, Code: "123456"},
	} {
		if res := w.disable(c, authkit.FactorTOTP, proof); !errors.Is(res.Refusal, authkit.ErrBadCode) {
			t.Fatalf("DisableSecondFactor with method %q = %v, want ErrBadCode", proof.Method, res.Refusal)
		}
	}
	if _, _, confirmed := w.totpRow(ada); !confirmed {
		t.Errorf("the totp factor was removed by a refused disable")
	}
	if n := w.count(`SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1 AND used_at IS NULL`, ada); n != 10 {
		t.Errorf("unused recovery rows = %d, want 10", n)
	}
	if n := w.count(`SELECT failures FROM auth_throttle WHERE login = 'ada@example.invalid' AND audience = 'staff'`); n != 3 {
		t.Errorf("throttle failures = %d, want 3", n)
	}
	var kinds []string
	rows, err := w.d.Owner.Query(`SELECT second_factor FROM auth_events WHERE principal_id = $1 AND source = 'second_factor' AND result = 'bad_code' ORDER BY second_factor`, ada)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, k)
	}
	rows.Close()
	if !slices.Equal(kinds, []string{"", "", "totp"}) {
		t.Errorf("bad_code second_factor values = %q, want [\"\" \"\" \"totp\"]", kinds)
	}
	if n := w.events(ada, "factor_removed"); n != 0 {
		t.Errorf("factor_removed events = %d, want 0", n)
	}

	if res := w.disable(c, authkit.FactorTOTP, authkit.FactorProof{Method: authkit.FactorTOTP, Code: totpCode(w.t, secret, w.clock.Now())}); res.Refusal != nil {
		t.Errorf("control disable with a current code = %v, want nil", res.Refusal)
	}
}

func TestDisableTheLastFactorWithItsOwnCode(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	a := w.signIn("ada@example.invalid", "the right password")
	c := w.claims(a)
	a2 := w.signIn("ada@example.invalid", "the right password")

	secret, _ := w.setUpTOTP(c)
	w.clock.Advance(30 * time.Second)
	res := w.disable(c, authkit.FactorTOTP, authkit.FactorProof{Method: authkit.FactorTOTP, Code: totpCode(w.t, secret, w.clock.Now())})
	if res.Refusal != nil || res.RecoveryCodesLeft != nil {
		t.Fatalf("DisableSecondFactor = %v, RecoveryCodesLeft %v; want nil and nil", res.Refusal, res.RecoveryCodesLeft)
	}
	if n := w.count(`SELECT count(*) FROM auth_second_factors WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("factor rows = %d, want 0", n)
	}
	if n := w.count(`SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("recovery rows = %d, want 0", n)
	}
	if n := w.count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND source = 'second_factor' AND result = 'factor_removed' AND second_factor = 'totp'`, ada); n != 1 {
		t.Errorf("factor_removed events = %d, want 1", n)
	}
	if n := w.count(`SELECT count(*) FROM auth_sessions WHERE id IN ($1, $2) AND revoked_at IS NULL`, a.Session.ID, a2.Session.ID); n != 2 {
		t.Errorf("live sessions = %d, want 2", n)
	}
	if got := w.sessionFactor(a.Session.ID); got != "totp" {
		t.Errorf("session second_factor = %q, want totp", got)
	}
	w.wantStatus(c, authkit.FactorStatus{})
}

func TestDisableKeepsRecoveryCodesWhileAFactorRemains(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	secret, _ := w.setUpTOTP(c)
	w.enrolEmail(c)
	if r := w.requestProof(c); r.Refusal != nil {
		t.Fatalf("RequestEmailProof = %v", r.Refusal)
	}
	w.clock.Advance(30 * time.Second)
	res := w.disable(c, authkit.FactorEmail, authkit.FactorProof{Method: authkit.FactorTOTP, Code: totpCode(w.t, secret, w.clock.Now())})
	if res.Refusal != nil {
		t.Fatalf("DisableSecondFactor(email) = %v, want nil", res.Refusal)
	}
	if n := w.count(`SELECT count(*) FROM auth_second_factors WHERE principal_id = $1 AND kind = 'totp' AND confirmed_at IS NOT NULL`, ada); n != 1 {
		t.Errorf("totp factor rows = %d, want 1", n)
	}
	if n := w.count(`SELECT count(*) FROM auth_second_factors WHERE principal_id = $1`, ada); n != 1 {
		t.Errorf("factor rows = %d, want only the totp row", n)
	}
	if n := w.count(`SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1 AND used_at IS NULL`, ada); n != 10 {
		t.Errorf("unused recovery rows = %d, want 10", n)
	}
	if n := w.count(`SELECT count(*) FROM auth_email_codes WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("email code rows = %d, want 0", n)
	}
}

func TestDisableWithARecoveryCodeSpendsItOnce(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	_, codes := w.setUpTOTP(c)
	w.enrolEmail(c)
	res := w.disable(c, authkit.FactorEmail, authkit.FactorProof{Method: authkit.FactorRecovery, Code: strings.ToUpper(codes[0])})
	if res.Refusal != nil || res.RecoveryCodesLeft == nil || *res.RecoveryCodesLeft != 9 {
		t.Fatalf("disable with a recovery code = %v, left %v; want nil and 9", res.Refusal, res.RecoveryCodesLeft)
	}
	if n := w.count(`SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1 AND used_at = $2`, ada, w.clock.Now()); n != 1 {
		t.Errorf("recovery rows used now = %d, want 1", n)
	}
	if res := w.disable(c, authkit.FactorTOTP, authkit.FactorProof{Method: authkit.FactorRecovery, Code: codes[0]}); !errors.Is(res.Refusal, authkit.ErrBadCode) {
		t.Errorf("reuse of a spent recovery code = %v, want ErrBadCode", res.Refusal)
	}
	if _, _, confirmed := w.totpRow(ada); !confirmed {
		t.Errorf("the totp factor was removed by a refused disable")
	}
	if n := w.count(`SELECT failures FROM auth_throttle WHERE login = 'ada@example.invalid' AND audience = 'staff'`); n != 1 {
		t.Errorf("throttle failures = %d, want 1", n)
	}
	res = w.disable(c, authkit.FactorTOTP, authkit.FactorProof{Method: authkit.FactorRecovery, Code: codes[1]})
	if res.Refusal != nil || res.RecoveryCodesLeft == nil || *res.RecoveryCodesLeft != 0 {
		t.Fatalf("last disable with a recovery code = %v, left %v; want nil and 0", res.Refusal, res.RecoveryCodesLeft)
	}
	if n := w.count(`SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("recovery rows = %d, want 0", n)
	}
}

func TestDisableWithAnEmailProofSpendsIt(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	w.setUpTOTP(c)
	w.enrolEmail(c)
	p := w.requestProof(c)
	if p.Refusal != nil || p.EmailCode == nil {
		t.Fatalf("RequestEmailProof = %v", p.Refusal)
	}
	m, err := w.mint(p.EmailCode.ID)
	if err != nil {
		t.Fatalf("MintEmailCode: %v", err)
	}
	if m.Purpose != "proof" {
		t.Fatalf("mint purpose = %q, want proof", m.Purpose)
	}
	if res := w.disable(c, authkit.FactorTOTP, authkit.FactorProof{Method: authkit.FactorEmail, Code: m.Code}); res.Refusal != nil {
		t.Fatalf("disable with the email proof = %v, want nil", res.Refusal)
	}
	if n := w.count(`SELECT count(*) FROM auth_email_codes WHERE principal_id = $1 AND purpose = 'proof'`, ada); n != 0 {
		t.Errorf("proof rows after use = %d, want 0", n)
	}

	w.setUpTOTP(c)
	if res := w.disable(c, authkit.FactorTOTP, authkit.FactorProof{Method: authkit.FactorEmail, Code: m.Code}); !errors.Is(res.Refusal, authkit.ErrCodeEnded) {
		t.Errorf("reuse of the email proof = %v, want ErrCodeEnded", res.Refusal)
	}
	if _, _, confirmed := w.totpRow(ada); !confirmed {
		t.Errorf("the totp factor was removed by a refused disable")
	}
	if n := w.count(`SELECT count(*) FROM auth_throttle`); n != 0 {
		t.Errorf("throttle rows = %d, want 0", n)
	}
	if n := w.events(ada, "bad_code"); n != 0 {
		t.Errorf("bad_code events = %d, want 0", n)
	}
}

func TestRequestEmailProofNeedsTheEmailFactor(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	w.setUpTOTP(c)
	res := w.requestProof(c)
	if !errors.Is(res.Refusal, authkit.ErrFactorNotFound) || res.EmailCode != nil {
		t.Errorf("RequestEmailProof without the email factor = %v, want ErrFactorNotFound", res.Refusal)
	}
	if n := w.count(`SELECT count(*) FROM auth_email_codes WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("email code rows = %d, want 0", n)
	}
}

func TestDisableAnAbsentFactorIsNotFound(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	secret, _ := w.setUpTOTP(c)
	w.clock.Advance(30 * time.Second)
	code := totpCode(w.t, secret, w.clock.Now())
	_, lastBefore, _ := w.totpRow(ada)
	for _, kind := range []authkit.FactorKind{authkit.FactorEmail, authkit.FactorRecovery} {
		if res := w.disable(c, kind, authkit.FactorProof{Method: authkit.FactorTOTP, Code: code}); !errors.Is(res.Refusal, authkit.ErrFactorNotFound) {
			t.Errorf("DisableSecondFactor(%q) = %v, want ErrFactorNotFound", kind, res.Refusal)
		}
	}
	if _, last, _ := w.totpRow(ada); last != lastBefore {
		t.Errorf("totp last_step changed from %v to %v", lastBefore, last)
	}
	if n := w.count(`SELECT count(*) FROM auth_throttle`); n != 0 {
		t.Errorf("throttle rows = %d, want 0", n)
	}
	if n := w.count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'bad_code'`, ada); n != 0 {
		t.Errorf("bad_code events = %d, want 0", n)
	}
	if res := w.disable(c, authkit.FactorTOTP, authkit.FactorProof{Method: authkit.FactorTOTP, Code: code}); res.Refusal != nil {
		t.Errorf("disable with the unspent code = %v, want nil", res.Refusal)
	}
}

func TestALockedLoginRefusesDisable(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	secret, _ := w.setUpTOTP(c)
	for i := 0; i < 10; i++ {
		w.login("staff", "ada@example.invalid", "wrong")
	}
	w.clock.Advance(30 * time.Second)
	res := w.disable(c, authkit.FactorTOTP, authkit.FactorProof{Method: authkit.FactorTOTP, Code: totpCode(w.t, secret, w.clock.Now())})
	var locked authkit.ErrLocked
	if !errors.As(res.Refusal, &locked) || locked.RetryAfter <= 0 {
		t.Fatalf("DisableSecondFactor on a locked login = %v, want ErrLocked", res.Refusal)
	}
	if _, _, confirmed := w.totpRow(ada); !confirmed {
		t.Errorf("the totp factor was removed while locked")
	}
	if n := w.events(ada, "factor_removed"); n != 0 {
		t.Errorf("factor_removed events = %d, want 0", n)
	}
}

func TestTwoDisablesLeaveNoCodesWithoutAFactor(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c1 := w.claims(w.signIn("ada@example.invalid", "the right password"))
	c2 := w.claims(w.signIn("ada@example.invalid", "the right password"))

	_, codes := w.setUpTOTP(c1)
	w.enrolEmail(c1)

	tx1, err := w.d.App.BeginTx(w.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx1.Rollback()
	res1, err := w.svc.DisableSecondFactor(w.ctx, sqldb.Tx(tx1), c1, authkit.FactorTOTP, authkit.FactorProof{Method: authkit.FactorRecovery, Code: codes[0]}, fm)
	if err != nil || res1.Refusal != nil {
		t.Fatalf("first DisableSecondFactor = %v, %v; want nil", res1.Refusal, err)
	}

	type outcome struct {
		res authkit.Result
		err error
	}
	out := make(chan outcome, 1)
	go func() {
		var res authkit.Result
		err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
			var err error
			res, err = w.svc.DisableSecondFactor(w.ctx, q, c2, authkit.FactorEmail, authkit.FactorProof{Method: authkit.FactorRecovery, Code: codes[1]}, fm)
			return err
		})
		out <- outcome{res, err}
	}()
	w.d.WaitForLockWaiters(t, 1)
	if err := tx1.Commit(); err != nil {
		t.Fatal(err)
	}
	got := <-out
	if got.err != nil || got.res.Refusal != nil || got.res.RecoveryCodesLeft == nil || *got.res.RecoveryCodesLeft != 0 {
		t.Fatalf("second DisableSecondFactor = %v, %v; want nil with 0 codes left", got.res.Refusal, got.err)
	}
	if n := w.count(`SELECT count(*) FROM auth_second_factors WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("factor rows = %d, want 0", n)
	}
	if n := w.count(`SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("recovery rows = %d, want 0", n)
	}
	if n := w.events(ada, "factor_removed"); n != 2 {
		t.Errorf("factor_removed events = %d, want 2", n)
	}
}
