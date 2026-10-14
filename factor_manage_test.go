package authkit_test

import (
	"bytes"
	crand "crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"image/png"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/factor"
)

var (
	testFactorKey = bytes.Repeat([]byte{0x2a}, 32)
	factorMeta    = authkit.Meta{IP: "192.0.2.7", UserAgent: "authkit-test"}
	recoveryShape = regexp.MustCompile(`^[0-9a-hjkmnp-tv-z]{5}-[0-9a-hjkmnp-tv-z]{5}$`)
)

func withSecondFactors(c *authkit.Config) {
	c.SecondFactors = authkit.SecondFactorRules{Key: testFactorKey}
}

func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func recoveryHash(principal uuid.UUID, code string) []byte {
	keys := factor.DeriveKeys(testFactorKey)
	return factor.HashCode(keys.RecoveryKey, principal, "recovery", factor.NormalizeCode(code))
}

func (w *world) factor(fn func(q db.Querier) (authkit.Result, error)) (authkit.Result, error) {
	w.t.Helper()
	var res authkit.Result
	err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
		var err error
		res, err = fn(q)
		return err
	})
	return res, err
}

func (w *world) factorStatus(c *authkit.Claims) (authkit.FactorStatus, error) {
	w.t.Helper()
	var st authkit.FactorStatus
	err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
		var err error
		st, err = w.svc.SecondFactorStatus(w.ctx, q, c)
		return err
	})
	return st, err
}

func (w *world) wantStatus(c *authkit.Claims, want authkit.FactorStatus) {
	w.t.Helper()
	got, err := w.factorStatus(c)
	if err != nil {
		w.t.Fatalf("SecondFactorStatus: %v", err)
	}
	if got != want {
		w.t.Errorf("SecondFactorStatus = %+v, want %+v", got, want)
	}
}

func (w *world) beginSetup(c *authkit.Claims) authkit.TOTPSetup {
	w.t.Helper()
	res, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.BeginTOTPSetup(w.ctx, q, c, factorMeta)
	})
	if err != nil || res.Refusal != nil || res.TOTPSetup == nil {
		w.t.Fatalf("BeginTOTPSetup = %v, %v", res.Refusal, err)
	}
	return *res.TOTPSetup
}

func (w *world) confirmSetup(c *authkit.Claims, code string) authkit.Result {
	w.t.Helper()
	res, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.ConfirmTOTP(w.ctx, q, c, code, factorMeta)
	})
	if err != nil {
		w.t.Fatalf("ConfirmTOTP: %v", err)
	}
	return res
}

func (w *world) setUpTOTP(c *authkit.Claims) (string, []string) {
	w.t.Helper()
	secret := w.beginSetup(c).Secret
	res := w.confirmSetup(c, totpCode(w.t, secret, w.clock.Now()))
	if res.Refusal != nil {
		w.t.Fatalf("ConfirmTOTP refused: %v", res.Refusal)
	}
	return secret, res.RecoveryCodes
}

func (w *world) totpRow(id uuid.UUID) ([]byte, sql.NullInt64, bool) {
	w.t.Helper()
	var secret []byte
	var lastStep sql.NullInt64
	var confirmed bool
	if err := w.d.Row(w.t, `SELECT secret, last_step, confirmed_at IS NOT NULL FROM auth_second_factors WHERE principal_id = $1 AND kind = 'totp'`, id).Scan(&secret, &lastStep, &confirmed); err != nil {
		w.t.Fatal(err)
	}
	return secret, lastStep, confirmed
}

func (w *world) seedRecoveryCodes(principal uuid.UUID, n int) []uuid.UUID {
	w.t.Helper()
	ids := make([]uuid.UUID, n)
	for i := range ids {
		hash := make([]byte, 32)
		if _, err := crand.Read(hash); err != nil {
			w.t.Fatal(err)
		}
		ids[i] = uuid.New()
		w.d.Exec(w.t, "INSERT INTO auth_recovery_codes (id, principal_id, code_hash, used_at, created_at) VALUES ($1, $2, $3, NULL, $4)", ids[i], principal, hash, w.clock.Now())
	}
	return ids
}

func (w *world) recoveryRowsOf(ids []uuid.UUID) int {
	w.t.Helper()
	n := 0
	for _, id := range ids {
		n += w.count("SELECT count(*) FROM auth_recovery_codes WHERE id = $1", id)
	}
	return n
}

func TestBeginTOTPSetupReturnsASealedEnrolment(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	now := w.clock.Now()
	setup := w.beginSetup(c)
	if !strings.HasPrefix(setup.URI, "otpauth://totp/") || !strings.Contains(setup.URI, "issuer=authkit") {
		t.Errorf("URI is not an authkit otpauth://totp/ URI")
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil || len(raw) != 20 {
		t.Errorf("Secret is not 20 base32-encoded bytes (err %v)", err)
	}
	img, err := png.Decode(bytes.NewReader(setup.QRPNG))
	if err != nil || img.Bounds().Dx() != 256 || img.Bounds().Dy() != 256 {
		t.Errorf("QRPNG is not a 256x256 PNG (err %v)", err)
	}
	if !setup.ExpiresAt.Equal(now.Add(15 * time.Minute)) {
		t.Errorf("ExpiresAt = %v, want %v", setup.ExpiresAt, now.Add(15*time.Minute))
	}
	if n := w.count("SELECT count(*) FROM auth_second_factors WHERE principal_id = $1 AND kind = 'totp' AND confirmed_at IS NULL AND last_step IS NULL AND created_at = $2", ada, now); n != 1 {
		t.Fatalf("pending TOTP rows = %d, want 1", n)
	}
	sealed, _, _ := w.totpRow(ada)
	if bytes.Contains(sealed, raw) {
		t.Errorf("the stored secret holds the raw TOTP secret")
	}
	if n := w.count("SELECT count(*) FROM auth_events WHERE principal_id = $1 AND source = 'second_factor'", ada); n != 0 {
		t.Errorf("a begun setup recorded %d second-factor events, want 0", n)
	}
}

func TestBeginTOTPSetupAgainReplacesThePendingOne(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	first := w.beginSetup(c)
	w.clock.Advance(time.Minute)
	second := w.beginSetup(c)
	if n := w.count("SELECT count(*) FROM auth_second_factors WHERE principal_id = $1 AND kind = 'totp'", ada); n != 1 {
		t.Fatalf("TOTP rows = %d, want 1", n)
	}
	if n := w.count("SELECT count(*) FROM auth_second_factors WHERE principal_id = $1 AND kind = 'totp' AND created_at = $2", ada, w.clock.Now()); n != 1 {
		t.Errorf("the replacing setup did not reset created_at")
	}
	if res := w.confirmSetup(c, totpCode(w.t, first.Secret, w.clock.Now())); !errors.Is(res.Refusal, authkit.ErrBadCode) {
		t.Errorf("the replaced setup's code confirmed the setup: %v", res.Refusal)
	}
	if res := w.confirmSetup(c, totpCode(w.t, second.Secret, w.clock.Now())); res.Refusal != nil {
		t.Errorf("the replacing setup's code was refused: %v", res.Refusal)
	}
}

func TestConfirmTOTPTurnsItOnWithTenRecoveryCodes(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	setup := w.beginSetup(c)
	now := w.clock.Now()
	res := w.confirmSetup(c, totpCode(w.t, setup.Secret, now))
	if res.Refusal != nil {
		t.Fatalf("ConfirmTOTP refused: %v", res.Refusal)
	}
	if len(res.RecoveryCodes) != 10 {
		t.Fatalf("RecoveryCodes = %d, want 10", len(res.RecoveryCodes))
	}
	distinct := map[string]bool{}
	for _, code := range res.RecoveryCodes {
		if !recoveryShape.MatchString(code) {
			t.Errorf("a recovery code is not in the xxxxx-xxxxx form")
		}
		distinct[code] = true
		if w.count("SELECT count(*) FROM auth_recovery_codes WHERE code_hash = convert_to($1, 'UTF8')", code) != 0 {
			t.Errorf("a recovery code is stored in clear")
		}
	}
	if len(distinct) != 10 {
		t.Errorf("distinct recovery codes = %d, want 10", len(distinct))
	}
	if n := w.count("SELECT count(*) FROM auth_second_factors WHERE principal_id = $1 AND kind = 'totp' AND confirmed_at = $2", ada, now); n != 1 {
		t.Errorf("the factor is not confirmed at now")
	}
	if n := w.count("SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1 AND used_at IS NULL AND created_at = $2", ada, now); n != 10 {
		t.Errorf("unused recovery rows = %d, want 10", n)
	}
	w.wantStatus(c, authkit.FactorStatus{TOTP: true, RecoveryCodesLeft: 10})
}

func TestConfirmTOTPWritesTheStepItAccepted(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	setup := w.beginSetup(c)
	step := w.clock.Now().Unix() / 30
	res := w.confirmSetup(c, totpCode(w.t, setup.Secret, w.clock.Now().Add(-30*time.Second)))
	if res.Refusal != nil {
		t.Fatalf("ConfirmTOTP refused: %v", res.Refusal)
	}
	if n := w.count("SELECT count(*) FROM auth_second_factors WHERE principal_id = $1 AND kind = 'totp' AND last_step = $2", ada, step-1); n != 1 {
		t.Errorf("the confirm did not write the step it accepted")
	}
	if err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
		replayed, err := factor.AcceptStep(w.ctx, q, ada, step-1)
		if err != nil {
			return err
		}
		if replayed {
			t.Errorf("the confirmed step was accepted again at sign-in")
		}
		fresh, err := factor.AcceptStep(w.ctx, q, ada, step)
		if err != nil {
			return err
		}
		if !fresh {
			t.Errorf("a later step was refused at sign-in")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmTOTPUsesTheServiceClock(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	setup := w.beginSetup(c)
	now := w.clock.Now()
	if res := w.confirmSetup(c, totpCode(w.t, setup.Secret, now.Add(-60*time.Second))); !errors.Is(res.Refusal, authkit.ErrBadCode) {
		t.Errorf("a code two steps back = %v, want ErrBadCode", res.Refusal)
	}
	if n := w.count("SELECT count(*) FROM auth_second_factors WHERE principal_id = $1 AND confirmed_at IS NULL", ada); n != 1 {
		t.Errorf("the setup was confirmed by a code two steps back")
	}
	if res := w.confirmSetup(c, totpCode(w.t, setup.Secret, now.Add(30*time.Second))); res.Refusal != nil {
		t.Errorf("a code one step ahead = %v, want it accepted", res.Refusal)
	}
}

func TestAWrongSetupCodeWritesNothing(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	signed := w.signIn("ada@example.invalid", "the right password")
	c := w.claims(signed)
	setup := w.beginSetup(c)
	code := []byte(totpCode(w.t, setup.Secret, w.clock.Now()))
	code[5] = '0' + (code[5]-'0'+1)%10
	res := w.confirmSetup(c, string(code))
	if !errors.Is(res.Refusal, authkit.ErrBadCode) || res.RecoveryCodes != nil {
		t.Errorf("a wrong code = %v with %d codes, want ErrBadCode and no codes", res.Refusal, len(res.RecoveryCodes))
	}
	if n := w.count("SELECT count(*) FROM auth_second_factors WHERE principal_id = $1 AND confirmed_at IS NULL AND last_step IS NULL", ada); n != 1 {
		t.Errorf("the pending row changed after a wrong code")
	}
	if n := w.count("SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1", ada); n != 0 {
		t.Errorf("a wrong code wrote %d recovery rows, want 0", n)
	}
	if n := w.count("SELECT count(*) FROM auth_events WHERE principal_id = $1 AND source = 'second_factor' AND result = 'bad_code'", ada); n != 1 {
		t.Errorf("bad_code events = %d, want 1", n)
	}
	if n := w.count("SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'factor_added'", ada); n != 0 {
		t.Errorf("a wrong code recorded %d factor_added events, want 0", n)
	}
	if n := w.count("SELECT count(*) FROM auth_sessions WHERE id = $1 AND second_factor = ''", signed.Session.ID); n != 1 {
		t.Errorf("a wrong code marked the caller's session")
	}
}

func TestAWrongSetupCodeNeverFeedsTheLoginThrottle(t *testing.T) {
	cases := map[string]func(w *world, c *authkit.Claims) func() authkit.Result{
		"totp": func(w *world, c *authkit.Claims) func() authkit.Result {
			setup := w.beginSetup(c)
			code := []byte(totpCode(w.t, setup.Secret, w.clock.Now()))
			code[5] = '0' + (code[5]-'0'+1)%10
			return func() authkit.Result { return w.confirmSetup(c, string(code)) }
		},
		"email": func(w *world, c *authkit.Claims) func() authkit.Result {
			b := w.beginEmail(c)
			m, err := w.mint(b.EmailCode.ID)
			if err != nil {
				w.t.Fatalf("MintEmailCode: %v", err)
			}
			return func() authkit.Result { return w.confirmEmail(c, w.otherCode(m.Code)) }
		},
	}
	for name, prepare := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, withSecondFactors)
			w.user("ada@example.invalid", "the right password")
			c := w.claims(w.signIn("ada@example.invalid", "the right password"))
			wrong := prepare(w, c)
			for i := 0; i < 5; i++ {
				if r := wrong(); !errors.Is(r.Refusal, authkit.ErrBadCode) {
					t.Fatalf("wrong try %d = %v, want ErrBadCode", i+1, r.Refusal)
				}
			}
			if n := w.count(`SELECT count(*) FROM auth_throttle`); n != 0 {
				t.Errorf("throttle rows = %d, want 0", n)
			}
			if res := w.login("staff", "ada@example.invalid", "the right password"); res.Refusal != nil {
				t.Errorf("sign-in after five wrong setup codes = %v, want no refusal", res.Refusal)
			}
		})
	}
}

func TestASetupEndsAfterSetupTTL(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	setup := w.beginSetup(w.claims(w.signIn("ada@example.invalid", "the right password")))
	w.clock.Advance(11 * time.Minute)
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	w.clock.Advance(4 * time.Minute)
	res := w.confirmSetup(c, totpCode(w.t, setup.Secret, w.clock.Now()))
	if !errors.Is(res.Refusal, authkit.ErrSetupExpired) || res.RecoveryCodes != nil {
		t.Errorf("a confirm at the end of the setup = %v with %d codes, want ErrSetupExpired", res.Refusal, len(res.RecoveryCodes))
	}
	if n := w.count("SELECT count(*) FROM auth_second_factors WHERE principal_id = $1 AND confirmed_at IS NULL", ada); n != 1 {
		t.Errorf("the expired setup is no longer pending")
	}
	if n := w.count("SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1", ada); n != 0 {
		t.Errorf("an expired setup wrote %d recovery rows, want 0", n)
	}
	setup = w.beginSetup(c)
	w.clock.Advance(14 * time.Minute)
	c = w.claims(w.signIn("ada@example.invalid", "the right password"))
	w.clock.Advance(15*time.Minute - time.Second - 14*time.Minute)
	if res := w.confirmSetup(c, totpCode(w.t, setup.Secret, w.clock.Now())); res.Refusal != nil {
		t.Errorf("a confirm one second before the end = %v, want it accepted", res.Refusal)
	}
}

func TestConfirmTOTPNeedsAPendingSetup(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	if res := w.confirmSetup(c, "000000"); !errors.Is(res.Refusal, authkit.ErrFactorNotFound) {
		t.Errorf("a confirm with no setup = %v, want ErrFactorNotFound", res.Refusal)
	}
	if n := w.count("SELECT count(*) FROM auth_second_factors WHERE principal_id = $1", ada); n != 0 {
		t.Errorf("a confirm with no setup wrote %d factor rows, want 0", n)
	}
	secret, codes := w.setUpTOTP(c)
	if len(codes) != 10 {
		t.Fatalf("set-up codes = %d, want 10", len(codes))
	}
	w.clock.Advance(30 * time.Second)
	if res := w.confirmSetup(c, totpCode(w.t, secret, w.clock.Now())); !errors.Is(res.Refusal, authkit.ErrFactorExists) {
		t.Errorf("a second confirm = %v, want ErrFactorExists", res.Refusal)
	}
	if n := w.count("SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1", ada); n != 10 {
		t.Errorf("recovery rows = %d, want the 10 from the first confirm", n)
	}
	if n := w.count("SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'factor_added'", ada); n != 1 {
		t.Errorf("factor_added events = %d, want 1", n)
	}
}

func TestBeginTOTPSetupRefusesAConfirmedAuthenticator(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	w.setUpTOTP(c)
	before, beforeStep, _ := w.totpRow(ada)
	res, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.BeginTOTPSetup(w.ctx, q, c, factorMeta)
	})
	if err != nil || !errors.Is(res.Refusal, authkit.ErrFactorExists) || res.TOTPSetup != nil {
		t.Fatalf("Begin on a confirmed authenticator = %v, %v, want ErrFactorExists and no setup", res.Refusal, err)
	}
	after, afterStep, confirmed := w.totpRow(ada)
	if !confirmed || !bytes.Equal(before, after) || beforeStep != afterStep {
		t.Errorf("the confirmed authenticator changed (secret or last step)")
	}
}

func TestConfirmTOTPAfterAnotherFactorIssuesNoCodes(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	w.d.Exec(w.t, "INSERT INTO auth_second_factors (principal_id, kind, secret, last_step, created_at, confirmed_at) VALUES ($1, 'email', NULL, NULL, $2, $2)", ada, w.clock.Now())
	seeded := w.seedRecoveryCodes(ada, 3)
	setup := w.beginSetup(c)
	res := w.confirmSetup(c, totpCode(w.t, setup.Secret, w.clock.Now()))
	if res.Refusal != nil || res.RecoveryCodes != nil {
		t.Errorf("a second factor = %v with %d codes, want no refusal and no codes", res.Refusal, len(res.RecoveryCodes))
	}
	if n := w.count("SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1", ada); n != 3 || w.recoveryRowsOf(seeded) != 3 {
		t.Errorf("recovery rows = %d, want the 3 seeded ones", n)
	}
	w.wantStatus(c, authkit.FactorStatus{TOTP: true, Email: true, RecoveryCodesLeft: 3})
}

func TestConfirmTOTPMarksOnlyTheCallersSession(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	a1 := w.signIn("ada@example.invalid", "the right password")
	a2 := w.signIn("ada@example.invalid", "the right password")
	w.setUpTOTP(w.claims(a1))
	if n := w.count("SELECT count(*) FROM auth_sessions WHERE id = $1 AND second_factor = 'totp'", a1.Session.ID); n != 1 {
		t.Errorf("the caller's session is not marked totp")
	}
	if n := w.count("SELECT count(*) FROM auth_sessions WHERE id = $1 AND second_factor = ''", a2.Session.ID); n != 1 {
		t.Errorf("the other session was marked")
	}
	if n := w.count("SELECT count(*) FROM auth_events WHERE source = 'second_factor' AND result = 'factor_added' AND second_factor = 'totp' AND session_id = $1 AND principal_id = $2", a1.Session.ID, ada); n != 1 {
		t.Errorf("factor_added events for the caller's session = %d, want 1", n)
	}
	if !w.sessionLive(a1.Session.ID) || !w.sessionLive(a2.Session.ID) {
		t.Errorf("a session was revoked by a confirm")
	}
}

func TestListEventsReadsTheSecondFactor(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	w.setUpTOTP(c)
	var events []authkit.Event
	if err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
		var err error
		events, _, err = w.svc.ListEvents(w.ctx, q, ada, nil, 10, 0)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Result == authkit.ResultFactorAdded {
			found = true
			if e.SecondFactor != "totp" {
				t.Errorf("the factor_added event names second factor %q, want totp", e.SecondFactor)
			}
		} else if e.SecondFactor != "" {
			t.Errorf("the %s event names second factor %q, want none", e.Result, e.SecondFactor)
		}
	}
	if !found {
		t.Errorf("no factor_added event listed")
	}
}

func TestRegenerateRecoveryCodesReplacesTheSet(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	_, old := w.setUpTOTP(c)
	w.d.Exec(w.t, "UPDATE auth_recovery_codes SET used_at = $3 WHERE principal_id = $1 AND code_hash = $2", ada, recoveryHash(ada, old[0]), w.clock.Now())
	w.clock.Advance(time.Minute)
	now := w.clock.Now()
	res, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.RegenerateRecoveryCodes(w.ctx, q, c, factorMeta)
	})
	if err != nil || res.Refusal != nil || len(res.RecoveryCodes) != 10 {
		t.Fatalf("RegenerateRecoveryCodes = %v, %v with %d codes, want 10", res.Refusal, err, len(res.RecoveryCodes))
	}
	replaced := map[string]bool{}
	for _, code := range old {
		replaced[code] = true
	}
	for _, code := range res.RecoveryCodes {
		if replaced[code] {
			t.Errorf("a regenerated code repeats one of the replaced set")
		}
	}
	if n := w.count("SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1", ada); n != 10 {
		t.Errorf("recovery rows = %d, want 10", n)
	}
	if n := w.count("SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1 AND used_at IS NULL AND created_at = $2", ada, now); n != 10 {
		t.Errorf("unused new recovery rows = %d, want 10", n)
	}
	if n := w.count("SELECT count(*) FROM auth_events WHERE principal_id = $1 AND source = 'second_factor' AND result = 'recovery_codes_regenerated' AND second_factor = ''", ada); n != 1 {
		t.Errorf("recovery_codes_regenerated events = %d, want 1", n)
	}
	if err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
		gone, err := factor.SpendRecoveryCode(w.ctx, q, ada, recoveryHash(ada, old[1]), now)
		if err != nil {
			return err
		}
		if gone {
			t.Errorf("a code from the replaced set was spent")
		}
		fresh, err := factor.SpendRecoveryCode(w.ctx, q, ada, recoveryHash(ada, res.RecoveryCodes[0]), now)
		if err != nil {
			return err
		}
		if !fresh {
			t.Errorf("a regenerated code was not spendable")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRegenerateRecoveryCodesNeedsAFactor(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	w.beginSetup(c)
	res, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.RegenerateRecoveryCodes(w.ctx, q, c, factorMeta)
	})
	if err != nil || !errors.Is(res.Refusal, authkit.ErrFactorNotFound) || res.RecoveryCodes != nil {
		t.Errorf("Regenerate with only a pending setup = %v, %v, want ErrFactorNotFound and no codes", res.Refusal, err)
	}
	if n := w.count("SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1", ada); n != 0 {
		t.Errorf("recovery rows = %d, want 0", n)
	}
	if n := w.count("SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'recovery_codes_regenerated'", ada); n != 0 {
		t.Errorf("recovery_codes_regenerated events = %d, want 0", n)
	}
}

func TestFactorChangesNeedASignInWithinReauth(t *testing.T) {
	w := newWorld(t, withSecondFactors, func(c *authkit.Config) { c.SecondFactors.Reauth = 2 * time.Minute })
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	w.clock.Advance(2 * time.Minute)
	begun, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.BeginTOTPSetup(w.ctx, q, c, factorMeta)
	})
	if err != nil || begun.Refusal != nil || begun.TOTPSetup == nil {
		t.Fatalf("Begin at exactly Reauth = %v, %v, want a setup", begun.Refusal, err)
	}
	before, _, _ := w.totpRow(ada)
	w.clock.Advance(time.Second)
	begin, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.BeginTOTPSetup(w.ctx, q, c, factorMeta)
	})
	confirm, err2 := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.ConfirmTOTP(w.ctx, q, c, totpCode(w.t, begun.TOTPSetup.Secret, w.clock.Now()), factorMeta)
	})
	regen, err3 := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.RegenerateRecoveryCodes(w.ctx, q, c, factorMeta)
	})
	for name, got := range map[string]struct {
		res authkit.Result
		err error
	}{"BeginTOTPSetup": {begin, err}, "ConfirmTOTP": {confirm, err2}, "RegenerateRecoveryCodes": {regen, err3}} {
		if got.err != nil || !errors.Is(got.res.Refusal, authkit.ErrReauthRequired) {
			t.Errorf("%s past Reauth = %v, %v, want ErrReauthRequired", name, got.res.Refusal, got.err)
		}
	}
	if authkit.ErrReauthRequired.Error() != "authkit: sign in again to change sign-in methods" {
		t.Errorf("ErrReauthRequired message = %q", authkit.ErrReauthRequired.Error())
	}
	secret, _, confirmed := w.totpRow(ada)
	if confirmed || !bytes.Equal(secret, before) {
		t.Errorf("a refused change altered the pending setup")
	}
	if n := w.count("SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1", ada); n != 0 {
		t.Errorf("a refused change wrote %d recovery rows", n)
	}
	if n := w.count("SELECT count(*) FROM auth_events WHERE principal_id = $1 AND source = 'second_factor'", ada); n != 0 {
		t.Errorf("a refused change recorded %d second-factor events", n)
	}
}

func TestFactorReauthCountsFromTheLastPasswordProof(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	w.clock.Advance(10 * time.Minute)
	if res, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.BeginTOTPSetup(w.ctx, q, c, factorMeta)
	}); err != nil || !errors.Is(res.Refusal, authkit.ErrReauthRequired) {
		t.Fatalf("Begin 10 minutes after sign-in = %v, %v, want ErrReauthRequired", res.Refusal, err)
	}
	if res := w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.ChangePassword(w.ctx, q, c, "the right password", "another password", factorMeta)
	}); res.Refusal != nil {
		t.Fatalf("ChangePassword refused: %v", res.Refusal)
	}
	w.clock.Advance(4 * time.Minute)
	if res, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.BeginTOTPSetup(w.ctx, q, c, factorMeta)
	}); err != nil || res.Refusal != nil {
		t.Errorf("Begin 4 minutes after the password proof = %v, %v, want a setup", res.Refusal, err)
	}
}

func TestFactorChangesRefuseAnEndedSession(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	a1 := w.claims(w.signIn("ada@example.invalid", "the right password"))
	w.signIn("ada@example.invalid", "the right password")
	w.logout(w.pinned(ada), a1)
	res, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.BeginTOTPSetup(w.ctx, q, a1, factorMeta)
	})
	if err != nil || !errors.Is(res.Refusal, authkit.ErrReauthRequired) {
		t.Errorf("Begin on an ended session = %v, %v, want ErrReauthRequired", res.Refusal, err)
	}
	if n := w.count("SELECT count(*) FROM auth_second_factors WHERE principal_id = $1", ada); n != 0 {
		t.Errorf("an ended session wrote %d factor rows", n)
	}
}

func TestSecondFactorMethodsAreOffWithoutAKey(t *testing.T) {
	w := newWorld(t)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	if res, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.BeginTOTPSetup(w.ctx, q, c, factorMeta)
	}); err != nil || !errors.Is(res.Refusal, authkit.ErrSecondFactorsOff) {
		t.Errorf("Begin without a key = %v, %v, want ErrSecondFactorsOff", res.Refusal, err)
	}
	if res := w.confirmSetup(c, "000000"); !errors.Is(res.Refusal, authkit.ErrSecondFactorsOff) {
		t.Errorf("Confirm without a key = %v, want ErrSecondFactorsOff", res.Refusal)
	}
	if res, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.RegenerateRecoveryCodes(w.ctx, q, c, factorMeta)
	}); err != nil || !errors.Is(res.Refusal, authkit.ErrSecondFactorsOff) {
		t.Errorf("Regenerate without a key = %v, %v, want ErrSecondFactorsOff", res.Refusal, err)
	}
	if _, err := w.factorStatus(c); !errors.Is(err, authkit.ErrSecondFactorsOff) {
		t.Errorf("SecondFactorStatus without a key = %v, want ErrSecondFactorsOff", err)
	}
	if n := w.count("SELECT count(*) FROM auth_second_factors WHERE principal_id = $1", ada); n != 0 {
		t.Errorf("methods without a key wrote %d factor rows", n)
	}
	if n := w.count("SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1", ada); n != 0 {
		t.Errorf("methods without a key wrote %d recovery rows", n)
	}
}

func TestSecondFactorStatusCountsOnlyConfirmedFactors(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))
	setup := w.beginSetup(c)
	w.wantStatus(c, authkit.FactorStatus{})
	w.confirmSetup(c, totpCode(w.t, setup.Secret, w.clock.Now()))
	w.wantStatus(c, authkit.FactorStatus{TOTP: true, RecoveryCodesLeft: 10})
	w.d.Exec(w.t, "UPDATE auth_recovery_codes SET used_at = $2 WHERE id IN (SELECT id FROM auth_recovery_codes WHERE principal_id = $1 ORDER BY created_at LIMIT 3)", ada, w.clock.Now())
	w.wantStatus(c, authkit.FactorStatus{TOTP: true, RecoveryCodesLeft: 7})
}

func TestConcurrentRegeneratesLeaveOneSet(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	a1 := w.claims(w.signIn("ada@example.invalid", "the right password"))
	a2 := w.claims(w.signIn("ada@example.invalid", "the right password"))
	w.setUpTOTP(a1)
	holder, err := w.d.Owner.BeginTx(w.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.ExecContext(w.ctx, "SELECT 1 FROM auth_recovery_codes WHERE principal_id = $1 FOR UPDATE", ada); err != nil {
		holder.Rollback()
		t.Fatal(err)
	}
	type outcome struct {
		res authkit.Result
		err error
	}
	out := make(chan outcome, 2)
	for _, c := range []*authkit.Claims{a1, a2} {
		go func() {
			var o outcome
			o.err = w.d.InAuthTx(w.ctx, func(q db.Querier) error {
				var err error
				o.res, err = w.svc.RegenerateRecoveryCodes(w.ctx, q, c, factorMeta)
				return err
			})
			out <- o
		}()
	}
	w.d.WaitForLockWaiters(t, 2)
	if err := holder.Rollback(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		o := <-out
		if o.err != nil || o.res.Refusal != nil || len(o.res.RecoveryCodes) != 10 {
			t.Errorf("concurrent Regenerate = %v, %v with %d codes, want 10 and no refusal", o.res.Refusal, o.err, len(o.res.RecoveryCodes))
		}
	}
	if n := w.count("SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1", ada); n != 10 {
		t.Errorf("recovery rows after two regenerates = %d, want 10", n)
	}
}
