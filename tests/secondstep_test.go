package tests

import (
	"bytes"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
)

const pw = "the right password"

var meta = authkit.Meta{IP: "192.0.2.1", UserAgent: "authkit-test"}

func factors(c *kittest.Rules) {
	c.Factors.Key = bytes.Repeat([]byte{0x07}, 32)
}

func throttleAt(n int) func(*kittest.Rules) {
	return func(c *kittest.Rules) { c.Throttle.Failures = n }
}

func maxTries(n int) func(*kittest.Rules) {
	return func(c *kittest.Rules) { c.Factors.MaxTries = n }
}

func (w *world) code(secret string) string {
	w.T.Helper()
	code, err := totp.GenerateCodeCustom(secret, w.Clock.Now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		w.T.Fatalf("totp code: %v", err)
	}
	return code
}

func wrong(code string) string {
	d := int(code[len(code)-1] - '0')
	return code[:len(code)-1] + strconv.Itoa((d+1)%10)
}

func (w *world) enrolTOTP(login string) (uuid.UUID, string, []string) {
	w.T.Helper()
	id := w.User(login, pw)
	c := w.Claims(w.SignIn(login, pw))
	setup := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Factors.BeginTOTPSetup(w.Ctx, q, c, meta)
	})
	if setup.TOTPSetup == nil {
		w.T.Fatalf("begin the authenticator: %v", setup.Refusal)
	}
	key, err := otp.NewKeyFromURL(setup.TOTPSetup.URI)
	if err != nil {
		w.T.Fatalf("setup URI: %v", err)
	}
	secret := key.Secret()
	conf := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Factors.ConfirmTOTP(w.Ctx, q, c, w.code(secret), meta)
	})
	if conf.Refusal != nil {
		w.T.Fatalf("confirm the authenticator: %v", conf.Refusal)
	}
	if len(conf.RecoveryCodes) != 10 {
		w.T.Fatalf("got %d recovery codes, want 10", len(conf.RecoveryCodes))
	}
	w.Clock.Advance(30 * time.Second)
	return id, secret, conf.RecoveryCodes
}

func (w *world) verify(aud authkit.Audience, token string, method authkit.FactorKind, code string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.VerifySecondStep(w.Ctx, q, aud, token, method, code, meta)
	})
}

func (w *world) challenge(login string) string {
	w.T.Helper()
	res := w.Login("staff", login, pw)
	if res.SecondStep == nil {
		w.T.Fatalf("login gave no second step: %v", res.Refusal)
	}
	return res.SecondStep.Token
}

func (w *world) offline(key []byte) {
	w.T.Helper()
	cfg := w.Cfg
	cfg.Factors.Key = key
	w.Svc = w.Build(cfg)
}

func (w *world) unplugged() {
	w.T.Helper()
	w.Svc = w.BuildNoFactors(w.Cfg)
}

func (w *world) sessionMode() {
	w.T.Helper()
	cfg := w.Cfg
	cfg.Transport, cfg.Issuer, cfg.Secret = authkit.TransportSession, "", nil
	w.Svc = w.Build(cfg)
}

func (w *world) eventResults(id uuid.UUID, source string) []string {
	w.T.Helper()
	rows, err := w.D.Owner.Query(`SELECT result FROM auth_events WHERE principal_id = $1 AND source = $2 ORDER BY at, id`, id, source)
	if err != nil {
		w.T.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			w.T.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		w.T.Fatal(err)
	}
	return out
}

func (w *world) openSessions(id uuid.UUID) int {
	w.T.Helper()
	return w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND revoked_at IS NULL`, id)
}

func (w *world) factorSessions(id uuid.UUID) int {
	w.T.Helper()
	return w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND second_factor <> '' AND id <> (SELECT id FROM auth_sessions WHERE principal_id = $1 ORDER BY created_at, id LIMIT 1)`, id)
}

func (w *world) tries(id uuid.UUID) int {
	w.T.Helper()
	return w.Count(`SELECT COALESCE(sum(tries), 0) FROM auth_second_step_challenges WHERE principal_id = $1`, id)
}

func (w *world) usedCodes(id uuid.UUID) int {
	w.T.Helper()
	return w.Count(`SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1 AND used_at IS NOT NULL`, id)
}

func TestLoginWithAFactorReturnsAChallengeNotASession(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, _, _ := w.enrolTOTP(login)
	n := w.openSessions(id)
	res := w.Login("staff", login, pw)
	if res.Refusal != nil || res.SecondStep == nil {
		t.Fatalf("login = refusal %v, second step nil %v; want a second step", res.Refusal, res.SecondStep == nil)
	}
	if res.SecondStep.Token == "" {
		t.Fatal("the second step has no token")
	}
	if want := w.Clock.Now().Add(10 * time.Minute); !res.SecondStep.ExpiresAt.Equal(want) {
		t.Fatalf("second step expires at %v, want %v", res.SecondStep.ExpiresAt, want)
	}
	if !slices.Equal(res.SecondStep.Methods, []authkit.FactorKind{authkit.FactorTOTP, authkit.FactorRecovery}) {
		t.Fatalf("second step methods %v, want [totp recovery]", res.SecondStep.Methods)
	}
	if res.Session != nil || res.Tokens != nil || res.SessionToken != "" {
		t.Fatal("a login with a factor opened a session")
	}
	if got := w.openSessions(id); got != n {
		t.Fatalf("open sessions %d, want %d", got, n)
	}
	ev := w.eventResults(id, "login")
	if len(ev) == 0 || ev[len(ev)-1] != "second_step_required" {
		t.Fatalf("login events %v, want a trailing second_step_required", ev)
	}
	if countOf(ev, "signed_in") != 1 {
		t.Fatalf("login events %v, want only the enrolment's signed_in", ev)
	}
	if w.Count(`SELECT count(*) FROM auth_second_step_challenges WHERE principal_id = $1 AND origin = 'login' AND audience = 'staff' AND tries = 0 AND used_at IS NULL`, id) != 1 {
		t.Fatal("no unspent login challenge for the principal")
	}
}

func TestTheSecondStepOpensASessionWithTheFactor(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, secret, _ := w.enrolTOTP(login)
	res := w.verify("staff", w.challenge(login), authkit.FactorTOTP, w.code(secret))
	if res.Refusal != nil || res.Tokens == nil || res.Session == nil {
		t.Fatalf("second step = refusal %v; want a session", res.Refusal)
	}
	if res.Session.SecondFactor != "totp" {
		t.Fatalf("session second factor %q, want totp", res.Session.SecondFactor)
	}
	if got := w.sessionFactor(res.Session.ID); got != "totp" {
		t.Fatalf("stored session second factor %q, want totp", got)
	}
	if got := w.eventResults(id, "second_step"); !slices.Equal(got, []string{"signed_in"}) {
		t.Fatalf("second_step events %v, want [signed_in]", got)
	}
	if w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND source = 'second_step' AND result = 'signed_in' AND second_factor = 'totp' AND session_id = $2`, id, res.Session.ID) != 1 {
		t.Fatal("the signed_in event does not record the totp factor and the session")
	}
	if w.Count(`SELECT count(*) FROM auth_second_step_challenges WHERE principal_id = $1 AND used_at IS NOT NULL`, id) != 1 {
		t.Fatal("the challenge is not spent")
	}
}

func TestARecoveryCodeOpensASessionAndReportsWhatIsLeft(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, _, recovery := w.enrolTOTP(login)
	res := w.verify("staff", w.challenge(login), authkit.FactorRecovery, strings.ToUpper(recovery[0]))
	if res.Refusal != nil || res.Session == nil {
		t.Fatalf("recovery second step = refusal %v; want a session", res.Refusal)
	}
	if res.Session.SecondFactor != "recovery" {
		t.Fatalf("session second factor %q, want recovery", res.Session.SecondFactor)
	}
	if res.RecoveryCodesLeft == nil || *res.RecoveryCodesLeft != 9 {
		t.Fatalf("recovery codes left %v, want 9", res.RecoveryCodesLeft)
	}
	if w.usedCodes(id) != 1 {
		t.Fatal("the recovery code is not spent")
	}
}

func TestARecoveryCodeWorksOnce(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, _, recovery := w.enrolTOTP(login)
	if first := w.verify("staff", w.challenge(login), authkit.FactorRecovery, recovery[0]); first.Refusal != nil || first.Session == nil {
		t.Fatalf("first use refused: %v", first.Refusal)
	}
	n := w.openSessions(id)
	w.Clock.Advance(time.Second)
	res := w.verify("staff", w.challenge(login), authkit.FactorRecovery, recovery[0])
	if res.Refusal != authkit.ErrBadCode {
		t.Fatalf("second use refusal %v, want ErrBadCode", res.Refusal)
	}
	if got := w.openSessions(id); got != n {
		t.Fatalf("open sessions %d, want %d", got, n)
	}
	if w.usedCodes(id) != 1 {
		t.Fatal("the recovery code was spent twice")
	}
	ev := w.eventResults(id, "second_step")
	if len(ev) == 0 || ev[len(ev)-1] != "bad_code" {
		t.Fatalf("second_step events %v, want a trailing bad_code", ev)
	}
}

func TestAChallengeWorksOnce(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, secret, _ := w.enrolTOTP(login)
	tok := w.challenge(login)
	first := w.verify("staff", tok, authkit.FactorTOTP, w.code(secret))
	if first.Refusal != nil || first.Session == nil {
		t.Fatalf("first answer refused: %v", first.Refusal)
	}
	w.Clock.Advance(30 * time.Second)
	if res := w.verify("staff", tok, authkit.FactorTOTP, w.code(secret)); res.Refusal != authkit.ErrChallengeEnded {
		t.Fatalf("second answer refusal %v, want ErrChallengeEnded", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND second_factor = 'totp' AND id = $2`, id, first.Session.ID) != 1 {
		t.Fatal("the first answer's session does not record totp")
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND second_factor = 'totp'`, id) != 2 {
		t.Fatal("the reused challenge opened a session")
	}
	if slices.Contains(w.eventResults(id, "second_step"), "bad_code") {
		t.Fatal("a spent challenge counted a bad code")
	}
	if w.tries(id) != 0 {
		t.Fatalf("tries %d, want 0", w.tries(id))
	}
}

func TestAChallengeEndsAtItsTTL(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, secret, _ := w.enrolTOTP(login)
	tok := w.challenge(login)
	w.Clock.Advance(10 * time.Minute)
	if res := w.verify("staff", tok, authkit.FactorTOTP, w.code(secret)); res.Refusal != authkit.ErrChallengeEnded {
		t.Fatalf("expired challenge refusal %v, want ErrChallengeEnded", res.Refusal)
	}
	if w.tries(id) != 0 || slices.Contains(w.eventResults(id, "second_step"), "bad_code") {
		t.Fatal("an expired challenge counted a try")
	}
	if w.factorSessions(id) != 0 {
		t.Fatal("an expired challenge opened a session")
	}
	tok2 := w.challenge(login)
	w.Clock.Advance(10*time.Minute - time.Second)
	if res := w.verify("staff", tok2, authkit.FactorTOTP, w.code(secret)); res.Refusal != nil || res.Session == nil {
		t.Fatalf("challenge one second before its end refused: %v", res.Refusal)
	}
}

func TestAChallengeIsBoundToItsAudience(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, secret, _ := w.enrolTOTP(login)
	tok := w.challenge(login)
	if res := w.verify("client", tok, authkit.FactorTOTP, w.code(secret)); res.Refusal != authkit.ErrChallengeEnded {
		t.Fatalf("other audience refusal %v, want ErrChallengeEnded", res.Refusal)
	}
	if w.tries(id) != 0 || w.factorSessions(id) != 0 {
		t.Fatal("another audience's answer counted a try or opened a session")
	}
	if res := w.verify("staff", tok, authkit.FactorTOTP, w.code(secret)); res.Refusal != nil || res.Session == nil {
		t.Fatalf("the challenge's own audience refused: %v", res.Refusal)
	}
}

func TestFiveWrongCodesEndTheChallenge(t *testing.T) {
	w := newWorld(t, factors, throttleAt(100))
	const login = "ada@example.invalid"
	id, secret, _ := w.enrolTOTP(login)
	tok := w.challenge(login)
	for i := 0; i < 4; i++ {
		if res := w.verify("staff", tok, authkit.FactorTOTP, wrong(w.code(secret))); res.Refusal != authkit.ErrBadCode {
			t.Fatalf("wrong code %d refusal %v, want ErrBadCode", i+1, res.Refusal)
		}
	}
	if res := w.verify("staff", tok, authkit.FactorTOTP, wrong(w.code(secret))); res.Refusal != authkit.ErrChallengeEnded {
		t.Fatalf("fifth wrong code refusal %v, want ErrChallengeEnded", res.Refusal)
	}
	if res := w.verify("staff", tok, authkit.FactorTOTP, w.code(secret)); res.Refusal != authkit.ErrChallengeEnded {
		t.Fatalf("right code after five wrong refusal %v, want ErrChallengeEnded", res.Refusal)
	}
	if w.tries(id) != 5 {
		t.Fatalf("tries %d, want 5", w.tries(id))
	}
	if n := countOf(w.eventResults(id, "second_step"), "bad_code"); n != 5 {
		t.Fatalf("bad_code events %d, want 5", n)
	}
	if w.factorSessions(id) != 0 {
		t.Fatal("a challenge with five wrong codes opened a session")
	}
}

func TestWrongCodesLockTheLoginThrottle(t *testing.T) {
	w := newWorld(t, factors, throttleAt(3), maxTries(10))
	const login = "ada@example.invalid"
	id, secret, _ := w.enrolTOTP(login)
	tok := w.challenge(login)
	for i := 0; i < 3; i++ {
		if res := w.verify("staff", tok, authkit.FactorTOTP, wrong(w.code(secret))); res.Refusal != authkit.ErrBadCode {
			t.Fatalf("wrong code %d refusal %v, want ErrBadCode", i+1, res.Refusal)
		}
		w.Clock.Advance(time.Second)
	}
	var locked authkit.ErrLocked
	if res := w.verify("staff", tok, authkit.FactorTOTP, w.code(secret)); !errors.As(res.Refusal, &locked) || locked.RetryAfter <= 0 {
		t.Fatalf("right code after the throttle filled refusal %v, want ErrLocked", res.Refusal)
	}
	if res := w.Login("staff", login, pw); !errors.As(res.Refusal, &locked) {
		t.Fatalf("login after the throttle filled refusal %v, want ErrLocked", res.Refusal)
	}
	if ev := w.eventResults(id, "second_step"); len(ev) == 0 || ev[len(ev)-1] != "locked" {
		t.Fatalf("second_step events %v, want a trailing locked", ev)
	}
	if w.factorSessions(id) != 0 {
		t.Fatal("a locked login opened a session with a factor")
	}
}

func TestALockedThrottleRefusesBeforeTheCode(t *testing.T) {
	w := newWorld(t, factors, throttleAt(3), maxTries(10))
	const login = "ada@example.invalid"
	id, secret, recovery := w.enrolTOTP(login)
	tok := w.challenge(login)
	for i := 0; i < 3; i++ {
		w.verify("staff", tok, authkit.FactorTOTP, wrong(w.code(secret)))
	}
	var locked authkit.ErrLocked
	if res := w.verify("staff", tok, authkit.FactorRecovery, recovery[0]); !errors.As(res.Refusal, &locked) {
		t.Fatalf("recovery code under a lock refusal %v, want ErrLocked", res.Refusal)
	}
	if w.usedCodes(id) != 0 {
		t.Fatal("a locked throttle spent a recovery code")
	}
	if w.tries(id) != 3 {
		t.Fatalf("tries %d, want 3", w.tries(id))
	}
}

func TestASecondStepSignInClearsTheThrottle(t *testing.T) {
	w := newWorld(t, factors, throttleAt(3), maxTries(10))
	const login = "ada@example.invalid"
	_, secret, _ := w.enrolTOTP(login)
	tok := w.challenge(login)
	for i := 0; i < 2; i++ {
		w.verify("staff", tok, authkit.FactorTOTP, wrong(w.code(secret)))
	}
	if res := w.verify("staff", tok, authkit.FactorTOTP, w.code(secret)); res.Refusal != nil || res.Session == nil {
		t.Fatalf("right code after two wrong refused: %v", res.Refusal)
	}
	if got := w.Count(`SELECT COALESCE(sum(failures), 0) FROM auth_throttle WHERE audience = 'staff'`); got != 0 {
		t.Fatalf("throttle failures %d after a second-step sign-in, want 0", got)
	}
}

func TestAnAuthenticatorCodeIsNotReplayed(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, secret, _ := w.enrolTOTP(login)
	c := w.code(secret)
	if res := w.verify("staff", w.challenge(login), authkit.FactorTOTP, c); res.Refusal != nil || res.Session == nil {
		t.Fatalf("first sign-in refused: %v", res.Refusal)
	}
	n := w.openSessions(id)
	if res := w.verify("staff", w.challenge(login), authkit.FactorTOTP, c); res.Refusal != authkit.ErrBadCode {
		t.Fatalf("replayed code refusal %v, want ErrBadCode", res.Refusal)
	}
	if got := w.openSessions(id); got != n {
		t.Fatalf("open sessions %d, want %d", got, n)
	}
	if w.tries(id) != 1 {
		t.Fatalf("tries %d, want 1", w.tries(id))
	}
}

func TestAnAdmitRefusalAtTheSecondStepSpendsNothing(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, _, recovery := w.enrolTOTP(login)
	tok := w.challenge(login)
	errNo := errors.New("app: no membership")
	w.P.Refuse(id, errNo)
	if res := w.verify("staff", tok, authkit.FactorRecovery, recovery[0]); res.Refusal != errNo {
		t.Fatalf("refusal %v, want the admit refusal", res.Refusal)
	}
	if w.usedCodes(id) != 0 || w.tries(id) != 0 {
		t.Fatal("a refused admit spent a code or counted a try")
	}
	if w.Count(`SELECT count(*) FROM auth_second_step_challenges WHERE principal_id = $1 AND used_at IS NULL`, id) != 1 {
		t.Fatal("a refused admit spent the challenge")
	}
	if ev := w.eventResults(id, "second_step"); !slices.Equal(ev, []string{"no_membership"}) {
		t.Fatalf("second_step events %v, want [no_membership]", ev)
	}
	if w.factorSessions(id) != 0 {
		t.Fatal("a refused admit opened a session with a factor")
	}
}

func TestALoginAdmitRefusalGivesNoChallenge(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, _, _ := w.enrolTOTP(login)
	errNo := errors.New("app: no membership")
	w.P.Refuse(id, errNo)
	res := w.Login("staff", login, pw)
	if res.Refusal != errNo || res.SecondStep != nil {
		t.Fatalf("login = refusal %v, second step nil %v; want the admit refusal and no challenge", res.Refusal, res.SecondStep == nil)
	}
	if w.Count(`SELECT count(*) FROM auth_second_step_challenges`) != 0 {
		t.Fatal("a refused login left a challenge")
	}
}

func TestWithoutAKeyAFactorHolderCannotSignIn(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, _, _ := w.enrolTOTP(login)
	n := w.openSessions(id)
	events := len(w.eventResults(id, "login"))
	w.offline(nil)
	res := w.Login("staff", login, pw)
	if res.Refusal != authkit.ErrSecondFactorsOff || res.SecondStep != nil || res.Session != nil || res.Tokens != nil {
		t.Fatalf("login without a key = refusal %v; want ErrSecondFactorsOff alone", res.Refusal)
	}
	if got := w.openSessions(id); got != n {
		t.Fatalf("open sessions %d, want %d", got, n)
	}
	if w.Count(`SELECT count(*) FROM auth_second_step_challenges`) != 0 {
		t.Fatal("a login without a key left a challenge")
	}
	if got := len(w.eventResults(id, "login")); got != events {
		t.Fatalf("login events %d, want %d", got, events)
	}
}

func TestVerifyIsOffWithoutAKey(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, secret, _ := w.enrolTOTP(login)
	tok := w.challenge(login)
	w.offline(nil)
	if res := w.verify("staff", tok, authkit.FactorTOTP, w.code(secret)); res.Refusal != authkit.ErrSecondFactorsOff {
		t.Fatalf("verify without a key refusal %v, want ErrSecondFactorsOff", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_second_step_challenges WHERE principal_id = $1 AND used_at IS NULL AND tries = 0`, id) != 1 {
		t.Fatal("verify without a key touched the challenge")
	}
	if w.factorSessions(id) != 0 {
		t.Fatal("verify without a key opened a session")
	}
}

func TestCompleteResetReturnsAChallengeAndKeepsTheFactors(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, secret, _ := w.enrolTOTP(login)
	res := w.completeReset(w.mintLink(*w.requestReset(login).TokenID), "a brand new password")
	if res.Refusal != nil || res.SecondStep == nil {
		t.Fatalf("reset = refusal %v; want a second step", res.Refusal)
	}
	if !slices.Equal(res.SecondStep.Methods, []authkit.FactorKind{authkit.FactorTOTP, authkit.FactorRecovery}) {
		t.Fatalf("second step methods %v, want [totp recovery]", res.SecondStep.Methods)
	}
	if res.Session != nil || res.Tokens != nil {
		t.Fatal("a reset with a factor opened a session")
	}
	if got := w.openSessions(id); got != 0 {
		t.Fatalf("open sessions %d after the reset, want 0", got)
	}
	if w.Count(`SELECT count(*) FROM auth_second_step_challenges WHERE principal_id = $1 AND origin = 'reset'`, id) != 1 {
		t.Fatal("no reset challenge")
	}
	if w.Count(`SELECT count(*) FROM auth_second_factors WHERE principal_id = $1 AND confirmed_at IS NOT NULL`, id) != 1 {
		t.Fatal("the reset removed the authenticator")
	}
	if w.Count(`SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1 AND used_at IS NULL`, id) != 10 {
		t.Fatal("the reset changed the recovery codes")
	}
	if w.Login("staff", login, "a brand new password").SecondStep == nil {
		t.Fatal("login with the new password gave no second step")
	}
	if got := w.verify("staff", res.SecondStep.Token, authkit.FactorTOTP, w.code(secret)); got.Refusal != nil || got.Session == nil || got.Session.SecondFactor != "totp" {
		t.Fatalf("reset's second step refused: %v", got.Refusal)
	}
}

func TestCompleteResetInSessionModeOpensNoSession(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, secret, _ := w.enrolTOTP(login)
	w.sessionMode()
	signedIn := w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'signed_in'`, id)
	res := w.completeReset(w.mintLink(*w.requestReset(login).TokenID), "a brand new password")
	if res.Refusal != nil || res.SecondStep == nil || res.SessionToken != "" {
		t.Fatalf("session-mode reset = refusal %v; want a second step and no session token", res.Refusal)
	}
	if got := w.openSessions(id); got != 0 {
		t.Fatalf("open sessions %d after the reset, want 0", got)
	}
	if got := w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'signed_in'`, id); got != signedIn {
		t.Fatal("the reset recorded a signed_in")
	}
	got := w.verify("staff", res.SecondStep.Token, authkit.FactorTOTP, w.code(secret))
	if got.Refusal != nil || got.SessionToken == "" || got.Session == nil {
		t.Fatalf("session-mode second step refused: %v", got.Refusal)
	}
	if w.sessionFactor(got.Session.ID) != "totp" {
		t.Fatal("the session does not record the totp factor")
	}
}

func TestAResetChallengeCountsOnTheLoginThrottle(t *testing.T) {
	w := newWorld(t, factors, throttleAt(3), maxTries(10))
	const login = "ada@example.invalid"
	_, secret, _ := w.enrolTOTP(login)
	res := w.completeReset(w.mintLink(*w.requestReset(login).TokenID), "a brand new password")
	if res.SecondStep == nil {
		t.Fatalf("reset gave no second step: %v", res.Refusal)
	}
	for i := 0; i < 3; i++ {
		w.verify("staff", res.SecondStep.Token, authkit.FactorTOTP, wrong(w.code(secret)))
	}
	var locked authkit.ErrLocked
	if got := w.Login("staff", login, "a brand new password"); !errors.As(got.Refusal, &locked) {
		t.Fatalf("login after the reset's wrong codes refusal %v, want ErrLocked", got.Refusal)
	}
}

func TestCompleteResetWithoutAKeyChangesNothing(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, _, _ := w.enrolTOTP(login)
	h := w.StoredHash(id)
	n := w.openSessions(id)
	w.offline(nil)
	res := w.completeReset(w.mintLink(*w.requestReset(login).TokenID), "a brand new password")
	if res.Refusal != authkit.ErrSecondFactorsOff {
		t.Fatalf("reset without a key refusal %v, want ErrSecondFactorsOff", res.Refusal)
	}
	if w.StoredHash(id) != h {
		t.Fatal("a reset without a key changed the password")
	}
	if got := w.openSessions(id); got != n {
		t.Fatalf("open sessions %d, want %d", got, n)
	}
	if slices.Contains(w.eventResults(id, "complete_reset"), "password_reset") {
		t.Fatal("a reset without a key recorded password_reset")
	}
	if w.Count(`SELECT count(*) FROM auth_second_step_challenges`) != 0 {
		t.Fatal("a reset without a key left a challenge")
	}
}

func TestAResetAdmitRefusalInBearerModeWritesNothing(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, _, _ := w.enrolTOTP(login)
	h := w.StoredHash(id)
	n := w.openSessions(id)
	errNo := errors.New("app: no membership")
	w.P.Refuse(id, errNo)
	if res := w.completeReset(w.mintLink(*w.requestReset(login).TokenID), "a brand new password"); res.Refusal != errNo {
		t.Fatalf("reset refusal %v, want the admit refusal", res.Refusal)
	}
	if w.StoredHash(id) != h {
		t.Fatal("a refused reset changed the password")
	}
	if got := w.openSessions(id); got != n {
		t.Fatalf("open sessions %d, want %d", got, n)
	}
	if ev := w.eventResults(id, "complete_reset"); !slices.Equal(ev, []string{"no_membership"}) {
		t.Fatalf("complete_reset events %v, want [no_membership]", ev)
	}
}

func TestListSessionsShowsTheFactor(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	_, secret, _ := w.enrolTOTP(login)
	res := w.verify("staff", w.challenge(login), authkit.FactorTOTP, w.code(secret))
	if res.Refusal != nil || res.Session == nil {
		t.Fatalf("second step refused: %v", res.Refusal)
	}
	var list []authkit.Session
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		var err error
		list, _, err = w.Svc.ListSessions(w.Ctx, q, w.Claims(res), 10, 0)
		return err
	}); err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	var found bool
	for _, s := range list {
		if s.ID == res.Session.ID {
			found = true
		}
		if s.SecondFactor != "totp" {
			t.Fatalf("listed second factor %q, want totp", s.SecondFactor)
		}
	}
	if !found {
		t.Fatal("ListSessions does not list the new session")
	}
}

func TestTheSecondStepLeaksNoSecret(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, secret, recovery := w.enrolTOTP(login)
	tok := w.challenge(login)
	bad := wrong(w.code(secret))
	first := w.verify("staff", tok, authkit.FactorTOTP, bad)
	second := w.verify("staff", tok, authkit.FactorRecovery, recovery[0])
	if first.Refusal != authkit.ErrBadCode || second.Refusal != nil {
		t.Fatalf("second step outcomes %v, %v", first.Refusal, second.Refusal)
	}
	rows, err := w.D.Owner.Query(`SELECT concat_ws('|', login, result, ip, user_agent, source, second_factor) FROM auth_events WHERE principal_id = $1`, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var audit strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		audit.WriteString(line)
		audit.WriteString("\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	var refusals string
	if first.Refusal != nil {
		refusals += first.Refusal.Error()
	}
	if second.Refusal != nil {
		refusals += second.Refusal.Error()
	}
	for _, s := range []string{tok, bad, recovery[0], secret} {
		if strings.Contains(audit.String(), s) || strings.Contains(refusals, s) {
			t.Fatal("an audit row or refusal carries a secret: <redacted>")
		}
	}
}

func TestPruneDeletesChallengesAnHourPastExpiry(t *testing.T) {
	w := newWorld(t, factors)
	oldID, _, _ := w.enrolTOTP("old@example.invalid")
	edgeID, _, _ := w.enrolTOTP("edge@example.invalid")
	liveID, _, _ := w.enrolTOTP("live@example.invalid")
	w.challenge("old@example.invalid")
	w.challenge("edge@example.invalid")
	w.challenge("live@example.invalid")
	now := w.Clock.Now()
	w.D.Exec(w.T, `UPDATE auth_second_step_challenges SET expires_at = $1 WHERE principal_id = $2`, now.Add(-61*time.Minute), oldID)
	w.D.Exec(w.T, `UPDATE auth_second_step_challenges SET expires_at = $1 WHERE principal_id = $2`, now.Add(-59*time.Minute), edgeID)
	if err := w.D.InGlobalSystemTx(w.Ctx, func(q db.Querier) error { return w.Svc.Prune(w.Ctx, q) }); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	for _, c := range []struct {
		name string
		id   uuid.UUID
		want int
	}{{"old", oldID, 0}, {"edge", edgeID, 1}, {"live", liveID, 1}} {
		if got := w.Count(`SELECT count(*) FROM auth_second_step_challenges WHERE principal_id = $1`, c.id); got != c.want {
			t.Fatalf("%s challenges left %d, want %d", c.name, got, c.want)
		}
	}
}

func TestConcurrentVerifiesOfOneChallengeOpenOneSession(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, _, recovery := w.enrolTOTP(login)
	tok := w.challenge(login)

	type outcome struct {
		res authkit.Result
		err error
	}
	aDone := make(chan outcome, 2)
	aEnd := make(chan error, 1)
	release := make(chan struct{})
	go func() {
		err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
			res, err := w.Svc.VerifySecondStep(w.Ctx, q, "staff", tok, authkit.FactorRecovery, recovery[0], meta)
			aDone <- outcome{res, err}
			if err != nil {
				return err
			}
			<-release
			return nil
		})
		aEnd <- err
	}()
	a := <-aDone
	if a.err != nil || a.res.Refusal != nil || a.res.Session == nil {
		t.Fatalf("first verify: err %v, refusal %v", a.err != nil, a.res.Refusal)
	}

	bDone := make(chan outcome, 2)
	go func() {
		err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
			res, err := w.Svc.VerifySecondStep(w.Ctx, q, "staff", tok, authkit.FactorRecovery, recovery[1], meta)
			bDone <- outcome{res, err}
			return err
		})
		if err != nil {
			bDone <- outcome{err: err}
		}
	}()
	select {
	case <-bDone:
		t.Fatal("the second verify finished while the first held the challenge")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	var b outcome
	select {
	case b = <-bDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the second verify did not finish after the first committed")
	}
	if b.err != nil || b.res.Refusal != authkit.ErrChallengeEnded {
		t.Fatalf("second verify: err %v, refusal %v; want ErrChallengeEnded", b.err != nil, b.res.Refusal)
	}
	select {
	case err := <-aEnd:
		if err != nil {
			t.Fatalf("first transaction: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the first transaction did not commit")
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND second_factor = 'recovery'`, id) != 1 {
		t.Fatal("the challenge did not open exactly one session")
	}
	if w.usedCodes(id) != 1 {
		t.Fatal("the challenge did not spend exactly one recovery code")
	}
}

func TestMethodsOmitRecoveryWhenNoneAreLeft(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, _, _ := w.enrolTOTP(login)
	w.D.Exec(w.T, `UPDATE auth_recovery_codes SET used_at = $1 WHERE principal_id = $2`, w.Clock.Now(), id)
	res := w.Login("staff", login, pw)
	if res.SecondStep == nil {
		t.Fatalf("login gave no second step: %v", res.Refusal)
	}
	if !slices.Equal(res.SecondStep.Methods, []authkit.FactorKind{authkit.FactorTOTP}) {
		t.Fatalf("second step methods %v, want [totp]", res.SecondStep.Methods)
	}
}

func TestAnUnconfirmedAuthenticatorAsksNoSecondStep(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	w.User(login, pw)
	c := w.Claims(w.SignIn(login, pw))
	w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Factors.BeginTOTPSetup(w.Ctx, q, c, meta)
	})
	res := w.Login("staff", login, pw)
	if res.Refusal != nil || res.Session == nil || res.SecondStep != nil {
		t.Fatalf("login with an unconfirmed authenticator = refusal %v; want a session and no second step", res.Refusal)
	}
	if got := w.sessionFactor(res.Session.ID); got != "" {
		t.Fatalf("session second factor %q, want none", got)
	}
}

func TestAChangedKeyFailsClosed(t *testing.T) {
	w := newWorld(t, factors)
	const login = "ada@example.invalid"
	id, secret, recovery := w.enrolTOTP(login)
	n := w.openSessions(id)
	tok := w.challenge(login)
	w.offline(bytes.Repeat([]byte{0x08}, 32))
	var res authkit.Result
	err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		var err error
		res, err = w.Svc.VerifySecondStep(w.Ctx, q, "staff", tok, authkit.FactorTOTP, w.code(secret), meta)
		return err
	})
	if err == nil || res.Refusal != nil || res.Session != nil || res.Tokens != nil {
		t.Fatal("a changed key did not fail closed with an error")
	}
	if got := w.openSessions(id); got != n {
		t.Fatalf("open sessions %d, want %d", got, n)
	}
	if w.tries(id) != 0 {
		t.Fatalf("tries %d, want 0", w.tries(id))
	}
	if got := w.verify("staff", tok, authkit.FactorRecovery, recovery[0]); got.Refusal != authkit.ErrBadCode {
		t.Fatalf("recovery code under a changed key refusal %v, want ErrBadCode", got.Refusal)
	}
	if w.usedCodes(id) != 0 || w.factorSessions(id) != 0 {
		t.Fatal("a changed key spent a recovery code or opened a session with a factor")
	}
}

func TestAPasskeySignInRecordsPasskey(t *testing.T) {
	w := newWorld(t, kittest.Passkeys)
	id := w.User("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", kittest.StaffOrigin)
	w.SeedPasskey(id, a)
	res := w.passkeySignIn("staff", a)
	if res.Refusal != nil || res.Session == nil {
		t.Fatalf("sign-in refused: %v", res.Refusal)
	}
	if res.Session.SecondFactor != "passkey" {
		t.Errorf("session second factor %q, want passkey", res.Session.SecondFactor)
	}
	var stored string
	if err := w.D.Row(w.T, `SELECT second_factor FROM auth_sessions WHERE id = $1`, res.Session.ID).Scan(&stored); err != nil {
		w.T.Fatal(err)
	}
	if stored != "passkey" {
		t.Errorf("stored session second factor %q, want passkey", stored)
	}
	var event string
	if err := w.D.Row(w.T, `SELECT second_factor FROM auth_events WHERE principal_id = $1 AND source = 'passkey_login' AND result = 'signed_in'`, id).Scan(&event); err != nil {
		w.T.Fatal(err)
	}
	if event != "passkey" {
		t.Errorf("signed_in event second factor %q, want passkey", event)
	}
}

func countOf(list []string, s string) int {
	n := 0
	for _, v := range list {
		if v == s {
			n++
		}
	}
	return n
}
