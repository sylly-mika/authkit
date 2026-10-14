package authkit_test

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

var (
	fm        = authkit.Meta{IP: "192.0.2.9", UserAgent: "authkit-test"}
	codeShape = regexp.MustCompile(`^[0-9]{6}$`)
)

type emailRowState struct {
	ID        uuid.UUID
	Hashed    bool
	Tries     int
	Sends     int
	ExpiresAt time.Time
}

func (w *world) beginEmail(c *authkit.Claims) authkit.Result {
	w.t.Helper()
	res, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.BeginEmailCodeSetup(w.ctx, q, c, fm)
	})
	if err != nil {
		w.t.Fatalf("BeginEmailCodeSetup: %v", err)
	}
	if res.Refusal == nil && res.EmailCode == nil {
		w.t.Fatal("BeginEmailCodeSetup: no code request and no refusal")
	}
	return res
}

func (w *world) confirmEmail(c *authkit.Claims, code string) authkit.Result {
	w.t.Helper()
	res, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.ConfirmEmailCode(w.ctx, q, c, code, fm)
	})
	if err != nil {
		w.t.Fatalf("ConfirmEmailCode: %v", err)
	}
	return res
}

func (w *world) requestProof(c *authkit.Claims) authkit.Result {
	w.t.Helper()
	res, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.RequestEmailProof(w.ctx, q, c, fm)
	})
	if err != nil {
		w.t.Fatalf("RequestEmailProof: %v", err)
	}
	return res
}

func (w *world) disable(c *authkit.Claims, kind authkit.FactorKind, proof authkit.FactorProof) authkit.Result {
	w.t.Helper()
	res, err := w.factor(func(q db.Querier) (authkit.Result, error) {
		return w.svc.DisableSecondFactor(w.ctx, q, c, kind, proof, fm)
	})
	if err != nil {
		w.t.Fatalf("DisableSecondFactor: %v", err)
	}
	return res
}

func (w *world) mint(id uuid.UUID) (authkit.EmailCodeMail, error) {
	w.t.Helper()
	var mail authkit.EmailCodeMail
	err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
		var err error
		mail, err = w.svc.MintEmailCode(w.ctx, q, id)
		return err
	})
	return mail, err
}

func (w *world) enrolEmail(c *authkit.Claims) []string {
	w.t.Helper()
	b := w.beginEmail(c)
	if b.Refusal != nil || b.EmailCode == nil {
		w.t.Fatalf("enrol email: %v", b.Refusal)
	}
	mail, err := w.mint(b.EmailCode.ID)
	if err != nil {
		w.t.Fatalf("enrol email: mint: %v", err)
	}
	r := w.confirmEmail(c, mail.Code)
	if r.Refusal != nil {
		w.t.Fatalf("enrol email: %v", r.Refusal)
	}
	return r.RecoveryCodes
}

func (w *world) wrongTOTP(secret string) string {
	w.t.Helper()
	now := w.clock.Now()
	right := map[string]bool{}
	for _, at := range []time.Time{now.Add(-30 * time.Second), now, now.Add(30 * time.Second)} {
		right[totpCode(w.t, secret, at)] = true
	}
	for d := byte('0'); d <= '9'; d++ {
		code := strings.Repeat(string(d), 6)
		if !right[code] {
			return code
		}
	}
	w.t.Fatal("no wrong TOTP code")
	return ""
}

func (w *world) otherCode(code string) string {
	last := code[len(code)-1]
	return code[:len(code)-1] + string('0'+(last-'0'+1)%10)
}

func (w *world) events(id uuid.UUID, result string) int {
	w.t.Helper()
	return w.count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND source = 'second_factor' AND result = $2`, id, result)
}

func (w *world) emailRow(id uuid.UUID, purpose string) (emailRowState, bool) {
	w.t.Helper()
	var s emailRowState
	err := w.d.Row(w.t, `SELECT id, code_hash IS NOT NULL, tries, sends, expires_at FROM auth_email_codes WHERE principal_id = $1 AND purpose = $2`, id, purpose).Scan(&s.ID, &s.Hashed, &s.Tries, &s.Sends, &s.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return s, false
	}
	if err != nil {
		w.t.Fatal(err)
	}
	return s, true
}

func (w *world) sessionFactor(id uuid.UUID) string {
	w.t.Helper()
	var kind string
	if err := w.d.Row(w.t, `SELECT second_factor FROM auth_sessions WHERE id = $1`, id).Scan(&kind); err != nil {
		w.t.Fatal(err)
	}
	return kind
}

func TestEmailFactorTurnsOnThroughAMintedCode(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	a := w.signIn("ada@example.invalid", "the right password")
	c := w.claims(a)
	now := w.clock.Now()

	b := w.beginEmail(c)
	if b.Refusal != nil || b.EmailCode == nil {
		t.Fatalf("BeginEmailCodeSetup = %v", b.Refusal)
	}
	if !b.EmailCode.ExpiresAt.Equal(now.Add(10 * time.Minute)) {
		t.Errorf("ExpiresAt = %v, want %v", b.EmailCode.ExpiresAt, now.Add(10*time.Minute))
	}
	row, found := w.emailRow(ada, "enable")
	if !found || row.Hashed || row.Tries != 0 || row.Sends != 1 {
		t.Errorf("enable row = %+v (found %v), want no hash, 0 tries, 1 send", row, found)
	}
	if n := w.count("SELECT count(*) FROM auth_second_factors WHERE principal_id = $1", ada); n != 0 {
		t.Errorf("auth_second_factors rows after begin = %d, want 0", n)
	}

	mail, err := w.mint(b.EmailCode.ID)
	if err != nil {
		t.Fatalf("MintEmailCode: %v", err)
	}
	if mail.PrincipalID != ada || mail.Purpose != "enable" || !mail.ExpiresAt.Equal(b.EmailCode.ExpiresAt) || !codeShape.MatchString(mail.Code) {
		t.Fatalf("MintEmailCode = principal %v purpose %q expires %v, want %v, enable; code <redacted>", mail.PrincipalID, mail.Purpose, mail.ExpiresAt, b.EmailCode.ExpiresAt)
	}

	r := w.confirmEmail(c, mail.Code)
	if r.Refusal != nil {
		t.Fatalf("ConfirmEmailCode refused: %v", r.Refusal)
	}
	seen := map[string]bool{}
	for _, code := range r.RecoveryCodes {
		seen[code] = true
	}
	if len(r.RecoveryCodes) != 10 || len(seen) != 10 {
		t.Errorf("RecoveryCodes = %d (%d distinct), want 10 distinct", len(r.RecoveryCodes), len(seen))
	}
	if n := w.count(`SELECT count(*) FROM auth_second_factors WHERE principal_id = $1 AND kind = 'email' AND secret IS NULL AND confirmed_at = $2`, ada, now); n != 1 {
		t.Errorf("confirmed email factor rows = %d, want 1", n)
	}
	if n := w.count(`SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1 AND used_at IS NULL`, ada); n != 10 {
		t.Errorf("unused recovery rows = %d, want 10", n)
	}
	if n := w.count(`SELECT count(*) FROM auth_email_codes WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("auth_email_codes rows after confirm = %d, want 0", n)
	}
	if got := w.sessionFactor(a.Session.ID); got != "email" {
		t.Errorf("session second_factor = %q, want email", got)
	}
	if n := w.count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND source = 'second_factor' AND result = 'factor_added' AND second_factor = 'email' AND session_id = $2 AND ip = '192.0.2.9'`, ada, a.Session.ID); n != 1 {
		t.Errorf("factor_added events with the email factor = %d, want 1", n)
	}
	w.wantStatus(c, authkit.FactorStatus{Email: true, RecoveryCodesLeft: 10})
}

func TestTheEmailCodeIsStoredAsAKeyedHash(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	b := w.beginEmail(c)
	mail, err := w.mint(b.EmailCode.ID)
	if err != nil {
		t.Fatalf("MintEmailCode: %v", err)
	}
	var hash []byte
	if err := w.d.Row(w.t, `SELECT code_hash FROM auth_email_codes WHERE principal_id = $1 AND purpose = 'enable'`, ada).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(mail.Code))
	if len(hash) != 32 || bytes.Equal(hash, []byte(mail.Code)) || bytes.Equal(hash, sum[:]) {
		t.Errorf("code_hash is %d bytes, not a keyed hash of the code", len(hash))
	}
	if n := w.count(`SELECT position(convert_to($2, 'UTF8') in code_hash) FROM auth_email_codes WHERE principal_id = $1`, ada, mail.Code); n != 0 {
		t.Errorf("code_hash holds the code in clear")
	}
	if n := w.count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND source = 'second_factor'`, ada); n != 0 {
		t.Errorf("second-factor auth_events rows after begin and mint = %d, want 0", n)
	}
}

func TestAResendReplacesTheEmailCode(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	b1 := w.beginEmail(c)
	m1, err := w.mint(b1.EmailCode.ID)
	if err != nil {
		t.Fatalf("MintEmailCode: %v", err)
	}
	w.clock.Advance(61 * time.Second)
	b2 := w.beginEmail(c)
	if b2.Refusal != nil || b2.EmailCode == nil {
		t.Fatalf("second BeginEmailCodeSetup = %v", b2.Refusal)
	}
	if b2.EmailCode.ID == b1.EmailCode.ID {
		t.Errorf("resend kept the id %v", b1.EmailCode.ID)
	}
	if want := w.clock.Now().Add(10 * time.Minute); !b2.EmailCode.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", b2.EmailCode.ExpiresAt, want)
	}
	row, _ := w.emailRow(ada, "enable")
	if row.Hashed || row.Tries != 0 || row.Sends != 2 {
		t.Errorf("row after resend = %+v, want no hash, 0 tries, 2 sends", row)
	}
	if _, err := w.mint(b1.EmailCode.ID); !errors.Is(err, authkit.ErrCodeEnded) {
		t.Errorf("minting the replaced id = %v, want ErrCodeEnded", err)
	}
	m2, err := w.mint(b2.EmailCode.ID)
	if err != nil {
		t.Fatalf("MintEmailCode after resend: %v", err)
	}
	if m2.Code == m1.Code {
		t.Fatal("codes collide: <redacted>")
	}
	if r := w.confirmEmail(c, m1.Code); !errors.Is(r.Refusal, authkit.ErrBadCode) {
		t.Errorf("confirm with the replaced code = %v, want ErrBadCode", r.Refusal)
	}
	if n := w.count(`SELECT count(*) FROM auth_second_factors WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("factor rows after a bad confirm = %d, want 0", n)
	}
	if r := w.confirmEmail(c, m2.Code); r.Refusal != nil {
		t.Errorf("confirm with the new code = %v, want nil", r.Refusal)
	}
}

func TestAResendWaitsResendEvery(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	b1 := w.beginEmail(c)
	if _, err := w.mint(b1.EmailCode.ID); err != nil {
		t.Fatalf("MintEmailCode: %v", err)
	}
	w.clock.Advance(30 * time.Second)
	b2 := w.beginEmail(c)
	var tooSoon authkit.ErrResendTooSoon
	if !errors.As(b2.Refusal, &tooSoon) || tooSoon.RetryAfter != 30*time.Second || b2.EmailCode != nil {
		t.Fatalf("resend at 30s = %v, want ErrResendTooSoon with 30s", b2.Refusal)
	}
	row, _ := w.emailRow(ada, "enable")
	if row.ID != b1.EmailCode.ID || !row.Hashed || row.Sends != 1 {
		t.Errorf("row after a refused resend = %+v, want the first id, a hash, 1 send", row)
	}
	w.clock.Advance(30 * time.Second)
	if b3 := w.beginEmail(c); b3.Refusal != nil {
		t.Fatalf("resend at 60s = %v, want nil", b3.Refusal)
	}
	if row, _ := w.emailRow(ada, "enable"); row.Sends != 2 {
		t.Errorf("sends after the second resend = %d, want 2", row.Sends)
	}
}

func TestAnEmailCodeRowAllowsFiveSends(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	var last authkit.Result
	for i := 0; i < 5; i++ {
		if i > 0 {
			w.clock.Advance(60 * time.Second)
		}
		last = w.beginEmail(c)
		if last.Refusal != nil {
			t.Fatalf("begin %d = %v, want nil", i+1, last.Refusal)
		}
	}
	if row, _ := w.emailRow(ada, "enable"); row.Sends != 5 {
		t.Fatalf("sends = %d, want 5", row.Sends)
	}
	w.clock.Advance(30 * time.Second)
	refused := w.beginEmail(c)
	var tooSoon authkit.ErrResendTooSoon
	if !errors.As(refused.Refusal, &tooSoon) || tooSoon.RetryAfter != 570*time.Second {
		t.Fatalf("sixth begin = %v, want ErrResendTooSoon with 570s", refused.Refusal)
	}
	row, _ := w.emailRow(ada, "enable")
	if row.ID != last.EmailCode.ID || row.Sends != 5 {
		t.Errorf("row after the refused sixth begin = %+v, want the fifth id and 5 sends", row)
	}
	w.clock.Advance(571 * time.Second)
	b := w.signIn("ada@example.invalid", "the right password")
	if r := w.beginEmail(w.claims(b)); r.Refusal != nil {
		t.Fatalf("begin on a fresh row = %v, want nil", r.Refusal)
	}
	if row, _ := w.emailRow(ada, "enable"); row.Sends != 1 {
		t.Errorf("sends on a fresh row = %d, want 1", row.Sends)
	}
}

func TestAnEmailCodeAllowsFiveWrongTries(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	b := w.beginEmail(c)
	m, err := w.mint(b.EmailCode.ID)
	if err != nil {
		t.Fatalf("MintEmailCode: %v", err)
	}
	for i := 0; i < 5; i++ {
		if r := w.confirmEmail(c, w.otherCode(m.Code)); !errors.Is(r.Refusal, authkit.ErrBadCode) {
			t.Fatalf("wrong try %d = %v, want ErrBadCode", i+1, r.Refusal)
		}
	}
	if row, _ := w.emailRow(ada, "enable"); row.Tries != 5 {
		t.Errorf("tries = %d, want 5", row.Tries)
	}
	if r := w.confirmEmail(c, m.Code); !errors.Is(r.Refusal, authkit.ErrCodeEnded) {
		t.Errorf("sixth try with the right code = %v, want ErrCodeEnded", r.Refusal)
	}
	if n := w.count(`SELECT count(*) FROM auth_second_factors WHERE principal_id = $1 AND confirmed_at IS NOT NULL`, ada); n != 0 {
		t.Errorf("factor rows = %d, want 0", n)
	}
	if n := w.count(`SELECT count(*) FROM auth_recovery_codes WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("recovery rows = %d, want 0", n)
	}
	if n := w.count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND source = 'second_factor' AND result = 'bad_code' AND second_factor = 'email'`, ada); n != 5 {
		t.Errorf("bad_code events = %d, want 5", n)
	}
	if n := w.events(ada, "factor_added"); n != 0 {
		t.Errorf("factor_added events = %d, want 0", n)
	}
	if got := w.sessionFactor(c.SessionID); got != "" {
		t.Errorf("session second_factor = %q, want empty", got)
	}
	if n := w.count(`SELECT count(*) FROM auth_throttle`); n != 0 {
		t.Errorf("throttle rows = %d, want 0", n)
	}
}

func TestAnEmailCodeExpiresOnTheInjectedClock(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	b := w.beginEmail(c)
	m, err := w.mint(b.EmailCode.ID)
	if err != nil {
		t.Fatalf("MintEmailCode: %v", err)
	}
	w.clock.Advance(10*time.Minute + time.Second)
	fresh := w.claims(w.signIn("ada@example.invalid", "the right password"))
	if r := w.confirmEmail(fresh, m.Code); !errors.Is(r.Refusal, authkit.ErrCodeEnded) {
		t.Errorf("confirm after expiry = %v, want ErrCodeEnded", r.Refusal)
	}
	if n := w.count(`SELECT count(*) FROM auth_second_factors WHERE principal_id = $1 AND confirmed_at IS NOT NULL`, ada); n != 0 {
		t.Errorf("factor rows after expiry = %d, want 0", n)
	}
	if _, err := w.mint(b.EmailCode.ID); !errors.Is(err, authkit.ErrCodeEnded) {
		t.Errorf("mint after expiry = %v, want ErrCodeEnded", err)
	}

	b2 := w.beginEmail(fresh)
	m2, err := w.mint(b2.EmailCode.ID)
	if err != nil {
		t.Fatalf("MintEmailCode control: %v", err)
	}
	if r := w.confirmEmail(fresh, m2.Code); r.Refusal != nil {
		t.Errorf("control confirm = %v, want nil", r.Refusal)
	}
}

func TestAnUnmintedEmailCodeIsEnded(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	w.beginEmail(c)
	if r := w.confirmEmail(c, "123456"); !errors.Is(r.Refusal, authkit.ErrCodeEnded) {
		t.Errorf("confirm before a mint = %v, want ErrCodeEnded", r.Refusal)
	}
	row, _ := w.emailRow(ada, "enable")
	if row.Tries != 0 || row.Hashed {
		t.Errorf("row = %+v, want 0 tries and no hash", row)
	}
	if n := w.count(`SELECT count(*) FROM auth_second_factors WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("factor rows = %d, want 0", n)
	}
}

func TestReMintReplacesTheCodeAndKeepsTheTries(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	b := w.beginEmail(c)
	m1, err := w.mint(b.EmailCode.ID)
	if err != nil {
		t.Fatalf("MintEmailCode: %v", err)
	}
	if r := w.confirmEmail(c, w.otherCode(m1.Code)); !errors.Is(r.Refusal, authkit.ErrBadCode) {
		t.Fatalf("wrong try = %v, want ErrBadCode", r.Refusal)
	}
	m2, err := w.mint(b.EmailCode.ID)
	if err != nil {
		t.Fatalf("re-mint: %v", err)
	}
	if !m2.ExpiresAt.Equal(m1.ExpiresAt) {
		t.Errorf("re-mint expiry = %v, want %v", m2.ExpiresAt, m1.ExpiresAt)
	}
	if m2.Code == m1.Code {
		t.Fatal("re-mint kept the code: <redacted>")
	}
	if row, _ := w.emailRow(ada, "enable"); row.Tries != 1 {
		t.Errorf("tries after re-mint = %d, want 1", row.Tries)
	}
	if r := w.confirmEmail(c, m1.Code); !errors.Is(r.Refusal, authkit.ErrBadCode) {
		t.Errorf("confirm with the first code = %v, want ErrBadCode", r.Refusal)
	}
	if r := w.confirmEmail(c, m2.Code); r.Refusal != nil {
		t.Errorf("confirm with the re-minted code = %v, want nil", r.Refusal)
	}
}

func TestBeginEmailCodeSetupNeedsARecentSignIn(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	w.clock.Advance(5*time.Minute + time.Second)
	r := w.beginEmail(c)
	if !errors.Is(r.Refusal, authkit.ErrReauthRequired) || r.EmailCode != nil {
		t.Errorf("begin after 5m = %v, want ErrReauthRequired", r.Refusal)
	}
	if n := w.count(`SELECT count(*) FROM auth_email_codes WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("email code rows = %d, want 0", n)
	}
}

func TestConfirmEmailCodeNeedsARecentSignIn(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	a := w.signIn("ada@example.invalid", "the right password")
	c := w.claims(a)

	b := w.beginEmail(c)
	m, err := w.mint(b.EmailCode.ID)
	if err != nil {
		t.Fatalf("MintEmailCode: %v", err)
	}
	w.clock.Advance(5*time.Minute + time.Second)
	if r := w.confirmEmail(c, m.Code); !errors.Is(r.Refusal, authkit.ErrReauthRequired) {
		t.Fatalf("confirm after 5m = %v, want ErrReauthRequired", r.Refusal)
	}
	if n := w.count(`SELECT count(*) FROM auth_second_factors WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("factor rows = %d, want 0", n)
	}
	if row, _ := w.emailRow(ada, "enable"); !row.Hashed || row.Tries != 0 {
		t.Errorf("row = %+v, want a hash and 0 tries", row)
	}
	fresh := w.signIn("ada@example.invalid", "the right password")
	if r := w.confirmEmail(w.claims(fresh), m.Code); r.Refusal != nil {
		t.Fatalf("confirm after a fresh sign-in = %v, want nil", r.Refusal)
	}
	if got := w.sessionFactor(fresh.Session.ID); got != "email" {
		t.Errorf("fresh session second_factor = %q, want email", got)
	}
	if got := w.sessionFactor(a.Session.ID); got != "" {
		t.Errorf("old session second_factor = %q, want empty", got)
	}
}

func TestASecondEmailSetupIsRefused(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	w.enrolEmail(c)
	if r := w.beginEmail(c); !errors.Is(r.Refusal, authkit.ErrFactorExists) {
		t.Errorf("second begin = %v, want ErrFactorExists", r.Refusal)
	}
	if n := w.count(`SELECT count(*) FROM auth_email_codes WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("email code rows = %d, want 0", n)
	}
	if r := w.confirmEmail(c, "123456"); !errors.Is(r.Refusal, authkit.ErrFactorExists) {
		t.Errorf("second confirm = %v, want ErrFactorExists", r.Refusal)
	}
	if n := w.count(`SELECT count(*) FROM auth_second_factors WHERE principal_id = $1 AND kind = 'email'`, ada); n != 1 {
		t.Errorf("email factor rows = %d, want 1", n)
	}
	if n := w.events(ada, "factor_added"); n != 1 {
		t.Errorf("factor_added events = %d, want 1", n)
	}
}

func TestEmailAfterTOTPKeepsTheRecoveryCodes(t *testing.T) {
	w := newWorld(t, withSecondFactors)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	w.setUpTOTP(c)
	snapshot := func() string {
		var s string
		if err := w.d.Row(w.t, `SELECT string_agg(encode(code_hash, 'hex'), ',' ORDER BY code_hash) FROM auth_recovery_codes WHERE principal_id = $1`, ada).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := snapshot()
	if codes := w.enrolEmail(c); len(codes) != 0 {
		t.Errorf("email confirm returned %d recovery codes, want none", len(codes))
	}
	if after := snapshot(); after != before {
		t.Errorf("recovery code hashes changed when the email factor was added")
	}
	if got := w.sessionFactor(c.SessionID); got != "totp" {
		t.Errorf("session second_factor = %q, want totp", got)
	}
	w.wantStatus(c, authkit.FactorStatus{TOTP: true, Email: true, RecoveryCodesLeft: 10})
}

func TestEmailMethodsAreOffWithoutAKey(t *testing.T) {
	w := newWorld(t)
	ada := w.user("ada@example.invalid", "the right password")
	c := w.claims(w.signIn("ada@example.invalid", "the right password"))

	calls := map[string]func(q db.Querier) (authkit.Result, error){
		"BeginEmailCodeSetup": func(q db.Querier) (authkit.Result, error) { return w.svc.BeginEmailCodeSetup(w.ctx, q, c, fm) },
		"ConfirmEmailCode":    func(q db.Querier) (authkit.Result, error) { return w.svc.ConfirmEmailCode(w.ctx, q, c, "123456", fm) },
		"RequestEmailProof":   func(q db.Querier) (authkit.Result, error) { return w.svc.RequestEmailProof(w.ctx, q, c, fm) },
		"DisableSecondFactor": func(q db.Querier) (authkit.Result, error) {
			return w.svc.DisableSecondFactor(w.ctx, q, c, authkit.FactorTOTP, authkit.FactorProof{Method: authkit.FactorTOTP, Code: "123456"}, fm)
		},
	}
	for name, call := range calls {
		res, err := w.factor(call)
		if err != nil || res.Refusal != authkit.ErrSecondFactorsOff {
			t.Errorf("%s = %v, %v, want ErrSecondFactorsOff with a nil error", name, res.Refusal, err)
		}
	}
	if _, err := w.mint(uuid.New()); !errors.Is(err, authkit.ErrSecondFactorsOff) {
		t.Errorf("MintEmailCode = %v, want ErrSecondFactorsOff", err)
	}
	if n := w.count(`SELECT count(*) FROM auth_email_codes WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("email code rows = %d, want 0", n)
	}
	if n := w.count(`SELECT count(*) FROM auth_second_factors WHERE principal_id = $1`, ada); n != 0 {
		t.Errorf("factor rows = %d, want 0", n)
	}
	if n := w.count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND second_factor <> ''`, ada); n != 0 {
		t.Errorf("second_factor events = %d, want 0", n)
	}
}
