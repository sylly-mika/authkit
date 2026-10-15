package tests

import (
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/internal/token"
)

var sixDigits = regexp.MustCompile(`^[0-9]{6}$`)

func emailWorld(t *testing.T, tweaks ...func(*kittest.Rules)) *world {
	t.Helper()
	return withFactorClaim(newWorld(t, append([]func(*kittest.Rules){factors}, tweaks...)...))
}

func (w *world) emailUser() uuid.UUID {
	w.T.Helper()
	id := w.User("ada@example.invalid", pw)
	w.D.Exec(w.T, "INSERT INTO auth_second_factors (principal_id, kind, created_at, confirmed_at) VALUES ($1, 'email', $2, $2)", id, w.Clock.Now())
	return id
}

func (w *world) stepSend(aud authkit.Audience, tok string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.SendSecondStepEmail(w.Ctx, q, aud, tok, meta)
	})
}

func (w *world) codeRow(id uuid.UUID) emailRowState {
	w.T.Helper()
	row, ok := w.emailRow(id, "sign_in")
	if !ok {
		w.T.Fatalf("no sign-in code row for %v", id)
	}
	return row
}

func (w *world) codeRows(id uuid.UUID) int {
	w.T.Helper()
	return w.Count(`SELECT count(*) FROM auth_email_codes WHERE principal_id = $1 AND purpose = 'sign_in'`, id)
}

func (w *world) sessionCount(id uuid.UUID) int {
	w.T.Helper()
	return w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, id)
}

func (w *world) challengeTries(tok string) int {
	w.T.Helper()
	return w.Count(`SELECT tries FROM auth_second_step_challenges WHERE challenge_hash = $1`, token.Hash(tok))
}

func (w *world) throttleFailures() int {
	w.T.Helper()
	return w.Count(`SELECT failures FROM auth_throttle WHERE login = 'ada@example.invalid' AND audience = 'staff'`)
}

func TestSendSecondStepEmailIssuesASignInCode(t *testing.T) {
	login := "ada@example.invalid"
	w := emailWorld(t)
	id := w.emailUser()
	tok := w.challenge(login)
	ev := w.Count(`SELECT count(*) FROM auth_events`)
	res := w.stepSend("staff", tok)
	if res.Refusal != nil || res.EmailCode == nil || res.EmailCode.ID == uuid.Nil {
		t.Fatalf("send: refusal %v, email code %v", res.Refusal, res.EmailCode)
	}
	if want := w.Clock.Now().Add(10 * time.Minute); !res.EmailCode.ExpiresAt.Equal(want) {
		t.Fatalf("expires %v, want %v", res.EmailCode.ExpiresAt, want)
	}
	if res.Principal.ID != id || res.Principal.Login != login {
		t.Fatalf("principal %v %q, want %v %q", res.Principal.ID, res.Principal.Login, id, login)
	}
	if res.Session != nil || res.Tokens != nil {
		t.Fatalf("send opened a session")
	}
	row := w.codeRow(id)
	if row.ID != res.EmailCode.ID || row.Hashed || row.Tries != 0 || row.Sends != 1 {
		t.Fatalf("code row %+v, want id %v, unhashed, tries 0, sends 1", row, res.EmailCode.ID)
	}
	if n := w.Count(`SELECT count(*) FROM auth_events`); n != ev {
		t.Fatalf("send wrote %d events, want %d", n, ev)
	}
	if n := w.challengeTries(tok); n != 0 {
		t.Fatalf("challenge tries %d, want 0", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_throttle WHERE login = $1`, login); n != 0 {
		t.Fatalf("send wrote %d throttle rows, want 0", n)
	}
	mail, err := w.mint(res.EmailCode.ID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if mail.Purpose != "sign_in" || mail.PrincipalID != id {
		t.Fatalf("mint = principal %v purpose %q, want %v sign_in", mail.PrincipalID, mail.Purpose, id)
	}
	if !sixDigits.MatchString(mail.Code) {
		t.Fatalf("code <redacted> is not six digits")
	}
}

func TestSecondStepEmailCodeSignsIn(t *testing.T) {
	login := "ada@example.invalid"
	w := emailWorld(t)
	id := w.emailUser()
	tok := w.challenge(login)
	sent := w.stepSend("staff", tok)
	mail, err := w.mint(sent.EmailCode.ID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	res := w.verify("staff", tok, authkit.FactorEmail, mail.Code)
	if res.Refusal != nil || res.Session == nil || res.Tokens == nil {
		t.Fatalf("verify refused: %v", res.Refusal)
	}
	if got := w.Claims(res).App["factor"]; got != "email" {
		t.Fatalf("claim factor = %v, want email", got)
	}
	if got := w.sessionFactor(res.Session.ID); got != "email" {
		t.Fatalf("session factor %q, want email", got)
	}
	if n := w.Count(`SELECT count(*) FROM auth_events WHERE source = 'second_step' AND result = 'signed_in' AND second_factor = 'email'`); n != 1 {
		t.Fatalf("signed_in events for email = %d, want 1", n)
	}
	if n := w.codeRows(id); n != 0 {
		t.Fatalf("code rows after sign-in %d, want 0", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_second_step_challenges WHERE challenge_hash = $1 AND used_at IS NOT NULL`, token.Hash(tok)); n != 1 {
		t.Fatalf("challenge not spent")
	}
}

func TestSecondStepEmailCodeIsSpentOnce(t *testing.T) {
	login := "ada@example.invalid"
	w := emailWorld(t)
	id := w.emailUser()
	tok := w.challenge(login)
	sent := w.stepSend("staff", tok)
	mail, err := w.mint(sent.EmailCode.ID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if res := w.verify("staff", tok, authkit.FactorEmail, mail.Code); res.Refusal != nil || res.Session == nil {
		t.Fatalf("first sign-in refused: %v", res.Refusal)
	}
	tok2 := w.challenge(login)
	res := w.verify("staff", tok2, authkit.FactorEmail, mail.Code)
	if !errors.Is(res.Refusal, authkit.ErrBadCode) || res.Session != nil || res.Tokens != nil {
		t.Fatalf("reused code: refusal %v, session %v", res.Refusal, res.Session != nil)
	}
	if n := w.sessionCount(id); n != 1 {
		t.Fatalf("sessions %d, want 1", n)
	}
	if n := w.challengeTries(tok2); n != 1 {
		t.Fatalf("second challenge tries %d, want 1", n)
	}
}

func TestSecondStepEmailResendKillsTheOldCode(t *testing.T) {
	login := "ada@example.invalid"
	w := emailWorld(t)
	id := w.emailUser()
	tok := w.challenge(login)
	r1 := w.stepSend("staff", tok)
	m1, err := w.mint(r1.EmailCode.ID)
	if err != nil {
		t.Fatalf("mint first: %v", err)
	}
	w.Clock.Advance(61 * time.Second)
	r2 := w.stepSend("staff", tok)
	if r2.Refusal != nil || r2.EmailCode == nil || r2.EmailCode.ID == r1.EmailCode.ID {
		t.Fatalf("resend: refusal %v, same id %v", r2.Refusal, r2.EmailCode != nil && r2.EmailCode.ID == r1.EmailCode.ID)
	}
	if row := w.codeRow(id); row.ID != r2.EmailCode.ID || row.Sends != 2 {
		t.Fatalf("code row %+v, want id of the resend and sends 2", row)
	}
	if _, err := w.mint(r1.EmailCode.ID); !errors.Is(err, authkit.ErrCodeEnded) {
		t.Fatalf("mint of the replaced code: %v, want ErrCodeEnded", err)
	}
	m2, err := w.mint(r2.EmailCode.ID)
	if err != nil {
		t.Fatalf("mint second: %v", err)
	}
	if m1.Code == m2.Code {
		t.Skip("<redacted>: equal codes")
	}
	if res := w.verify("staff", tok, authkit.FactorEmail, m1.Code); !errors.Is(res.Refusal, authkit.ErrBadCode) {
		t.Fatalf("old code: refusal %v, want ErrBadCode", res.Refusal)
	}
	if n := w.sessionCount(id); n != 0 {
		t.Fatalf("sessions after old code %d, want 0", n)
	}
	if res := w.verify("staff", tok, authkit.FactorEmail, m2.Code); res.Session == nil {
		t.Fatalf("new code refused: %v", res.Refusal)
	}
}

func TestSecondStepEmailResendWaitsResendEvery(t *testing.T) {
	login := "ada@example.invalid"
	w := emailWorld(t)
	id := w.emailUser()
	tok := w.challenge(login)
	r1 := w.stepSend("staff", tok)
	w.Clock.Advance(30 * time.Second)
	r2 := w.stepSend("staff", tok)
	var tooSoon authkit.ErrResendTooSoon
	if !errors.As(r2.Refusal, &tooSoon) || tooSoon.RetryAfter != 30*time.Second || r2.EmailCode != nil {
		t.Fatalf("early resend: refusal %v, want ErrResendTooSoon 30s", r2.Refusal)
	}
	if row := w.codeRow(id); row.ID != r1.EmailCode.ID || row.Sends != 1 {
		t.Fatalf("code row %+v, want the first code with sends 1", row)
	}
	w.Clock.Advance(30 * time.Second)
	if r3 := w.stepSend("staff", tok); r3.Refusal != nil {
		t.Fatalf("resend after ResendEvery: %v", r3.Refusal)
	}
	if row := w.codeRow(id); row.Sends != 2 {
		t.Fatalf("sends %d, want 2", row.Sends)
	}
}

func TestSecondStepEmailStopsAtMaxSends(t *testing.T) {
	login := "ada@example.invalid"
	w := emailWorld(t)
	id := w.emailUser()
	tok := w.challenge(login)
	last := w.stepSend("staff", tok)
	for i := 2; i <= 5; i++ {
		w.Clock.Advance(60 * time.Second)
		last = w.stepSend("staff", tok)
		if last.Refusal != nil {
			t.Fatalf("send %d: %v", i, last.Refusal)
		}
	}
	if row := w.codeRow(id); row.Sends != 5 {
		t.Fatalf("sends %d, want 5", row.Sends)
	}
	w.Clock.Advance(60 * time.Second)
	sixth := w.stepSend("staff", tok)
	var tooSoon authkit.ErrResendTooSoon
	if !errors.As(sixth.Refusal, &tooSoon) || tooSoon.RetryAfter != 9*time.Minute {
		t.Fatalf("sixth send: refusal %v, want ErrResendTooSoon 9m", sixth.Refusal)
	}
	if row := w.codeRow(id); row.Sends != 5 || row.ID != last.EmailCode.ID {
		t.Fatalf("code row %+v, want the last code with sends 5", row)
	}
	w.Clock.Advance(9 * time.Minute)
	tok2 := w.challenge(login)
	if r := w.stepSend("staff", tok2); r.Refusal != nil {
		t.Fatalf("send after the row ended: %v", r.Refusal)
	}
	if row := w.codeRow(id); row.Sends != 1 {
		t.Fatalf("sends %d after the row ended, want 1", row.Sends)
	}
}

func TestSendSecondStepEmailRefusesAnEndedChallenge(t *testing.T) {
	login := "ada@example.invalid"
	w := emailWorld(t, throttleAt(20))
	id := w.emailUser()
	refused := func(name string, r authkit.Result) {
		t.Helper()
		if !errors.Is(r.Refusal, authkit.ErrChallengeEnded) || r.EmailCode != nil {
			t.Fatalf("%s: refusal %v, want ErrChallengeEnded", name, r.Refusal)
		}
		if n := w.codeRows(id); n != 0 {
			t.Fatalf("%s: %d code rows, want 0", name, n)
		}
	}
	refused("unknown token", w.stepSend("staff", "not-a-token"))
	tok := w.challenge(login)
	refused("other audience", w.stepSend("client", tok))
	w.Clock.Advance(10*time.Minute + time.Second)
	refused("expired", w.stepSend("staff", tok))
	tok2 := w.challenge(login)
	for i := 0; i < 4; i++ {
		if res := w.verify("staff", tok2, authkit.FactorEmail, "000000"); !errors.Is(res.Refusal, authkit.ErrBadCode) {
			t.Fatalf("wrong code %d: %v, want ErrBadCode", i+1, res.Refusal)
		}
	}
	if res := w.verify("staff", tok2, authkit.FactorEmail, "000000"); !errors.Is(res.Refusal, authkit.ErrChallengeEnded) {
		t.Fatalf("fifth wrong code: %v, want ErrChallengeEnded", res.Refusal)
	}
	refused("tries spent", w.stepSend("staff", tok2))
	tok3 := w.challenge(login)
	sent := w.stepSend("staff", tok3)
	if sent.Refusal != nil {
		t.Fatalf("send: %v", sent.Refusal)
	}
	mail, err := w.mint(sent.EmailCode.ID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if res := w.verify("staff", tok3, authkit.FactorEmail, mail.Code); res.Session == nil {
		t.Fatalf("sign-in refused: %v", res.Refusal)
	}
	refused("spent", w.stepSend("staff", tok3))
}

func TestSendSecondStepEmailNeedsAConfirmedEmailFactor(t *testing.T) {
	login := "ada@example.invalid"
	w := emailWorld(t)
	id := w.User(login, pw)
	w.D.Exec(w.T, `INSERT INTO auth_second_factors (principal_id, kind, secret, created_at, confirmed_at) VALUES ($1, 'totp', '\x01'::bytea, $2, $2)`, id, w.Clock.Now())
	w.D.Exec(w.T, `INSERT INTO auth_second_factors (principal_id, kind, secret, created_at, confirmed_at) VALUES ($1, 'email', NULL, $2, NULL)`, id, w.Clock.Now())
	tok := w.challenge(login)
	res := w.stepSend("staff", tok)
	if !errors.Is(res.Refusal, authkit.ErrFactorNotFound) || res.EmailCode != nil {
		t.Fatalf("send: refusal %v, want ErrFactorNotFound", res.Refusal)
	}
	if n := w.codeRows(id); n != 0 {
		t.Fatalf("code rows %d, want 0", n)
	}
	res = w.verify("staff", tok, authkit.FactorEmail, "000000")
	if !errors.Is(res.Refusal, authkit.ErrBadCode) || res.Session != nil {
		t.Fatalf("email verify without the factor: refusal %v", res.Refusal)
	}
	if n := w.sessionCount(id); n != 0 {
		t.Fatalf("sessions %d, want 0", n)
	}
	if n := w.challengeTries(tok); n != 1 {
		t.Fatalf("challenge tries %d, want 1", n)
	}
	if n := w.throttleFailures(); n != 1 {
		t.Fatalf("throttle failures %d, want 1", n)
	}
}

func TestSendSecondStepEmailRefusesALockedLogin(t *testing.T) {
	login := "ada@example.invalid"
	w := emailWorld(t, throttleAt(2))
	id := w.emailUser()
	tok := w.challenge(login)
	for i := 0; i < 2; i++ {
		if res := w.verify("staff", tok, authkit.FactorEmail, "000000"); !errors.Is(res.Refusal, authkit.ErrBadCode) {
			t.Fatalf("wrong code %d: %v, want ErrBadCode", i+1, res.Refusal)
		}
	}
	res := w.stepSend("staff", tok)
	var locked authkit.ErrLocked
	if !errors.As(res.Refusal, &locked) || locked.RetryAfter != 15*time.Minute {
		t.Fatalf("send on a locked login: refusal %v, want ErrLocked 15m", res.Refusal)
	}
	if n := w.codeRows(id); n != 0 {
		t.Fatalf("code rows %d, want 0", n)
	}
}

func TestSecondStepEmailCodeTakesFiveWrongTries(t *testing.T) {
	login := "ada@example.invalid"
	w := emailWorld(t, throttleAt(20))
	id := w.emailUser()
	tokA := w.challenge(login)
	sent := w.stepSend("staff", tokA)
	mail, err := w.mint(sent.EmailCode.ID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	for i := 0; i < 3; i++ {
		if res := w.verify("staff", tokA, authkit.FactorEmail, wrong(mail.Code)); !errors.Is(res.Refusal, authkit.ErrBadCode) {
			t.Fatalf("wrong code %d: %v, want ErrBadCode", i+1, res.Refusal)
		}
	}
	tokB := w.challenge(login)
	for i := 0; i < 2; i++ {
		if res := w.verify("staff", tokB, authkit.FactorEmail, wrong(mail.Code)); !errors.Is(res.Refusal, authkit.ErrBadCode) {
			t.Fatalf("wrong code on B %d: %v, want ErrBadCode", i+1, res.Refusal)
		}
	}
	if row := w.codeRow(id); row.Tries != 5 {
		t.Fatalf("code tries %d, want 5", row.Tries)
	}
	res := w.verify("staff", tokB, authkit.FactorEmail, mail.Code)
	if !errors.Is(res.Refusal, authkit.ErrBadCode) || res.Session != nil {
		t.Fatalf("right code after five tries: refusal %v, want ErrBadCode", res.Refusal)
	}
	if n := w.sessionCount(id); n != 0 {
		t.Fatalf("sessions %d, want 0", n)
	}
	if row := w.codeRow(id); row.Tries != 5 {
		t.Fatalf("code tries %d after the refused code, want 5", row.Tries)
	}
	if n := w.challengeTries(tokB); n != 3 {
		t.Fatalf("challenge B tries %d, want 3", n)
	}
}

func TestSecondStepEmailCodeExpires(t *testing.T) {
	login := "ada@example.invalid"
	w := emailWorld(t, func(c *kittest.Rules) { c.SecondFactors.EmailCodeTTL = 2 * time.Minute })
	w.emailUser()
	tok := w.challenge(login)
	sent := w.stepSend("staff", tok)
	mail, err := w.mint(sent.EmailCode.ID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	w.Clock.Advance(2*time.Minute + time.Second)
	res := w.verify("staff", tok, authkit.FactorEmail, mail.Code)
	if !errors.Is(res.Refusal, authkit.ErrBadCode) || res.Session != nil {
		t.Fatalf("expired code: refusal %v, want ErrBadCode", res.Refusal)
	}
	if n := w.challengeTries(tok); n != 1 {
		t.Fatalf("challenge tries %d, want 1", n)
	}
}

func TestSecondStepEmailWrongCodeIsCounted(t *testing.T) {
	login := "ada@example.invalid"
	w := emailWorld(t)
	id := w.emailUser()
	tok := w.challenge(login)
	sent := w.stepSend("staff", tok)
	mail, err := w.mint(sent.EmailCode.ID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	res := w.verify("staff", tok, authkit.FactorEmail, wrong(mail.Code))
	if !errors.Is(res.Refusal, authkit.ErrBadCode) || res.Session != nil || res.Tokens != nil {
		t.Fatalf("wrong code: refusal %v, want ErrBadCode with no session", res.Refusal)
	}
	if n := w.sessionCount(id); n != 0 {
		t.Fatalf("sessions %d, want 0", n)
	}
	if row := w.codeRow(id); row.Tries != 1 {
		t.Fatalf("code tries %d, want 1", row.Tries)
	}
	if n := w.challengeTries(tok); n != 1 {
		t.Fatalf("challenge tries %d, want 1", n)
	}
	if n := w.throttleFailures(); n != 1 {
		t.Fatalf("throttle failures %d, want 1", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'bad_code'`, id); n != 1 {
		t.Fatalf("bad_code events %d, want 1", n)
	}
	if res := w.verify("staff", tok, authkit.FactorEmail, mail.Code); res.Session == nil {
		t.Fatalf("right code after one wrong: %v", res.Refusal)
	}
	if n := w.Count(`SELECT count(*) FROM auth_throttle WHERE login = 'ada@example.invalid' AND failures > 0`); n != 0 {
		t.Fatalf("throttle rows with failures %d after sign-in, want 0", n)
	}
}

func TestSendSecondStepEmailIsOffWithoutAKey(t *testing.T) {
	w := newWorld(t)
	res := w.stepSend("staff", "any")
	if !errors.Is(res.Refusal, authkit.ErrSecondFactorsOff) || res.EmailCode != nil {
		t.Fatalf("send without a key: refusal %v, want ErrSecondFactorsOff", res.Refusal)
	}
	if n := w.Count(`SELECT count(*) FROM auth_email_codes`); n != 0 {
		t.Fatalf("code rows %d, want 0", n)
	}
}

// WHY: PostgreSQL rounds timestamptz to the nearest microsecond, so this clock's 700ns tail is stored 300ns later than it reads in Go.
type roundingClock struct{}

func (roundingClock) Now() time.Time {
	return time.Date(2040, time.January, 1, 12, 0, 0, 1_000_700, time.UTC)
}

func withRoundingClock(c *kittest.Rules) { c.Clock = roundingClock{} }

func TestAFreshEmailCodeIsNotRefusedAsSentTooSoon(t *testing.T) {
	rows := []struct {
		name string
		send func(t *testing.T) authkit.Result
	}{
		{"begin email setup", func(t *testing.T) authkit.Result {
			w := newWorld(t, withSecondFactors, withRoundingClock)
			w.User("ada@example.invalid", "the right password")
			c := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
			return w.beginEmail(c)
		}},
		{"second step email", func(t *testing.T) authkit.Result {
			login := "ada@example.invalid"
			w := emailWorld(t, withRoundingClock)
			w.emailUser()
			return w.stepSend("staff", w.challenge(login))
		}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			res := r.send(t)
			if res.Refusal != nil || res.EmailCode == nil {
				t.Fatalf("first send: refusal %v, email code %v; want a code and no refusal", res.Refusal, res.EmailCode)
			}
		})
	}
}
