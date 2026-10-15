package tests

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/internal/kittest"
)

var regOrigins = map[authkit.Audience][]string{"staff": {kittest.StaffOrigin}, "client": {kittest.ClientOrigin}}

func regWorld(t *testing.T, origins map[authkit.Audience][]string) *world {
	return newWorld(t, func(c *kittest.Rules) {
		c.Passkeys = authkit.PasskeyRules{RPID: "localhost", Origins: origins, CeremonyTTL: 2 * time.Minute, Reauth: 5 * time.Minute, Max: 10}
		c.RevokeOnPasswordChange = authkit.RevokeOthers
	})
}

func regUser(w *world, login string) (uuid.UUID, authkit.Result) {
	w.T.Helper()
	id := w.User(login, "the right password")
	return id, w.SignIn(login, "the right password")
}

func regBegin(w *world, c *authkit.Claims) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.BeginPasskeyRegistration(w.Ctx, q, c, authkit.Meta{IP: "203.0.113.7", UserAgent: "UA-1"})
	})
}

func regFinish(w *world, c *authkit.Claims, id string, resp []byte, label string) authkit.Result {
	w.T.Helper()
	return w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.FinishPasskeyRegistration(w.Ctx, q, c, id, resp, label, authkit.Meta{IP: "203.0.113.7", UserAgent: "UA-1"})
	})
}

func regAuthn(origin string) *authkittest.Authenticator {
	return authkittest.NewAuthenticator("localhost", origin)
}

func regCreate(t *testing.T, a *authkittest.Authenticator, cer *authkit.Ceremony) []byte {
	t.Helper()
	resp, err := a.Create(cer.Options)
	if err != nil {
		t.Fatalf("create the authenticator's response: %v", err)
	}
	return resp
}

func regPasskeys(w *world, id uuid.UUID) int {
	w.T.Helper()
	return w.Count(`SELECT count(*) FROM auth_passkeys WHERE principal_id = $1`, id)
}

func regCeremonies(w *world, id uuid.UUID) (all, spent int) {
	w.T.Helper()
	if err := w.D.Row(w.T, `SELECT count(*), count(*) FILTER (WHERE used_at IS NOT NULL) FROM auth_passkey_ceremonies WHERE principal_id = $1`, id).Scan(&all, &spent); err != nil {
		w.T.Fatal(err)
	}
	return all, spent
}

func regAdded(w *world, id uuid.UUID) int {
	w.T.Helper()
	return w.Count(`SELECT count(*) FROM auth_events WHERE principal_id = $1 AND result = 'passkey_added'`, id)
}

func regRefused(t *testing.T, res authkit.Result, want error) {
	t.Helper()
	if !errors.Is(res.Refusal, want) || res.Passkey != nil {
		t.Fatalf("result = refusal %v, passkey stored %v; want refused %v", res.Refusal, res.Passkey != nil, want)
	}
}

type regOptions struct {
	PublicKey struct {
		Selection struct {
			ResidentKey      string `json:"residentKey"`
			UserVerification string `json:"userVerification"`
		} `json:"authenticatorSelection"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Exclude []struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"excludeCredentials"`
	} `json:"publicKey"`
}

func regParse(t *testing.T, cer *authkit.Ceremony) regOptions {
	t.Helper()
	var o regOptions
	if err := json.Unmarshal(cer.Options, &o); err != nil {
		t.Fatalf("parse the options: %v", err)
	}
	return o
}

func TestAddAPasskey(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	if begin.Refusal != nil || begin.Ceremony == nil {
		t.Fatalf("begin: refusal %v, ceremony given %v", begin.Refusal, begin.Ceremony != nil)
	}
	if begin.Ceremony.ID == "" {
		t.Fatal("begin: the ceremony has no id")
	}
	if want := w.Clock.Now().Add(2 * time.Minute); !begin.Ceremony.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", begin.Ceremony.ExpiresAt, want)
	}
	o := regParse(t, begin.Ceremony)
	if o.PublicKey.Selection.ResidentKey != "required" || o.PublicKey.Selection.UserVerification != "required" {
		t.Fatalf("authenticatorSelection = %q/%q, want required/required", o.PublicKey.Selection.ResidentKey, o.PublicKey.Selection.UserVerification)
	}
	if want := base64.RawURLEncoding.EncodeToString(id[:]); o.PublicKey.User.ID != want {
		t.Fatal("user.id is not the principal's id bytes")
	}
	finish := regFinish(w, c, begin.Ceremony.ID, regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony), "Laptop")
	if finish.Refusal != nil || finish.Passkey == nil {
		t.Fatalf("finish: refusal %v, passkey given %v", finish.Refusal, finish.Passkey != nil)
	}
	if finish.Passkey.Label != "Laptop" || !finish.Passkey.CreatedAt.Equal(w.Clock.Now()) || finish.Passkey.LastUsedAt != nil {
		t.Fatalf("passkey = %q, created %v, last used %v", finish.Passkey.Label, finish.Passkey.CreatedAt, finish.Passkey.LastUsedAt)
	}
	if n := regPasskeys(w, id); n != 1 {
		t.Fatalf("auth_passkeys rows = %d, want 1", n)
	}
	var label string
	var created time.Time
	var unused bool
	if err := w.D.Row(t, `SELECT label, created_at, last_used_at IS NULL FROM auth_passkeys WHERE principal_id = $1`, id).Scan(&label, &created, &unused); err != nil {
		t.Fatal(err)
	}
	if label != "Laptop" || !created.Equal(w.Clock.Now()) || !unused {
		t.Fatalf("row = label %q, created %v, last_used_at null %v", label, created, unused)
	}
	if all, spent := regCeremonies(w, id); all != 1 || spent != 1 {
		t.Fatalf("ceremonies = %d, spent %d; want 1 spent", all, spent)
	}
}

func TestAddingAPasskeyRecordsPasskeyAdded(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	if n := regAdded(w, id); n != 0 {
		t.Fatalf("passkey_added events after begin = %d, want 0", n)
	}
	finish := regFinish(w, c, begin.Ceremony.ID, regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony), "Laptop")
	if finish.Refusal != nil {
		t.Fatalf("finish refused: %v", finish.Refusal)
	}
	if n := regAdded(w, id); n != 1 {
		t.Fatalf("passkey_added events = %d, want 1", n)
	}
	var source, userAgent string
	var sessionID uuid.UUID
	if err := w.D.Row(t, `SELECT source, session_id, user_agent FROM auth_events WHERE principal_id = $1 AND result = 'passkey_added'`, id).Scan(&source, &sessionID, &userAgent); err != nil {
		t.Fatal(err)
	}
	if source != authkit.SourcePasskeyRegister || sessionID != c.SessionID || userAgent != "UA-1" {
		t.Fatalf("event = source %q, session %v, user agent %q", source, sessionID, userAgent)
	}
}

func TestACeremonyFinishesOnce(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	first := regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony)
	second := regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony)
	if r := regFinish(w, c, begin.Ceremony.ID, first, "Laptop"); r.Refusal != nil {
		t.Fatalf("first finish refused: %v", r.Refusal)
	}
	regRefused(t, regFinish(w, c, begin.Ceremony.ID, second, "Phone"), authkit.ErrPasskeyInvalid)
	if n := regPasskeys(w, id); n != 1 {
		t.Fatalf("auth_passkeys rows = %d, want 1", n)
	}
}

func TestAResponseWithoutUserVerificationIsRefused(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	a := regAuthn(kittest.StaffOrigin)
	a.NoUV = true
	regRefused(t, regFinish(w, c, begin.Ceremony.ID, regCreate(t, a, begin.Ceremony), "Laptop"), authkit.ErrPasskeyInvalid)
	if n := regPasskeys(w, id); n != 0 {
		t.Fatalf("auth_passkeys rows = %d, want 0", n)
	}
	if n := regAdded(w, id); n != 0 {
		t.Fatalf("passkey_added events = %d, want 0", n)
	}
	if all, spent := regCeremonies(w, id); all != 1 || spent != 1 {
		t.Fatalf("ceremonies = %d, spent %d; want 1 spent", all, spent)
	}
}

func TestAFailedFinishBurnsTheCeremony(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	regRefused(t, regFinish(w, c, begin.Ceremony.ID, []byte("{"), "Laptop"), authkit.ErrPasskeyInvalid)
	if all, spent := regCeremonies(w, id); all != 1 || spent != 1 {
		t.Fatalf("ceremonies = %d, spent %d; want 1 spent", all, spent)
	}
	regRefused(t, regFinish(w, c, begin.Ceremony.ID, regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony), "Laptop"), authkit.ErrPasskeyInvalid)
	if n := regPasskeys(w, id); n != 0 {
		t.Fatalf("auth_passkeys rows = %d, want 0", n)
	}
}

func TestAnotherSessionCannotFinishTheCeremony(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, s1 := regUser(w, "ada@example.invalid")
	s2 := w.SignIn("ada@example.invalid", "the right password")
	c1, c2 := w.Claims(s1), w.Claims(s2)
	begin := regBegin(w, c1)
	resp := regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony)
	regRefused(t, regFinish(w, c2, begin.Ceremony.ID, resp, "Laptop"), authkit.ErrPasskeyInvalid)
	if n := regPasskeys(w, id); n != 0 {
		t.Fatalf("auth_passkeys rows = %d, want 0", n)
	}
	if all, spent := regCeremonies(w, id); all != 1 || spent != 0 {
		t.Fatalf("ceremonies = %d, spent %d; want 1 unspent", all, spent)
	}
	if r := regFinish(w, c1, begin.Ceremony.ID, resp, "Laptop"); r.Refusal != nil {
		t.Fatalf("finish from the begin session refused: %v", r.Refusal)
	}
}

func TestAnotherPrincipalCannotFinishTheCeremony(t *testing.T) {
	w := regWorld(t, regOrigins)
	ada, ares := regUser(w, "ada@example.invalid")
	c := w.Claims(ares)
	begin := regBegin(w, c)
	resp := regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony)
	bob, bres := regUser(w, "bob@example.invalid")
	regRefused(t, regFinish(w, w.Claims(bres), begin.Ceremony.ID, resp, "Laptop"), authkit.ErrPasskeyInvalid)
	if n := regPasskeys(w, bob); n != 0 {
		t.Fatalf("Bob's auth_passkeys rows = %d, want 0", n)
	}
	if n := regPasskeys(w, ada); n != 0 {
		t.Fatalf("Ada's auth_passkeys rows = %d, want 0", n)
	}
	if all, spent := regCeremonies(w, ada); all != 1 || spent != 0 {
		t.Fatalf("ceremonies = %d, spent %d; want 1 unspent", all, spent)
	}
}

func TestACeremonyOfAnotherAudienceIsRefused(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	resp := regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony)
	w.D.Exec(t, `UPDATE auth_passkey_ceremonies SET audience = 'client' WHERE principal_id = $1`, id)
	regRefused(t, regFinish(w, c, begin.Ceremony.ID, resp, "Laptop"), authkit.ErrPasskeyInvalid)
	if all, spent := regCeremonies(w, id); all != 1 || spent != 0 {
		t.Fatalf("ceremonies = %d, spent %d; want 1 unspent", all, spent)
	}
	if n := regPasskeys(w, id); n != 0 {
		t.Fatalf("auth_passkeys rows = %d, want 0", n)
	}
}

func TestALoginCeremonyCannotFinishARegistration(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	resp := regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony)
	w.D.Exec(t, `UPDATE auth_passkey_ceremonies SET kind = 'login', principal_id = NULL, session_id = NULL WHERE principal_id = $1`, id)
	regRefused(t, regFinish(w, c, begin.Ceremony.ID, resp, "Laptop"), authkit.ErrPasskeyInvalid)
	if n := regPasskeys(w, id); n != 0 {
		t.Fatalf("auth_passkeys rows = %d, want 0", n)
	}
	if n := w.Count(`SELECT count(*) FROM auth_passkey_ceremonies WHERE used_at IS NOT NULL`); n != 0 {
		t.Fatalf("spent ceremonies = %d, want 0", n)
	}
}

func TestAnotherAudiencesOriginIsRefused(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	resp := regCreate(t, regAuthn(kittest.ClientOrigin), begin.Ceremony)
	regRefused(t, regFinish(w, c, begin.Ceremony.ID, resp, "Laptop"), authkit.ErrPasskeyInvalid)
	if n := regPasskeys(w, id); n != 0 {
		t.Fatalf("auth_passkeys rows = %d, want 0", n)
	}
	if n := regAdded(w, id); n != 0 {
		t.Fatalf("passkey_added events = %d, want 0", n)
	}
}

func TestAnAudienceWithoutOriginsIsRefused(t *testing.T) {
	w := regWorld(t, map[authkit.Audience][]string{"client": {kittest.ClientOrigin}})
	id, res := regUser(w, "ada@example.invalid")
	regRefused(t, regBegin(w, w.Claims(res)), authkit.ErrPasskeyInvalid)
	if all, _ := regCeremonies(w, id); all != 0 {
		t.Fatalf("ceremonies = %d, want 0", all)
	}
}

func TestPasskeyRegistrationNeedsPasskeysOn(t *testing.T) {
	w := newWorld(t)
	_, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	var begin, finish authkit.Result
	var beginErr, finishErr error
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		begin, beginErr = w.Svc.BeginPasskeyRegistration(w.Ctx, q, c, authkit.Meta{})
		finish, finishErr = w.Svc.FinishPasskeyRegistration(w.Ctx, q, c, "x", []byte("{}"), "", authkit.Meta{})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(beginErr, authkit.ErrPasskeysOff) || !reflect.ValueOf(begin).IsZero() {
		t.Fatalf("begin = %v, %+v; want ErrPasskeysOff and a zero Result", beginErr, begin)
	}
	if !errors.Is(finishErr, authkit.ErrPasskeysOff) || !reflect.ValueOf(finish).IsZero() {
		t.Fatalf("finish = %v, %+v; want ErrPasskeysOff and a zero Result", finishErr, finish)
	}
}

func TestASyncedPasskeyIsAccepted(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	a := regAuthn(kittest.StaffOrigin)
	a.BackupEligible = true
	if r := regFinish(w, c, begin.Ceremony.ID, regCreate(t, a, begin.Ceremony), "Laptop"); r.Refusal != nil {
		t.Fatalf("finish refused: %v", r.Refusal)
	}
	if n := regPasskeys(w, id); n != 1 {
		t.Fatalf("auth_passkeys rows = %d, want 1", n)
	}
}

func regLabel(w *world, id uuid.UUID) string {
	w.T.Helper()
	var label string
	if err := w.D.Row(w.T, `SELECT label FROM auth_passkeys WHERE principal_id = $1`, id).Scan(&label); err != nil {
		w.T.Fatal(err)
	}
	return label
}

func TestAnEmptyLabelBecomesTheDate(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	finish := regFinish(w, c, begin.Ceremony.ID, regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony), "   ")
	if finish.Refusal != nil || finish.Passkey == nil {
		t.Fatalf("finish: refusal %v, passkey given %v", finish.Refusal, finish.Passkey != nil)
	}
	if want := "Passkey 2040-01-01"; regLabel(w, id) != want || finish.Passkey.Label != want {
		t.Fatalf("label = %q, want %q", regLabel(w, id), want)
	}
}

func TestALabelWithAControlCharacterIsRefused(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	finish := regFinish(w, c, begin.Ceremony.ID, regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony), "Lap\ttop")
	regRefused(t, finish, authkit.ErrPasskeyLabel)
	if n := regPasskeys(w, id); n != 0 {
		t.Fatalf("auth_passkeys rows = %d, want 0", n)
	}
	if n := regAdded(w, id); n != 0 {
		t.Fatalf("passkey_added events = %d, want 0", n)
	}
}

func TestA65RuneLabelIsRefused(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	finish := regFinish(w, c, begin.Ceremony.ID, regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony), strings.Repeat("é", 65))
	regRefused(t, finish, authkit.ErrPasskeyLabel)
	if n := regPasskeys(w, id); n != 0 {
		t.Fatalf("auth_passkeys rows = %d, want 0", n)
	}
}

func TestALabelIsCountedInRunes(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	label := strings.Repeat("é", 64)
	finish := regFinish(w, c, begin.Ceremony.ID, regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony), label)
	if finish.Refusal != nil || finish.Passkey == nil {
		t.Fatalf("finish: refusal %v, passkey given %v", finish.Refusal, finish.Passkey != nil)
	}
	if got := regLabel(w, id); got != label {
		t.Fatalf("stored label is %d bytes, want the 128-byte label of 64 runes", len(got))
	}
}

func TestARefusedLabelKeepsTheCeremony(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	resp := regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony)
	regRefused(t, regFinish(w, c, begin.Ceremony.ID, resp, "a\nb"), authkit.ErrPasskeyLabel)
	if all, spent := regCeremonies(w, id); all != 1 || spent != 0 {
		t.Fatalf("ceremonies = %d, spent %d; want 1 unspent", all, spent)
	}
	retry := regFinish(w, c, begin.Ceremony.ID, resp, "Laptop")
	if retry.Refusal != nil || retry.Passkey == nil {
		t.Fatalf("retry: refusal %v, passkey given %v", retry.Refusal, retry.Passkey != nil)
	}
	if n := regPasskeys(w, id); n != 1 {
		t.Fatalf("auth_passkeys rows = %d, want 1", n)
	}
}

func TestBeginNeedsAPassword(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	w.D.Exec(t, `DELETE FROM auth_credentials WHERE principal_id = $1`, id)
	regRefused(t, regBegin(w, w.Claims(res)), authkit.ErrNoPassword)
	if all, _ := regCeremonies(w, id); all != 0 {
		t.Fatalf("ceremonies = %d, want 0", all)
	}
}

func TestFinishNeedsAPassword(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	resp := regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony)
	w.D.Exec(t, `DELETE FROM auth_credentials WHERE principal_id = $1`, id)
	regRefused(t, regFinish(w, c, begin.Ceremony.ID, resp, "Laptop"), authkit.ErrNoPassword)
	if n := regPasskeys(w, id); n != 0 {
		t.Fatalf("auth_passkeys rows = %d, want 0", n)
	}
	if all, spent := regCeremonies(w, id); all != 1 || spent != 0 {
		t.Fatalf("ceremonies = %d, spent %d; want 1 unspent", all, spent)
	}
}

func TestBeginAtTheEdgeOfTheReauthWindow(t *testing.T) {
	w := regWorld(t, regOrigins)
	_, res := regUser(w, "ada@example.invalid")
	w.Clock.Advance(5 * time.Minute)
	if begin := regBegin(w, w.Claims(res)); begin.Refusal != nil || begin.Ceremony == nil {
		t.Fatalf("begin: refusal %v, ceremony given %v", begin.Refusal, begin.Ceremony != nil)
	}
}

func TestBeginAfterTheReauthWindow(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	w.Clock.Advance(5*time.Minute + time.Second)
	regRefused(t, regBegin(w, w.Claims(res)), authkit.ErrReauthRequired)
	if all, _ := regCeremonies(w, id); all != 0 {
		t.Fatalf("ceremonies = %d, want 0", all)
	}
}

func TestFinishAfterTheReauthWindow(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	w.Clock.Advance(4 * time.Minute)
	begin := regBegin(w, c)
	resp := regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony)
	w.Clock.Advance(time.Minute + time.Second)
	regRefused(t, regFinish(w, c, begin.Ceremony.ID, resp, "Laptop"), authkit.ErrReauthRequired)
	if n := regPasskeys(w, id); n != 0 {
		t.Fatalf("auth_passkeys rows = %d, want 0", n)
	}
	if all, spent := regCeremonies(w, id); all != 1 || spent != 0 {
		t.Fatalf("ceremonies = %d, spent %d; want 1 unspent", all, spent)
	}
}

func TestChangingThePasswordRestartsTheReauthWindow(t *testing.T) {
	w := regWorld(t, regOrigins)
	_, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	w.Clock.Advance(6 * time.Minute)
	changed := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.ChangePassword(w.Ctx, q, c, "the right password", "another password", authkit.Meta{})
	})
	if changed.Refusal != nil || changed.Session == nil || changed.Session.ID != c.SessionID {
		t.Fatalf("change password: refusal %v, the session was kept %v", changed.Refusal, changed.Session != nil && changed.Session.ID == c.SessionID)
	}
	if begin := regBegin(w, c); begin.Refusal != nil || begin.Ceremony == nil {
		t.Fatalf("begin: refusal %v, ceremony given %v", begin.Refusal, begin.Ceremony != nil)
	}
}

func TestASwitchedSessionKeepsItsSignInTime(t *testing.T) {
	w := regWorld(t, regOrigins)
	_, res := regUser(w, "ada@example.invalid")
	w.Clock.Advance(6 * time.Minute)
	switched := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.OpenSessionFrom(w.Ctx, q, res.Session.ID, res.Principal, "staff", authkit.Meta{})
	})
	if switched.Refusal != nil || switched.Session == nil {
		t.Fatalf("switch: refusal %v, session given %v", switched.Refusal, switched.Session != nil)
	}
	regRefused(t, regBegin(w, w.Claims(switched)), authkit.ErrReauthRequired)
}

func TestBeginOnAnEndedSession(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Logout(w.Ctx, q, c, authkit.Meta{})
	})
	regRefused(t, regBegin(w, c), authkit.ErrReauthRequired)
	if all, _ := regCeremonies(w, id); all != 0 {
		t.Fatalf("ceremonies = %d, want 0", all)
	}
}

func regSeed(w *world, id uuid.UUID, n int) {
	w.T.Helper()
	for i := 0; i < n; i++ {
		cred := make([]byte, 16)
		if _, err := rand.Read(cred); err != nil {
			w.T.Fatal(err)
		}
		w.D.Exec(w.T, `INSERT INTO auth_passkeys (id, principal_id, credential_id, label, data, created_at) VALUES ($1, $2, $3, 'seed', '{}', $4)`,
			uuid.New(), id, cred, w.Clock.Now())
	}
}

func TestBeginAtTheCap(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	regSeed(w, id, 10)
	regRefused(t, regBegin(w, w.Claims(res)), authkit.ErrPasskeyLimit)
	if all, _ := regCeremonies(w, id); all != 0 {
		t.Fatalf("ceremonies = %d, want 0", all)
	}
}

func TestFinishAtTheCap(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	regSeed(w, id, 9)
	begin := regBegin(w, c)
	resp := regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony)
	regSeed(w, id, 1)
	regRefused(t, regFinish(w, c, begin.Ceremony.ID, resp, "Laptop"), authkit.ErrPasskeyLimit)
	if n := regPasskeys(w, id); n != 10 {
		t.Fatalf("auth_passkeys rows = %d, want 10", n)
	}
	if all, spent := regCeremonies(w, id); all != 1 || spent != 0 {
		t.Fatalf("ceremonies = %d, spent %d; want 1 unspent", all, spent)
	}
}

func TestTwoFinishesCannotPassTheCap(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, first := regUser(w, "ada@example.invalid")
	second := w.SignIn("ada@example.invalid", "the right password")
	c1, c2 := w.Claims(first), w.Claims(second)
	regSeed(w, id, 9)
	b1 := regBegin(w, c1)
	r1 := regCreate(t, regAuthn(kittest.StaffOrigin), b1.Ceremony)
	b2 := regBegin(w, c2)
	r2 := regCreate(t, regAuthn(kittest.StaffOrigin), b2.Ceremony)

	holder, err := w.D.App.BeginTx(w.Ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	held, err := w.Svc.FinishPasskeyRegistration(w.Ctx, sqldb.Tx(holder), c1, b1.Ceremony.ID, r1, "Laptop", authkit.Meta{})
	if err != nil || held.Refusal != nil || held.Passkey == nil {
		t.Fatalf("first finish: error %v, refusal %v, passkey given %v", err, held.Refusal, held.Passkey != nil)
	}

	var got authkit.Result
	var gotErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		gotErr = w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
			r, err := w.Svc.FinishPasskeyRegistration(w.Ctx, q, c2, b2.Ceremony.ID, r2, "Laptop", authkit.Meta{})
			got = r
			return err
		})
	}()
	w.D.WaitForLockWaiters(t, 1)
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	<-done
	if gotErr != nil {
		t.Fatalf("second finish: error %v", gotErr)
	}
	regRefused(t, got, authkit.ErrPasskeyLimit)
	if n := regPasskeys(w, id); n != 10 {
		t.Fatalf("auth_passkeys rows = %d, want 10", n)
	}
}

func regRawID(t *testing.T, resp []byte) []byte {
	t.Helper()
	var r struct {
		RawID string `json:"rawId"`
	}
	if err := json.Unmarshal(resp, &r); err != nil {
		t.Fatalf("parse the response: %v", err)
	}
	id, err := base64.RawURLEncoding.DecodeString(r.RawID)
	if err != nil {
		t.Fatalf("decode the response's id: %v", err)
	}
	return id
}

func TestBeginExcludesTheExistingPasskeys(t *testing.T) {
	w := regWorld(t, regOrigins)
	id, res := regUser(w, "ada@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	finish := regFinish(w, c, begin.Ceremony.ID, regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony), "Laptop")
	if finish.Refusal != nil || finish.Passkey == nil {
		t.Fatalf("finish: refusal %v, passkey given %v", finish.Refusal, finish.Passkey != nil)
	}
	var stored []byte
	if err := w.D.Row(t, `SELECT credential_id FROM auth_passkeys WHERE principal_id = $1`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	again := regBegin(w, c)
	if again.Refusal != nil || again.Ceremony == nil {
		t.Fatalf("second begin: refusal %v, ceremony given %v", again.Refusal, again.Ceremony != nil)
	}
	ex := regParse(t, again.Ceremony).PublicKey.Exclude
	if len(ex) != 1 || ex[0].Type != "public-key" || ex[0].ID != base64.RawURLEncoding.EncodeToString(stored) {
		t.Fatalf("excludeCredentials has %d items, want the one stored credential of type public-key", len(ex))
	}
}

func TestAKnownCredentialIsRefused(t *testing.T) {
	w := regWorld(t, regOrigins)
	ada, res := regUser(w, "ada@example.invalid")
	bob, _ := regUser(w, "bob@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	resp := regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony)
	w.D.Exec(t, `INSERT INTO auth_passkeys (id, principal_id, credential_id, label, data, created_at) VALUES ($1, $2, $3, 'seed', '{}', $4)`,
		uuid.New(), bob, regRawID(t, resp), w.Clock.Now())
	regRefused(t, regFinish(w, c, begin.Ceremony.ID, resp, "Laptop"), authkit.ErrPasskeyExists)
	if n := regPasskeys(w, ada); n != 0 {
		t.Fatalf("auth_passkeys rows = %d, want 0", n)
	}
	if n := regAdded(w, ada); n != 0 {
		t.Fatalf("passkey_added events = %d, want 0", n)
	}
	if all, spent := regCeremonies(w, ada); all != 1 || spent != 1 {
		t.Fatalf("ceremonies = %d, spent %d; want 1 spent", all, spent)
	}
}

func TestAKnownCredentialIsRefusedOnAPinnedConnection(t *testing.T) {
	w := regWorld(t, regOrigins)
	ada, res := regUser(w, "ada@example.invalid")
	bob, _ := regUser(w, "bob@example.invalid")
	c := w.Claims(res)
	begin := regBegin(w, c)
	resp := regCreate(t, regAuthn(kittest.StaffOrigin), begin.Ceremony)
	w.D.Exec(t, `INSERT INTO auth_passkeys (id, principal_id, credential_id, label, data, created_at) VALUES ($1, $2, $3, 'seed', '{}', $4)`,
		uuid.New(), bob, regRawID(t, resp), w.Clock.Now())
	finish := w.InConn(w.Pinned(ada), func(q db.Querier) (authkit.Result, error) {
		return w.Svc.FinishPasskeyRegistration(w.Ctx, q, c, begin.Ceremony.ID, resp, "Laptop", authkit.Meta{})
	})
	regRefused(t, finish, authkit.ErrPasskeyExists)
	if n := regPasskeys(w, ada); n != 0 {
		t.Fatalf("auth_passkeys rows = %d, want 0", n)
	}
	if all, spent := regCeremonies(w, ada); all != 1 || spent != 1 {
		t.Fatalf("ceremonies = %d, spent %d; want 1 spent", all, spent)
	}
}
