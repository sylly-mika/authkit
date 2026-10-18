package passkey_test

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/passkey"
)

const (
	appOrigin = "android:apk-key-hash:8O2fcxRaHkSeim_b9JB5RDswA9KUI1kIAodHnpUqorQ"
	otherApp  = "android:apk-key-hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fieldRPID = "api.example.invalid"
)

var appMeta = authkit.Meta{IP: "192.0.2.1", UserAgent: "authkit-test"}

func newPasskeyTestService(t *testing.T) *authkit.Service {
	t.Helper()
	svc, err := authkit.New(authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}, authkittest.NewPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func wantNewRefused(t *testing.T, r passkey.Rules, want string) {
	t.Helper()
	if _, err := passkey.New(newPasskeyTestService(t), r); err == nil || err.Error() != want {
		t.Errorf("New = %v, want %q", err, want)
	}
}

func appRules(c *kittest.Rules) {
	c.Passkeys = passkey.Rules{RPID: "localhost", RPIDs: map[authkit.Audience]string{"field": fieldRPID},
		Origins:     map[authkit.Audience][]string{"staff": {kittest.StaffOrigin}, "field": {appOrigin}},
		CeremonyTTL: 2 * time.Minute}
}

func (w *world) enrol(aud authkit.Audience, login string, a *authkittest.Authenticator) uuid.UUID {
	w.T.Helper()
	id := w.User(login, "the right password")
	c := w.Claims(w.Login(aud, login, "the right password"))
	begin := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Passkeys.BeginPasskeyRegistration(w.Ctx, q, c, appMeta)
	})
	if begin.Ceremony == nil {
		w.T.Fatalf("registration begin refused: %v", begin.Refusal)
	}
	resp, err := a.Create(begin.Ceremony.Options)
	if err != nil {
		w.T.Fatal(err)
	}
	fin := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Passkeys.FinishPasskeyRegistration(w.Ctx, q, c, begin.Ceremony.ID, resp, "phone", appMeta)
	})
	if fin.Passkey == nil {
		w.T.Fatalf("registration refused: %v", fin.Refusal)
	}
	return id
}

func (w *world) signInWith(aud authkit.Audience, a *authkittest.Authenticator) (string, authkit.Result) {
	w.T.Helper()
	begin := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Passkeys.BeginPasskeyLogin(w.Ctx, q, aud, appMeta)
	})
	if begin.Ceremony == nil {
		w.T.Fatalf("login begin refused: %v", begin.Refusal)
	}
	var opts struct {
		PublicKey struct {
			RPID string `json:"rpId"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(begin.Ceremony.Options, &opts); err != nil {
		w.T.Fatal(err)
	}
	resp, err := a.Get(begin.Ceremony.Options)
	if err != nil {
		w.T.Fatal(err)
	}
	return opts.PublicKey.RPID, w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Passkeys.FinishPasskeyLogin(w.Ctx, q, aud, begin.Ceremony.ID, resp, appMeta)
	})
}

func (w *world) signCount(id uuid.UUID) string {
	w.T.Helper()
	var n string
	if err := w.D.Row(w.T, `SELECT data->'authenticator'->>'signCount' FROM auth_passkeys WHERE principal_id = $1`, id).Scan(&n); err != nil {
		w.T.Fatal(err)
	}
	return n
}

func TestNewTwiceIsErrAttached(t *testing.T) {
	svc := newPasskeyTestService(t)
	first, err := passkey.New(svc, passkey.Rules{})
	if err != nil || first == nil {
		t.Fatalf("first New = %v, %v; want a module and nil", first, err)
	}
	second, err := passkey.New(svc, passkey.Rules{})
	if second != nil || !errors.Is(err, authkit.ErrAttached) {
		t.Fatalf("second New = %v, %v; want nil and ErrAttached", second, err)
	}
}

func TestARefusedNewLeavesThePasskeyNameFree(t *testing.T) {
	svc := newPasskeyTestService(t)
	bad := passkey.Rules{Origins: map[authkit.Audience][]string{"staff": {"https://tasks.example.invalid"}}}
	m, err := passkey.New(svc, bad)
	if m != nil {
		t.Fatalf("refused New returned a module")
	}
	if err == nil || err.Error() != "authkit: passkey.Rules.Origins needs passkey.Rules.RPID" {
		t.Fatalf("refused New error = %v; want the Origins refusal", err)
	}
	if _, err := passkey.New(svc, passkey.Rules{}); err != nil {
		t.Fatalf("New after a refusal = %v; want nil (the name stays free)", err)
	}
}

func TestAnAppOnlyAudienceBuilds(t *testing.T) {
	m, err := passkey.New(newPasskeyTestService(t), passkey.Rules{RPID: "localhost",
		Origins: map[authkit.Audience][]string{"field": {appOrigin}, "staff": {kittest.StaffOrigin, otherApp}}})
	if err != nil {
		t.Fatalf("New = %v; want an app-only audience to build", err)
	}
	field, ok, err := passkey.PasskeyRP(m, "field")
	if !ok || err != nil {
		t.Fatalf("field relying party: ok=%v err=%v", ok, err)
	}
	if field.Config.RPID != "localhost" || !slices.Equal(field.Config.RPOrigins, []string{"https://localhost"}) || !slices.Equal(field.Config.RPOpaqueOrigins, []string{appOrigin}) {
		t.Errorf("field: RPID %q, RPOrigins %v, RPOpaqueOrigins %v", field.Config.RPID, field.Config.RPOrigins, field.Config.RPOpaqueOrigins)
	}
	staff, ok, err := passkey.PasskeyRP(m, "staff")
	if !ok || err != nil {
		t.Fatalf("staff relying party: ok=%v err=%v", ok, err)
	}
	if !slices.Equal(staff.Config.RPOrigins, []string{kittest.StaffOrigin}) || !slices.Equal(staff.Config.RPOpaqueOrigins, []string{otherApp}) {
		t.Errorf("staff: RPOrigins %v, RPOpaqueOrigins %v", staff.Config.RPOrigins, staff.Config.RPOpaqueOrigins)
	}
}

func TestNewRefusesAMalformedAppOrigin(t *testing.T) {
	short := appOrigin[:len(appOrigin)-1]
	for _, o := range []string{
		short,
		appOrigin + "A",
		short + "=",
		short + "/",
		short + "+",
		short + "\n",
		short + "B",
		"android:apk-key-hash-sha256:" + strings.Repeat("A", 43),
		"android:apk-key-hash:",
		"android:" + strings.Repeat("A", 43),
	} {
		wantNewRefused(t, passkey.Rules{RPID: "localhost", Origins: map[authkit.Audience][]string{"field": {o}}},
			fmt.Sprintf("authkit: passkey.Rules.Origins[%q] %q is not an origin (scheme://host[:port])", "field", o))
	}
}

func TestNewRefusesAnAppOriginOnTwoAudiences(t *testing.T) {
	wantNewRefused(t, passkey.Rules{RPID: "localhost",
		Origins: map[authkit.Audience][]string{"field": {appOrigin}, "staff": {kittest.StaffOrigin, appOrigin}}},
		fmt.Sprintf("authkit: passkey.Rules.Origins %q is listed for both %q and %q", appOrigin, "field", "staff"))
}

func TestNewRefusesTheImpliedPageOnTwoAudiences(t *testing.T) {
	wantNewRefused(t, passkey.Rules{RPID: "localhost",
		Origins: map[authkit.Audience][]string{"field": {appOrigin}, "staff": {"https://localhost"}}},
		fmt.Sprintf("authkit: passkey.Rules.Origins %q is listed for both %q and %q", "https://localhost", "field", "staff"))
}

func TestNewRefusesBadRPIDs(t *testing.T) {
	wantNewRefused(t, passkey.Rules{RPIDs: map[authkit.Audience]string{"field": fieldRPID}},
		"authkit: passkey.Rules.RPIDs needs passkey.Rules.RPID")
	wantNewRefused(t, passkey.Rules{RPID: "localhost", RPIDs: map[authkit.Audience]string{"client": fieldRPID},
		Origins: map[authkit.Audience][]string{"staff": {kittest.StaffOrigin}}},
		`authkit: passkey.Rules.RPIDs["client"] has no passkey.Rules.Origins`)
	rpidRules := func(id string) passkey.Rules {
		return passkey.Rules{RPID: "localhost", RPIDs: map[authkit.Audience]string{"field": id},
			Origins: map[authkit.Audience][]string{"field": {appOrigin}}}
	}
	_, err := passkey.New(newPasskeyTestService(t), rpidRules("127.0.0.1"))
	if err == nil || !strings.HasPrefix(err.Error(), `authkit: passkey.Rules.RPIDs["field"] "127.0.0.1" is not a domain: `) {
		t.Errorf("New with an IP as RPIDs = %v, want the not-a-domain refusal", err)
	}
	wantNewRefused(t, rpidRules("Api.example.invalid"),
		`authkit: passkey.Rules.RPIDs["field"] "Api.example.invalid" must be lower case`)
}

func TestAnRPIDsAudienceChecksOriginsAgainstItsOwnRPID(t *testing.T) {
	rules := func(fieldOrigins ...string) passkey.Rules {
		return passkey.Rules{RPID: "localhost", RPIDs: map[authkit.Audience]string{"field": fieldRPID},
			Origins: map[authkit.Audience][]string{"staff": {kittest.StaffOrigin}, "field": fieldOrigins}}
	}
	wantNewRefused(t, rules("https://localhost"),
		`authkit: passkey.Rules.Origins["field"] "https://localhost" is outside RPID "api.example.invalid"`)
	wantNewRefused(t, rules("http://api.example.invalid"),
		`authkit: passkey.Rules.Origins["field"] "http://api.example.invalid" must use https`)

	m, err := passkey.New(newPasskeyTestService(t), rules("https://app.api.example.invalid", appOrigin))
	if err != nil {
		t.Fatalf("New = %v; want the field audience to build", err)
	}
	field, ok, err := passkey.PasskeyRP(m, "field")
	if !ok || err != nil {
		t.Fatalf("field relying party: ok=%v err=%v", ok, err)
	}
	if field.Config.RPID != fieldRPID || !slices.Equal(field.Config.RPOrigins, []string{"https://app.api.example.invalid"}) || !slices.Equal(field.Config.RPOpaqueOrigins, []string{appOrigin}) {
		t.Errorf("field: RPID %q, RPOrigins %v, RPOpaqueOrigins %v", field.Config.RPID, field.Config.RPOrigins, field.Config.RPOpaqueOrigins)
	}
	staff, ok, err := passkey.PasskeyRP(m, "staff")
	if !ok || err != nil {
		t.Fatalf("staff relying party: ok=%v err=%v", ok, err)
	}
	if staff.Config.RPID != "localhost" {
		t.Errorf("staff RPID %q, want localhost", staff.Config.RPID)
	}
}

func TestAnRPIDsAudienceSignsWithItsOwnRPID(t *testing.T) {
	w := newWorld(t, appRules)
	field := authkittest.NewAuthenticator(fieldRPID, appOrigin)
	field.SetCounter(1)
	workerID := w.enrol("field", "worker@example.invalid", field)
	staff := authkittest.NewAuthenticator("localhost", kittest.StaffOrigin)
	adaID := w.enrol("staff", "ada@example.invalid", staff)

	rpID, res := w.signInWith("field", field)
	if res.Refusal != nil || rpID != fieldRPID {
		t.Fatalf("field sign-in: rpId %q, refusal %v; want %q and no refusal", rpID, res.Refusal, fieldRPID)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", workerID); n != 2 {
		t.Errorf("worker sessions = %d, want 2", n)
	}
	rpID, res = w.signInWith("staff", staff)
	if res.Refusal != nil || rpID != "localhost" {
		t.Fatalf("staff sign-in: rpId %q, refusal %v; want localhost and no refusal", rpID, res.Refusal)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", adaID); n != 2 {
		t.Errorf("Ada sessions = %d, want 2", n)
	}

	sum := sha256.Sum256([]byte("localhost"))
	field.RPIDHash = sum[:]
	before := w.signCount(workerID)
	_, res = w.signInWith("field", field)
	if !errors.Is(res.Refusal, authkit.ErrPasskeyRejected) {
		t.Errorf("a field passkey signed with the localhost hash: refusal %v, want ErrPasskeyRejected", res.Refusal)
	}
	if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", workerID); n != 2 {
		t.Errorf("worker sessions after the refused sign-in = %d, want 2", n)
	}
	if after := w.signCount(workerID); after != before {
		t.Errorf("sign count after the refused sign-in = %s, want %s", after, before)
	}
}

func TestAnAppOriginSignsInOnlyOnItsAudience(t *testing.T) {
	w := newWorld(t, appRules)
	field := authkittest.NewAuthenticator(fieldRPID, appOrigin)
	workerID := w.enrol("field", "worker@example.invalid", field)
	staff := authkittest.NewAuthenticator("localhost", kittest.StaffOrigin)
	adaID := w.enrol("staff", "ada@example.invalid", staff)

	for _, c := range []struct {
		name   string
		aud    authkit.Audience
		a      *authkittest.Authenticator
		who    uuid.UUID
		origin string
	}{
		{"another app's origin on the field audience", "field", field, workerID, otherApp},
		{"a panel origin on the field audience", "field", field, workerID, kittest.StaffOrigin},
		{"the field app's origin on the staff audience", "staff", staff, adaID, appOrigin},
	} {
		c.a.Origin = c.origin
		_, res := w.signInWith(c.aud, c.a)
		if !errors.Is(res.Refusal, authkit.ErrPasskeyRejected) {
			t.Errorf("%s: refusal %v, want ErrPasskeyRejected", c.name, res.Refusal)
		}
		if n := w.Count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", c.who); n != 1 {
			t.Errorf("%s: sessions = %d, want 1 (the password one)", c.name, n)
		}
		if n := w.Count("SELECT count(*) FROM auth_passkeys WHERE principal_id = $1 AND last_used_at IS NOT NULL", c.who); n != 0 {
			t.Errorf("%s: passkeys used = %d, want 0", c.name, n)
		}
	}
}
