package passkey_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/passkey"
)

type world struct{ *kittest.World }

func newWorld(t *testing.T, tweaks ...func(*kittest.Rules)) *world {
	t.Helper()
	return &world{kittest.New(t, tweaks...)}
}

func TestPasskeyOwnerHandlerRefusesAnotherUsersHandle(t *testing.T) {
	w := newWorld(t, kittest.Passkeys)
	adaID := w.User("ada@example.invalid", "")
	bobID := w.User("bob@example.invalid", "")
	cred := w.SeedPasskey(adaID, authkittest.NewAuthenticator("localhost", kittest.StaffOrigin))
	lookup := func(userHandle []byte) (webauthn.User, error) {
		var user webauthn.User
		var err error
		if txErr := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
			user, err = passkey.PasskeyOwnerHandler(w.Ctx, q, cred.ID, userHandle)
			return nil
		}); txErr != nil {
			t.Fatalf("lookup: %v", txErr)
		}
		return user, err
	}
	if user, err := lookup(adaID[:]); err != nil || user == nil {
		t.Fatalf("the handler refused Ada's own handle: user %v, err %v", user, err)
	}
	user, err := lookup(bobID[:])
	if err == nil {
		t.Error("the handler accepted Bob's user handle for Ada's passkey")
	}
	if user != nil {
		t.Errorf("the handler returned user %s with a refusal", user.WebAuthnName())
	}
}

func passkeyWorld(t *testing.T, ttl time.Duration) *world {
	return newWorld(t, func(c *kittest.Rules) {
		c.Passkeys = passkey.Rules{
			RPID:   "localhost",
			RPName: "ino-tasks",
			Origins: map[authkit.Audience][]string{
				"staff":  {"http://localhost:3000"},
				"client": {"http://localhost:3100"},
			},
			CeremonyTTL: ttl,
		}
	})
}

func optionsMap(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m["publicKey"].(map[string]any)
}

func TestPasskeyRelyingPartyPerAudience(t *testing.T) {
	w := passkeyWorld(t, 2*time.Minute)
	staff, ok, err := passkey.PasskeyRP(w.Svc.Passkeys, "staff")
	if !ok || err != nil {
		t.Fatalf("staff relying party: ok=%v err=%v", ok, err)
	}
	if staff.Config.RPID != "localhost" {
		t.Fatalf("staff RPID %q, want localhost", staff.Config.RPID)
	}
	if got := staff.Config.RPOrigins; len(got) != 1 || got[0] != "http://localhost:3000" {
		t.Fatalf("staff RPOrigins %v, want [http://localhost:3000]", got)
	}
	if _, _, err := staff.BeginDiscoverableLogin(webauthn.WithLoginOrigin("http://localhost:3100")); err == nil {
		t.Error("the staff relying party began a login from the client origin")
	}
	if _, _, err := staff.BeginDiscoverableLogin(webauthn.WithLoginOrigin("http://localhost:3000")); err != nil {
		t.Errorf("the staff relying party refused its own origin: %v", err)
	}

	client, ok, err := passkey.PasskeyRP(w.Svc.Passkeys, "client")
	if !ok || err != nil {
		t.Fatalf("client relying party: ok=%v err=%v", ok, err)
	}
	if got := client.Config.RPOrigins; len(got) != 1 || got[0] != "http://localhost:3100" {
		t.Fatalf("client RPOrigins %v, want [http://localhost:3100]", got)
	}
	if _, _, err := client.BeginDiscoverableLogin(webauthn.WithLoginOrigin("http://localhost:3000")); err == nil {
		t.Error("the client relying party began a login from the staff origin")
	}

	rp, ok, err := passkey.PasskeyRP(w.Svc.Passkeys, "agent")
	if rp != nil || ok || err != nil {
		t.Fatalf("an audience with no relying party: rp=%v ok=%v err=%v", rp != nil, ok, err)
	}
}

var ada = authkit.Principal{ID: uuid.MustParse("6f1c2a52-8a43-4c1e-9d6f-0b7e2f6c9a10"), Login: "ada@example.invalid"}

func TestPasskeyRegistrationOptions(t *testing.T) {
	w := passkeyWorld(t, 2*time.Minute)
	rp, _, err := passkey.PasskeyRP(w.Svc.Passkeys, "staff")
	if err != nil {
		t.Fatal(err)
	}
	creation, sess, err := rp.BeginRegistration(passkey.NewPasskeyUser(ada, nil))
	if err != nil {
		t.Fatal(err)
	}
	pk := optionsMap(t, creation)
	rpOpt := pk["rp"].(map[string]any)
	user := pk["user"].(map[string]any)
	sel := pk["authenticatorSelection"].(map[string]any)
	if rpOpt["id"] != "localhost" || rpOpt["name"] != "ino-tasks" {
		t.Errorf("rp is %v, want localhost and ino-tasks", rpOpt)
	}
	if user["id"] != base64.RawURLEncoding.EncodeToString(ada.ID[:]) || user["name"] != "ada@example.invalid" {
		t.Errorf("user is %v", user)
	}
	if sel["residentKey"] != "required" || sel["requireResidentKey"] != true || sel["userVerification"] != "required" {
		t.Errorf("authenticatorSelection is %v, want required resident key and user verification", sel)
	}
	if pk["attestation"] != "none" {
		t.Errorf("attestation %v, want none", pk["attestation"])
	}
	if pk["timeout"] != float64(120000) {
		t.Errorf("timeout %v, want 120000", pk["timeout"])
	}
	if sess.UserVerification != protocol.VerificationRequired {
		t.Errorf("session UserVerification %q, want required", sess.UserVerification)
	}
	if !bytes.Equal(sess.UserID, ada.ID[:]) {
		t.Error("session UserID is not the principal's id")
	}
	if sess.Expires.IsZero() {
		t.Error("session has no expiry")
	}
}

func TestPasskeyLoginOptionsUseTheCeremonyTTL(t *testing.T) {
	w := passkeyWorld(t, 90*time.Second)
	rp, _, err := passkey.PasskeyRP(w.Svc.Passkeys, "staff")
	if err != nil {
		t.Fatal(err)
	}
	assertion, sess, err := rp.BeginDiscoverableLogin()
	if err != nil {
		t.Fatal(err)
	}
	pk := optionsMap(t, assertion)
	if pk["rpId"] != "localhost" || pk["userVerification"] != "required" {
		t.Errorf("login options are %v, want localhost and required user verification", pk)
	}
	if pk["timeout"] != float64(90000) {
		t.Errorf("login timeout %v, want 90000", pk["timeout"])
	}
	if _, ok := pk["allowCredentials"]; ok {
		t.Error("a discoverable login lists allowCredentials")
	}
	now := time.Now()
	if sess.Expires.Before(now.Add(85*time.Second)) || sess.Expires.After(now.Add(95*time.Second)) {
		t.Errorf("login expiry %v is not about 90s from now", sess.Expires)
	}

	creation, _, err := rp.BeginRegistration(passkey.NewPasskeyUser(ada, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := optionsMap(t, creation)["timeout"]; got != float64(90000) {
		t.Errorf("registration timeout %v, want 90000", got)
	}
}

func TestPasskeysOffWithoutRPID(t *testing.T) {
	w := newWorld(t)
	rp, ok, err := passkey.PasskeyRP(w.Svc.Passkeys, "staff")
	if rp != nil || ok || !errors.Is(err, authkit.ErrPasskeysOff) {
		t.Fatalf("passkeys off: rp=%v ok=%v err=%v, want ErrPasskeysOff", rp != nil, ok, err)
	}
}

func TestPasskeyUserCarriesTheHandleAndCredentials(t *testing.T) {
	w := passkeyWorld(t, 2*time.Minute)
	rp, _, err := passkey.PasskeyRP(w.Svc.Passkeys, "staff")
	if err != nil {
		t.Fatal(err)
	}
	assertion, sess, err := rp.BeginLogin(passkey.NewPasskeyUser(ada, []webauthn.Credential{{ID: []byte{1, 2, 3, 4}}}))
	if err != nil {
		t.Fatal(err)
	}
	pk := optionsMap(t, assertion)
	allow, ok := pk["allowCredentials"].([]any)
	if !ok || len(allow) != 1 || allow[0].(map[string]any)["id"] != "AQIDBA" {
		t.Errorf("allowCredentials %v, want one credential AQIDBA", pk["allowCredentials"])
	}
	if len(sess.UserID) != 16 || !bytes.Equal(sess.UserID, ada.ID[:]) {
		t.Error("session UserID is not the 16-byte principal id")
	}
	if got := passkey.NewPasskeyUser(ada, nil).WebAuthnDisplayName(); got != "ada@example.invalid" {
		t.Errorf("display name %q, want the login", got)
	}
}
