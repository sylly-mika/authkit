package authkittest_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/authkittest"
)

const (
	rpID        = "auth.test"
	staffOrigin = "https://auth.test"
	otherOrigin = "https://portal.auth.test"
)

type rpUser struct {
	id    []byte
	creds []webauthn.Credential
}

func (u *rpUser) WebAuthnID() []byte                         { return u.id }
func (u *rpUser) WebAuthnName() string                       { return "user" }
func (u *rpUser) WebAuthnDisplayName() string                { return "User" }
func (u *rpUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func newUser() *rpUser {
	id := uuid.New()
	return &rpUser{id: id[:]}
}

func newRP(t *testing.T, uv protocol.UserVerificationRequirement) *webauthn.WebAuthn {
	t.Helper()
	rp, err := webauthn.New(&webauthn.Config{
		RPID:                  rpID,
		RPDisplayName:         "authkit",
		RPOrigins:             []string{staffOrigin},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   uv,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute, TimeoutUVD: 2 * time.Minute},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute, TimeoutUVD: 2 * time.Minute},
		},
	})
	if err != nil {
		t.Fatalf("webauthn.New: <redacted>")
	}
	return rp
}

func register(t *testing.T, rp *webauthn.WebAuthn, a *authkittest.Authenticator, u *rpUser) (*webauthn.Credential, error) {
	t.Helper()
	_, cred, err := registerResponse(t, rp, a, u)
	return cred, err
}

func registerResponse(t *testing.T, rp *webauthn.WebAuthn, a *authkittest.Authenticator, u *rpUser) ([]byte, *webauthn.Credential, error) {
	t.Helper()
	creation, session, err := rp.BeginRegistration(u)
	if err != nil {
		t.Fatalf("BeginRegistration: <redacted>")
	}
	opts, err := json.Marshal(creation)
	if err != nil {
		t.Fatalf("marshal creation options: <redacted>")
	}
	resp, err := a.Create(opts)
	if err != nil {
		t.Fatalf("Create: <redacted>")
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(resp)
	if err != nil {
		return nil, nil, err
	}
	cred, err := rp.CreateCredential(u, *session, parsed)
	return resp, cred, err
}

func signIn(t *testing.T, rp *webauthn.WebAuthn, a *authkittest.Authenticator, h webauthn.DiscoverableUserHandler) (webauthn.User, *webauthn.Credential, error) {
	t.Helper()
	assertion, session, err := rp.BeginDiscoverableLogin()
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: <redacted>")
	}
	opts, err := json.Marshal(assertion)
	if err != nil {
		t.Fatalf("marshal assertion options: <redacted>")
	}
	resp, err := a.Get(opts)
	if err != nil {
		t.Fatalf("Get: <redacted>")
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(resp)
	if err != nil {
		return nil, nil, err
	}
	return rp.ValidatePasskeyLogin(h, *session, parsed)
}

func holder(u *rpUser, seen *[2][]byte) webauthn.DiscoverableUserHandler {
	return func(rawID, userHandle []byte) (webauthn.User, error) {
		if seen != nil {
			seen[0] = rawID
			seen[1] = userHandle
		}
		return u, nil
	}
}

func refusedFor(t *testing.T, err error, phrase string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted, want a refusal naming %q", phrase)
	}
	var pe *protocol.Error
	if !errors.As(err, &pe) {
		t.Fatalf("refusal is not a protocol error: <redacted>")
	}
	if !strings.Contains(pe.Details+" "+pe.DevInfo, phrase) {
		t.Fatalf("refusal does not name %q: <redacted>", phrase)
	}
}

func TestAuthenticatorPassesRegistrationAndPasskeyLogin(t *testing.T) {
	a := authkittest.NewAuthenticator(rpID, staffOrigin)
	u := newUser()
	rp := newRP(t, protocol.VerificationRequired)

	resp, cred, err := registerResponse(t, rp, a, u)
	if err != nil {
		t.Fatalf("registration refused: <redacted>")
	}
	var created struct {
		RawID string `json:"rawId"`
	}
	if err := json.Unmarshal(resp, &created); err != nil {
		t.Fatalf("decode Create response: <redacted>")
	}
	rawID, err := base64.RawURLEncoding.DecodeString(created.RawID)
	if err != nil {
		t.Fatalf("decode rawId: <redacted>")
	}
	if !bytes.Equal(cred.ID, rawID) {
		t.Fatalf("credential id is not the response rawId")
	}
	if cred.AttestationFormat != "none" {
		t.Fatalf("attestation format %q, want none", cred.AttestationFormat)
	}
	if !cred.Flags.UserPresent || !cred.Flags.UserVerified {
		t.Fatalf("registration flags UP=%v UV=%v, want both set", cred.Flags.UserPresent, cred.Flags.UserVerified)
	}
	if cred.Flags.BackupEligible {
		t.Fatalf("backup eligible set on a device-bound passkey")
	}
	if len(cred.PublicKey) == 0 {
		t.Fatalf("registered credential has no public key")
	}

	u.creds = []webauthn.Credential{*cred}
	var seen [2][]byte
	user, got, err := signIn(t, rp, a, holder(u, &seen))
	if err != nil {
		t.Fatalf("login refused: <redacted>")
	}
	if !bytes.Equal(user.WebAuthnID(), u.id) {
		t.Fatalf("login returned another user")
	}
	if !bytes.Equal(seen[0], cred.ID) {
		t.Fatalf("handler was not called with the asserted credential id")
	}
	if !bytes.Equal(seen[1], u.id) {
		t.Fatalf("handler was not called with the user handle")
	}
	if got.Authenticator.CloneWarning {
		t.Fatalf("clone warning on a first login")
	}
}

func TestGetSignsWithTheNewestCredential(t *testing.T) {
	a := authkittest.NewAuthenticator(rpID, staffOrigin)
	u := newUser()
	rp := newRP(t, protocol.VerificationRequired)

	cred1, err := register(t, rp, a, u)
	if err != nil {
		t.Fatalf("first registration refused: <redacted>")
	}
	cred2, err := register(t, rp, a, u)
	if err != nil {
		t.Fatalf("second registration refused: <redacted>")
	}
	if bytes.Equal(cred1.ID, cred2.ID) {
		t.Fatalf("two registrations returned one credential id")
	}
	u.creds = []webauthn.Credential{*cred1, *cred2}

	var seen [2][]byte
	_, got, err := signIn(t, rp, a, holder(u, &seen))
	if err != nil {
		t.Fatalf("login refused: <redacted>")
	}
	if !bytes.Equal(seen[0], cred2.ID) {
		t.Fatalf("login asserted an older credential")
	}
	if !bytes.Equal(got.ID, cred2.ID) {
		t.Fatalf("returned credential is not the newest one")
	}
}
