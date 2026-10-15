package kittest

import (
	"encoding/json"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
)

// StaffOrigin and ClientOrigin are the origins the passkey tests register under.
const StaffOrigin, ClientOrigin = "http://localhost:3000", "http://localhost:3100"

// Passkeys turns passkey sign-in on for localhost, with the staff and client origins.
func Passkeys(c *authkit.Config) {
	c.Passkeys = authkit.PasskeyRules{RPID: "localhost", Origins: map[authkit.Audience][]string{"staff": {StaffOrigin}, "client": {ClientOrigin}}, CeremonyTTL: 2 * time.Minute}
}

type testUser struct {
	id    uuid.UUID
	creds []webauthn.Credential
}

func (u testUser) WebAuthnID() []byte { return u.id[:] }

func (u testUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (u testUser) WebAuthnName() string { return u.id.String() }

func (u testUser) WebAuthnDisplayName() string { return u.id.String() }

// SeedPasskey registers a passkey for id through the authenticator a, stores it
// as a passkey of id, and returns its credential.
func (w *World) SeedPasskey(id uuid.UUID, a *authkittest.Authenticator) webauthn.Credential {
	w.T.Helper()
	rp, err := webauthn.New(&webauthn.Config{RPID: "localhost", RPDisplayName: "authkit", RPOrigins: []string{StaffOrigin, ClientOrigin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}})
	if err != nil {
		w.T.Fatalf("seed a passkey: %v", err)
	}
	creation, session, err := rp.BeginRegistration(testUser{id: id})
	if err != nil {
		w.T.Fatalf("seed a passkey: %v", err)
	}
	opts, err := json.Marshal(creation)
	if err != nil {
		w.T.Fatalf("seed a passkey: %v", err)
	}
	resp, err := a.Create(opts)
	if err != nil {
		w.T.Fatalf("seed a passkey: %v", err)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(resp)
	if err != nil {
		w.T.Fatalf("seed a passkey: %v", err)
	}
	cred, err := rp.CreateCredential(testUser{id: id}, *session, parsed)
	if err != nil {
		w.T.Fatalf("seed a passkey: %v", err)
	}
	data, err := json.Marshal(cred)
	if err != nil {
		w.T.Fatalf("seed a passkey: %v", err)
	}
	w.D.Exec(w.T, "INSERT INTO auth_passkeys (id, principal_id, credential_id, label, data, created_at) VALUES ($1, $2, $3, 'Seed', $4, $5)", uuid.New(), id, cred.ID, string(data), w.Clock.Now())
	return *cred
}
