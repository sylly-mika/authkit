package authkittest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// Authenticator is a software WebAuthn authenticator for tests: an ES256 key per credential and none attestation.
type Authenticator struct {
	// UserHandle, when not nil, replaces the user handle in every Get response; an empty non-nil value omits it.
	UserHandle []byte
	// NoUV clears the user-verified flag in every response.
	NoUV bool
	// Origin is the origin written into the client data of every response.
	Origin string
	// RPIDHash, when not nil, replaces the SHA-256 of the RP ID in the authenticator data.
	RPIDHash []byte
	// Counter is the sign count of the next response; it advances by one after each response unless it is zero.
	Counter uint32
	// BackupEligible sets the backup-eligible and backed-up flags in every response.
	BackupEligible bool
	// BadSignature makes every Get response carry a signature that does not verify.
	BadSignature bool

	mu    sync.Mutex
	rpID  string
	creds []softCredential
}

type softCredential struct {
	id         []byte
	key        *ecdsa.PrivateKey
	userHandle []byte
}

// NewAuthenticator returns an authenticator for the RP ID rpID that writes origin into its client data.
func NewAuthenticator(rpID, origin string) *Authenticator {
	return &Authenticator{Origin: origin, rpID: rpID}
}

// SetCounter sets the sign count of the next response.
func (a *Authenticator) SetCounter(n uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Counter = n
}

// Create answers creation options ({"publicKey":{…}}) with a new credential, as navigator.credentials.create would.
func (a *Authenticator) Create(optionsJSON []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	opts, err := parseOptions(optionsJSON)
	if err != nil {
		return nil, err
	}
	userID, err := decodeB64(opts.PublicKey.User.ID)
	if err != nil || len(userID) == 0 {
		return nil, errors.New("authkittest: options carry no user id")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("authkittest: generate key: %w", err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("authkittest: credential id: %w", err)
	}
	pub, err := key.PublicKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("authkittest: public key: %w", err)
	}
	raw := pub.Bytes()
	cose, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: 2, Algorithm: -7},
		Curve:         1,
		XCoord:        raw[1:33],
		YCoord:        raw[33:65],
	})
	if err != nil {
		return nil, fmt.Errorf("authkittest: cose key: %w", err)
	}

	authData := a.authData(true)
	authData = append(authData, make([]byte, 16)...)
	authData = append(authData, byte(len(id)>>8), byte(len(id)))
	authData = append(authData, id...)
	authData = append(authData, cose...)

	attestation, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		return nil, fmt.Errorf("authkittest: attestation: %w", err)
	}
	clientJSON, err := a.clientData("webauthn.create", opts.PublicKey.Challenge)
	if err != nil {
		return nil, err
	}

	a.creds = append(a.creds, softCredential{id: id, key: key, userHandle: userID})

	encoded := b64(id)
	return json.Marshal(createResponse{
		ID:                      encoded,
		RawID:                   encoded,
		Type:                    "public-key",
		AuthenticatorAttachment: "platform",
		Response: createResponseBody{
			ClientDataJSON:    b64(clientJSON),
			AttestationObject: b64(attestation),
			Transports:        []string{"internal"},
		},
	})
}

// Get answers request options ({"publicKey":{…}}) with an assertion from the newest credential, as navigator.credentials.get would.
func (a *Authenticator) Get(optionsJSON []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	opts, err := parseOptions(optionsJSON)
	if err != nil {
		return nil, err
	}
	if len(a.creds) == 0 {
		return nil, errors.New("authkittest: no credential")
	}
	cred := a.creds[len(a.creds)-1]

	clientJSON, err := a.clientData("webauthn.get", opts.PublicKey.Challenge)
	if err != nil {
		return nil, err
	}
	authData := a.authData(false)
	clientHash := sha256.Sum256(clientJSON)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, cred.key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("authkittest: sign: %w", err)
	}

	return json.Marshal(getResponse{
		ID:                      b64(cred.id),
		RawID:                   b64(cred.id),
		Type:                    "public-key",
		AuthenticatorAttachment: "platform",
		Response: getResponseBody{
			ClientDataJSON:    b64(clientJSON),
			AuthenticatorData: b64(authData),
			Signature:         b64(sig),
			UserHandle:        b64(cred.userHandle),
		},
	})
}

type options struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		User      struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"publicKey"`
}

func parseOptions(optionsJSON []byte) (options, error) {
	var opts options
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		return opts, fmt.Errorf("authkittest: bad options: %w", err)
	}
	if opts.PublicKey.Challenge == "" {
		return opts, errors.New("authkittest: options carry no challenge")
	}
	return opts, nil
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

func (a *Authenticator) clientData(typ, challenge string) ([]byte, error) {
	return json.Marshal(clientData{Type: typ, Challenge: challenge, Origin: a.Origin})
}

type createResponse struct {
	ID                      string             `json:"id"`
	RawID                   string             `json:"rawId"`
	Type                    string             `json:"type"`
	AuthenticatorAttachment string             `json:"authenticatorAttachment"`
	ClientExtensionResults  struct{}           `json:"clientExtensionResults"`
	Response                createResponseBody `json:"response"`
}

type createResponseBody struct {
	ClientDataJSON    string   `json:"clientDataJSON"`
	AttestationObject string   `json:"attestationObject"`
	Transports        []string `json:"transports"`
}

type getResponse struct {
	ID                      string          `json:"id"`
	RawID                   string          `json:"rawId"`
	Type                    string          `json:"type"`
	AuthenticatorAttachment string          `json:"authenticatorAttachment"`
	ClientExtensionResults  struct{}        `json:"clientExtensionResults"`
	Response                getResponseBody `json:"response"`
}

type getResponseBody struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

func (a *Authenticator) authData(create bool) []byte {
	b := append([]byte{}, a.rpHash()...)
	b = append(b, a.flags(create))
	return append(b, 0, 0, 0, 0)
}

func (a *Authenticator) flags(create bool) byte {
	f := byte(0x01 | 0x04)
	if create {
		f |= 0x40
	}
	return f
}

func (a *Authenticator) rpHash() []byte {
	sum := sha256.Sum256([]byte(a.rpID))
	return sum[:]
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
