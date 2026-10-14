package authkit

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// Ceremony is a passkey begin's answer: the id the finish sends back, the options for navigator.credentials, and when it expires.
type Ceremony struct {
	ID        string
	Options   json.RawMessage
	ExpiresAt time.Time
}

// Passkey is one of a principal's registered passkeys as the app lists it.
type Passkey struct {
	ID         uuid.UUID
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	BackedUp   bool
}

func relyingParties(r PasskeyRules) (map[Audience]*webauthn.WebAuthn, error) {
	if r.RPID == "" {
		return nil, nil
	}
	timeout := webauthn.TimeoutConfig{Enforce: true, Timeout: r.CeremonyTTL, TimeoutUVD: r.CeremonyTTL}
	rps := make(map[Audience]*webauthn.WebAuthn, len(r.Origins))
	for aud, origins := range r.Origins {
		if len(origins) == 0 {
			continue
		}
		rp, err := webauthn.New(&webauthn.Config{
			RPID:                  r.RPID,
			RPDisplayName:         r.RPName,
			RPOrigins:             slices.Clone(origins),
			AttestationPreference: protocol.PreferNoAttestation,
			AuthenticatorSelection: protocol.AuthenticatorSelection{
				ResidentKey:        protocol.ResidentKeyRequirementRequired,
				RequireResidentKey: protocol.ResidentKeyRequired(),
				UserVerification:   protocol.VerificationRequired,
			},
			Timeouts: webauthn.TimeoutsConfig{Login: timeout, Registration: timeout},
		})
		if err != nil {
			return nil, fmt.Errorf("authkit: passkeys for audience %q: %w", aud, err)
		}
		rps[aud] = rp
	}
	return rps, nil
}

func (s *Service) relyingParty(aud Audience) (*webauthn.WebAuthn, bool, error) {
	if s.cfg.Passkeys.RPID == "" {
		return nil, false, ErrPasskeysOff
	}
	rp, ok := s.rps[aud]
	if !ok {
		return nil, false, nil
	}
	return rp, true, nil
}

type passkeyUser struct {
	p     Principal
	creds []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte {
	id := u.p.ID
	return id[:]
}

func (u passkeyUser) WebAuthnName() string { return u.p.Login }

func (u passkeyUser) WebAuthnDisplayName() string { return u.p.Login }

func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }
