package passkey

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/sylly-mika/authkit"
)

// Module is passkey sign-in and passkey management on one Service.
type Module struct {
	core  *authkit.Core
	rules Rules
	rps   map[authkit.Audience]*webauthn.WebAuthn
}

// New attaches passkeys to svc. Zero fields of r take their defaults, and an empty RPID leaves passkeys off: every method then answers authkit.ErrPasskeysOff. New refuses rules that are out of range, and answers authkit.ErrAttached when svc already has passkeys.
func New(svc *authkit.Service, r Rules) (*Module, error) {
	inherit := r.Reauth == 0
	r = withDefaults(r)
	if err := r.check(); err != nil {
		return nil, err
	}
	rps, err := relyingParties(r)
	if err != nil {
		return nil, err
	}
	core, err := svc.Attach("passkey")
	if err != nil {
		return nil, err
	}
	if inherit {
		r.Reauth = core.Config().Recent
	}
	return &Module{core: core, rules: r, rps: rps}, nil
}

func withDefaults(r Rules) Rules {
	if r.RPName == "" {
		r.RPName = "authkit"
	}
	if r.CeremonyTTL == 0 {
		r.CeremonyTTL = 2 * time.Minute
	}
	if r.Reauth == 0 {
		r.Reauth = 5 * time.Minute
	}
	if r.Max == 0 {
		r.Max = 10
	}
	return r
}

func relyingParties(r Rules) (map[authkit.Audience]*webauthn.WebAuthn, error) {
	if r.RPID == "" {
		return nil, nil
	}
	timeout := webauthn.TimeoutConfig{Enforce: true, Timeout: r.CeremonyTTL, TimeoutUVD: r.CeremonyTTL}
	rps := make(map[authkit.Audience]*webauthn.WebAuthn, len(r.Origins))
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

func (mod *Module) relyingParty(aud authkit.Audience) (*webauthn.WebAuthn, bool, error) {
	if mod.rules.RPID == "" {
		return nil, false, authkit.ErrPasskeysOff
	}
	rp, ok := mod.rps[aud]
	if !ok {
		return nil, false, nil
	}
	return rp, true, nil
}

type passkeyUser struct {
	p     authkit.Principal
	creds []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte {
	id := u.p.ID
	return id[:]
}

func (u passkeyUser) WebAuthnName() string { return u.p.Login }

func (u passkeyUser) WebAuthnDisplayName() string { return u.p.Login }

func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// Rules configure passkey sign-in. A zero RPID switches passkeys off.
type Rules struct {
	// RPID is the relying party's domain, such as "example.com": no scheme, port or path.
	RPID string
	// RPName is the name the browser shows. Zero is "authkit".
	RPName string
	// Origins lists, per audience, the pages allowed to run a ceremony, as scheme://host[:port].
	Origins map[authkit.Audience][]string
	// CeremonyTTL is how long a begun ceremony may be finished. Zero is 2 minutes.
	CeremonyTTL time.Duration
	// Reauth is how recent a sign-in must be to add or remove a passkey. Zero is Config.Recent.
	Reauth time.Duration
	// Max is the most passkeys one principal may hold. Zero is 10.
	Max int
}

func (p Rules) check() error {
	if p.RPID == "" {
		if len(p.Origins) > 0 {
			return errors.New("authkit: passkey.Rules.Origins needs passkey.Rules.RPID")
		}
		return nil
	}
	if err := protocol.ValidateRPID(p.RPID); err != nil {
		return fmt.Errorf("authkit: passkey.Rules.RPID %q is not a domain: %v", p.RPID, err)
	}
	if p.RPID != strings.ToLower(p.RPID) {
		return fmt.Errorf("authkit: passkey.Rules.RPID %q must be lower case", p.RPID)
	}
	if len(p.Origins) == 0 {
		return errors.New("authkit: passkey.Rules.Origins is empty")
	}
	seen := map[string]authkit.Audience{}
	for _, aud := range slices.Sorted(maps.Keys(p.Origins)) {
		if len(p.Origins[aud]) == 0 {
			return fmt.Errorf("authkit: passkey.Rules.Origins[%q] is empty", aud)
		}
		for _, o := range p.Origins[aud] {
			u, err := url.Parse(o)
			if err != nil || u.Host == "" || o != u.Scheme+"://"+u.Host {
				return fmt.Errorf("authkit: passkey.Rules.Origins[%q] %q is not an origin (scheme://host[:port])", aud, o)
			}
			if u.Scheme != "https" && !(u.Scheme == "http" && p.RPID == "localhost") {
				return fmt.Errorf("authkit: passkey.Rules.Origins[%q] %q must use https", aud, o)
			}
			if host := u.Hostname(); host != p.RPID && !strings.HasSuffix(host, "."+p.RPID) {
				return fmt.Errorf("authkit: passkey.Rules.Origins[%q] %q is outside RPID %q", aud, o, p.RPID)
			}
			// WHY: a surface must not accept the other surface's page.
			if prev, ok := seen[o]; ok && prev != aud {
				return fmt.Errorf("authkit: passkey.Rules.Origins %q is listed for both %q and %q", o, prev, aud)
			}
			seen[o] = aud
		}
	}
	for _, d := range []struct {
		field string
		v     time.Duration
	}{{"CeremonyTTL", p.CeremonyTTL}, {"Reauth", p.Reauth}} {
		if d.v <= 0 || d.v > 10*time.Minute {
			return fmt.Errorf("authkit: passkey.Rules.%s must be in (0, 10m], not %v", d.field, d.v)
		}
	}
	if p.Max < 1 || p.Max > 100 {
		return fmt.Errorf("authkit: passkey.Rules.Max must be in [1, 100], not %d", p.Max)
	}
	return nil
}
