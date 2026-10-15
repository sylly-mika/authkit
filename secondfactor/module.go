package secondfactor

import (
	"fmt"
	"strings"
	"time"

	"github.com/sylly-mika/authkit"
)

// Rules configure two-factor sign-in. An empty Key switches second factors off.
type Rules struct {
	// Key is 32 random bytes that seal authenticator secrets and key the code hashes. Empty is off.
	Key []byte
	// Issuer names the app in authenticator apps. Zero is "authkit".
	Issuer string
	// ChallengeTTL is how long a password sign-in's second step may be finished. Zero is 10 minutes.
	ChallengeTTL time.Duration
	// EmailCodeTTL is how long an emailed code is valid. Zero is 10 minutes.
	EmailCodeTTL time.Duration
	// SetupTTL is how long a begun authenticator setup may be confirmed. Zero is 15 minutes.
	SetupTTL time.Duration
	// ResendEvery is the least time between two emailed codes. Zero is 60 seconds.
	ResendEvery time.Duration
	// Reauth is how recent a sign-in must be to change sign-in methods. Zero is 5 minutes.
	Reauth time.Duration
	// MaxTries is how many wrong codes end a second step or an emailed code. Zero is 5.
	MaxTries int
	// MaxSends is how many times one emailed code may be sent. Zero is 5.
	MaxSends int
	// RecoveryCodes is how many recovery codes one set holds. Zero is 10.
	RecoveryCodes int
}

// Module is second-factor setup and management on one Service, and its second-step verifier.
type Module struct {
	core *authkit.Core
	r    Rules
}

// New attaches second factors to svc. Zero fields of r take their defaults. With a Key, New gives svc its second-step verifier; with an empty Key every method answers authkit.ErrSecondFactorsOff and a sign-in that needs a second factor fails closed. New refuses rules out of range, and answers authkit.ErrAttached when svc already has second factors.
func New(svc *authkit.Service, r Rules) (*Module, error) {
	r = withDefaults(r)
	if err := r.check(); err != nil {
		return nil, err
	}
	core, err := svc.Attach("secondfactor")
	if err != nil {
		return nil, err
	}
	m := &Module{core: core, r: r}
	if len(r.Key) > 0 {
		if err := core.SetVerifier(verifier{m: m}); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func withDefaults(r Rules) Rules {
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	if r.Issuer == "" {
		r.Issuer = "authkit"
	}
	def(&r.ChallengeTTL, 10*time.Minute)
	def(&r.EmailCodeTTL, 10*time.Minute)
	def(&r.SetupTTL, 15*time.Minute)
	def(&r.ResendEvery, time.Minute)
	def(&r.Reauth, 5*time.Minute)
	if r.MaxTries == 0 {
		r.MaxTries = 5
	}
	if r.MaxSends == 0 {
		r.MaxSends = 5
	}
	if r.RecoveryCodes == 0 {
		r.RecoveryCodes = 10
	}
	return r
}

func (r Rules) check() error {
	if len(r.Key) != 0 && len(r.Key) != 32 {
		return fmt.Errorf("authkit: Config.SecondFactors.Key must be 32 bytes, not %d", len(r.Key))
	}
	// WHY: the otpauth label is Issuer:account; a colon in the issuer splits it wrongly in authenticator apps.
	if strings.Contains(r.Issuer, ":") {
		return fmt.Errorf("authkit: Config.SecondFactors.Issuer %q must not contain a colon", r.Issuer)
	}
	for _, d := range []struct {
		field string
		v     time.Duration
	}{{"ChallengeTTL", r.ChallengeTTL}, {"EmailCodeTTL", r.EmailCodeTTL}, {"SetupTTL", r.SetupTTL}} {
		if d.v <= 0 || d.v > time.Hour {
			return fmt.Errorf("authkit: Config.SecondFactors.%s must be in (0, 1h], not %v", d.field, d.v)
		}
	}
	for _, d := range []struct {
		field string
		v     time.Duration
	}{{"ResendEvery", r.ResendEvery}, {"Reauth", r.Reauth}} {
		if d.v <= 0 || d.v > 10*time.Minute {
			return fmt.Errorf("authkit: Config.SecondFactors.%s must be in (0, 10m], not %v", d.field, d.v)
		}
	}
	if r.MaxTries < 1 || r.MaxTries > 10 {
		return fmt.Errorf("authkit: Config.SecondFactors.MaxTries must be in [1, 10], not %d", r.MaxTries)
	}
	if r.MaxSends < 1 || r.MaxSends > 20 {
		return fmt.Errorf("authkit: Config.SecondFactors.MaxSends must be in [1, 20], not %d", r.MaxSends)
	}
	if r.RecoveryCodes < 8 || r.RecoveryCodes > 16 {
		return fmt.Errorf("authkit: Config.SecondFactors.RecoveryCodes must be in [8, 16], not %d", r.RecoveryCodes)
	}
	return nil
}
