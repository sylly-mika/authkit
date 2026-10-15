package tests

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/passkey"
	"github.com/sylly-mika/authkit/password"
)

func TestNewValidatesItsConfig(t *testing.T) {
	good := authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}
	p := authkittest.NewPrincipals()
	if _, err := authkit.New(good, p); err != nil {
		t.Fatalf("a valid config was refused: %v", err)
	}
	short := good
	short.Secret = []byte("too short")
	noIssuer := good
	noIssuer.Issuer = ""
	for name, tc := range map[string]struct {
		cfg authkit.Config
		p   authkit.Principals
	}{
		"a 9-byte secret": {short, p},
		"no issuer":       {noIssuer, p},
		"no Principals":   {good, nil},
	} {
		if _, err := authkit.New(tc.cfg, tc.p); err == nil {
			t.Errorf("New accepted %s", name)
		}
	}
}

func TestNewRefusesAConfigThatDisablesAGuard(t *testing.T) {
	good := kittest.Rules{Config: authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}}
	p := authkittest.NewPrincipals()
	for name, f := range map[string]func(*kittest.Rules){
		"a negative throttle window":  func(c *kittest.Rules) { c.Throttle = authkit.Throttle{Failures: 5, Window: -time.Minute} },
		"a negative throttle lockout": func(c *kittest.Rules) { c.Throttle = authkit.Throttle{Failures: 5, Lockout: -time.Minute} },
		"a negative throttle limit":   func(c *kittest.Rules) { c.Throttle = authkit.Throttle{Failures: -1} },
		"a negative RefreshTTL":       func(c *kittest.Rules) { c.RefreshTTL = -time.Hour },
		"a zero RefreshTTLFor":        func(c *kittest.Rules) { c.RefreshTTLFor = map[authkit.Audience]time.Duration{"staff": 0} },
		"a negative ResetTTL":         func(c *kittest.Rules) { c.Password.ResetTTL = -time.Hour },
		"a negative ResetFloor":       func(c *kittest.Rules) { c.Password.ResetFloor = -time.Second },
		"a negative HashWait":         func(c *kittest.Rules) { c.Password.HashWait = -time.Second },
		"a negative ReuseGrace":       func(c *kittest.Rules) { c.ReuseGrace = -time.Second },
		"a policy with no minimum":    func(c *kittest.Rules) { c.Password.Password = password.Policy{MaxRunes: 64} },
		"a policy with no maximum":    func(c *kittest.Rules) { c.Password.Password = password.Policy{MinRunes: 12} },
		"a minimum above the maximum": func(c *kittest.Rules) { c.Password.Password = password.Policy{MinRunes: 20, MaxRunes: 10} },
	} {
		cfg := good
		f(&cfg)
		if _, err := kittest.NewKit(cfg, p); err == nil {
			t.Errorf("New accepted %s", name)
		}
	}
}

func TestNewNamesTheDurationItRefuses(t *testing.T) {
	good := kittest.Rules{Config: authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}}
	for field, f := range map[string]func(*kittest.Rules){
		"RefreshTTL": func(c *kittest.Rules) { c.RefreshTTL = -time.Hour },
		"ResetTTL":   func(c *kittest.Rules) { c.Password.ResetTTL = -time.Hour },
		"ResetFloor": func(c *kittest.Rules) { c.Password.ResetFloor = -time.Second },
		"HashWait":   func(c *kittest.Rules) { c.Password.HashWait = -time.Second },
		"ReuseGrace": func(c *kittest.Rules) { c.ReuseGrace = -time.Second },
	} {
		cfg := good
		f(&cfg)
		if _, err := kittest.NewKit(cfg, authkittest.NewPrincipals()); err == nil || !strings.Contains(err.Error(), "Config."+field) {
			t.Errorf("New with a negative %s = %v, want an error naming Config.%s", field, err, field)
		}
	}
}

func TestNormalizeTrimsComposesAndLowers(t *testing.T) {
	for in, want := range map[string]string{
		"  Ada@Example.invalid ":    "ada@example.invalid",
		"ZOË@example.invalid":       "zoë@example.invalid",
		"Zoe\u0308@example.invalid": "zoë@example.invalid",
	} {
		if got := authkit.Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q (spec §5.1)", in, got, want)
		}
	}
}

func TestNormalizeIsStable(t *testing.T) {
	for in, want := range map[string]string{
		"I\u0307@example.invalid":      "i@example.invalid",
		"\u0130\u0301@example.invalid": "\u00ed@example.invalid",
		"\u03aa\u0301@example.invalid": "\u0390@example.invalid",
		"T\u0308@example.invalid":      "\u1e97@example.invalid",
		"\u0386\u0345@example.invalid": "\u1fb4@example.invalid",
		"ada\x00@example.invalid":      "ada@example.invalid",
		"ada\xff@example.invalid":      "ada@example.invalid",
	} {
		if got := authkit.Normalize(in); got != want || authkit.Normalize(got) != got {
			t.Errorf("Normalize(%q) = %q, want %q, a fixed point in NFC with no NUL", in, got, want)
		}
	}
}

func TestNewRefusesContradictorySessionRules(t *testing.T) {
	bearer := kittest.Rules{Config: authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}}
	session := kittest.Rules{Config: authkit.Config{Transport: authkit.TransportSession}}
	for name, tc := range map[string]struct {
		base kittest.Rules
		f    func(*kittest.Rules)
		want string
	}{
		"an idle timeout past the cap": {bearer, func(c *kittest.Rules) { c.Session = authkit.SessionRules{IdleTTL: 13 * time.Hour} }, "Config.Session.IdleTTL"},
		"a RefreshTTL past the cap":    {bearer, func(c *kittest.Rules) { c.RefreshTTL = 7 * 24 * time.Hour }, "Config.Session.IdleTTL"},
		"an audience's idle past the cap": {bearer, func(c *kittest.Rules) {
			c.RefreshTTLFor = map[authkit.Audience]time.Duration{"client": 13 * time.Hour}
		}, `RefreshTTLFor["client"]`},
		"a rotation as late as the idle timeout": {session, func(c *kittest.Rules) {
			c.Session = authkit.SessionRules{IdleTTL: 10 * time.Minute, RotateEvery: 10 * time.Minute}
		}, "Config.Session.RotateEvery"},
		"a rotation after an audience's idle timeout": {session, func(c *kittest.Rules) {
			c.RefreshTTLFor = map[authkit.Audience]time.Duration{"admin": 5 * time.Minute}
		}, "Config.Session.RotateEvery"},
		"a negative idle timeout": {session, func(c *kittest.Rules) { c.Session.IdleTTL = -time.Minute }, "Config.Session.IdleTTL"},
		"an unknown transport":    {bearer, func(c *kittest.Rules) { c.Transport = 2 }, "Config.Transport"},
		"an unknown revoke rule":  {bearer, func(c *kittest.Rules) { c.Password.RevokeOnPasswordChange = 2 }, "Config.RevokeOnPasswordChange"},
		"Bearer without a secret": {bearer, func(c *kittest.Rules) { c.Secret = nil }, "Config.Secret"},
	} {
		cfg := tc.base
		tc.f(&cfg)
		if _, err := kittest.NewKit(cfg, authkittest.NewPrincipals()); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: New = %v, want an error naming %s", name, err, tc.want)
		}
	}
}

func TestNewAcceptsTheConfigsTheAppsSet(t *testing.T) {
	for name, cfg := range map[string]kittest.Rules{
		"ino-tasks' pins (spec §6)": {Config: authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!"),
			Session:  authkit.SessionRules{IdleTTL: 7 * 24 * time.Hour, AbsoluteTTL: -1},
			Throttle: authkit.Throttle{Failures: 10, Window: 15 * time.Minute, Lockout: 15 * time.Minute, CountAfterVerify: true, PlainLoginKey: true},
			Events:   authkit.EventRules{ChangeLogsReset: true}, EventRetention: -1},
			Password: password.Config{Reset: authkit.ResetRules{MayCreateCredential: true}}},
		"BMParts' Session mode, no issuer or secret": {Config: authkit.Config{Transport: authkit.TransportSession},
			Password: password.Config{RevokeOnPasswordChange: authkit.RevokeAll,
				Hashing: password.Params{Memory: 64 * 1024, Time: 3, Threads: 2, SaltLen: 16, KeyLen: 32}, Password: password.Policy{MinRunes: 12, MaxRunes: 256}}},
		"Bearer ignores the rotation": {Config: authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!"),
			Session: authkit.SessionRules{IdleTTL: 10 * time.Minute, RotateEvery: time.Hour}}},
		"a session that never rotates": {Config: authkit.Config{Transport: authkit.TransportSession, Session: authkit.SessionRules{IdleTTL: time.Minute, RotateEvery: -1}}},
	} {
		svc, err := kittest.NewKit(cfg, authkittest.NewPrincipals())
		if err != nil {
			t.Errorf("%s: New = %v", name, err)
			continue
		}
		if (svc.Codec() == nil) != (cfg.Transport == authkit.TransportSession) {
			t.Errorf("%s: Codec() = %v; want one in Bearer mode only", name, svc.Codec())
		}
	}
}

var passkeyBase = authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}

var prodPasskeys = passkey.Rules{
	RPID: "tasks.inostudio.lv",
	Origins: map[authkit.Audience][]string{
		"staff":  {"https://tasks.inostudio.lv"},
		"client": {"https://portal.tasks.inostudio.lv"},
	},
}

var devPasskeys = passkey.Rules{
	RPID: "localhost",
	Origins: map[authkit.Audience][]string{
		"staff":  {"http://localhost:3000"},
		"client": {"http://localhost:3100"},
	},
}

func newWithPasskeys(p passkey.Rules) error {
	svc, err := authkit.New(passkeyBase, authkittest.NewPrincipals())
	if err != nil {
		return err
	}
	_, err = passkey.New(svc, p)
	return err
}

func newWithSecondFactors(r authkit.SecondFactorRules) error {
	cfg := passkeyBase
	cfg.SecondFactors = r
	_, err := authkit.New(cfg, authkittest.NewPrincipals())
	return err
}

func TestNewAcceptsSecondFactorRules(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	for name, r := range map[string]authkit.SecondFactorRules{
		"off":         {},
		"key only":    {Key: key},
		"upper bound": {Key: key, Issuer: "Ino Tasks", ChallengeTTL: time.Hour, EmailCodeTTL: time.Hour, SetupTTL: time.Hour, ResendEvery: 10 * time.Minute, Reauth: 10 * time.Minute, MaxTries: 10, MaxSends: 20, RecoveryCodes: 16},
		"lower bound": {Key: key, ChallengeTTL: time.Second, EmailCodeTTL: time.Second, SetupTTL: time.Second, ResendEvery: time.Second, Reauth: time.Second, MaxTries: 1, MaxSends: 1, RecoveryCodes: 8},
	} {
		if err := newWithSecondFactors(r); err != nil {
			t.Errorf("%s: New refused a valid SecondFactors: %v", name, err)
		}
	}
}

func TestNewRefusesSecondFactorRulesOutOfRange(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	with := func(f func(*authkit.SecondFactorRules)) authkit.SecondFactorRules {
		r := authkit.SecondFactorRules{Key: key}
		f(&r)
		return r
	}
	const prefix = "authkit: Config.SecondFactors."
	for name, c := range map[string]struct {
		r    authkit.SecondFactorRules
		want string
	}{
		"Key 31 bytes":          {authkit.SecondFactorRules{Key: key[:31]}, prefix + "Key must be 32 bytes, not 31"},
		"Key 33 bytes":          {authkit.SecondFactorRules{Key: append(append([]byte{}, key...), 'x')}, prefix + "Key must be 32 bytes, not 33"},
		"Key 16 bytes":          {authkit.SecondFactorRules{Key: key[:16]}, prefix + "Key must be 32 bytes, not 16"},
		"Issuer colon":          {with(func(r *authkit.SecondFactorRules) { r.Issuer = "Ino:Tasks" }), prefix + `Issuer "Ino:Tasks" must not contain a colon`},
		"ChallengeTTL negative": {with(func(r *authkit.SecondFactorRules) { r.ChallengeTTL = -time.Second }), prefix + "ChallengeTTL must be in (0, 1h], not -1s"},
		"EmailCodeTTL over 1h":  {with(func(r *authkit.SecondFactorRules) { r.EmailCodeTTL = time.Hour + time.Second }), prefix + "EmailCodeTTL must be in (0, 1h], not 1h0m1s"},
		"SetupTTL negative":     {with(func(r *authkit.SecondFactorRules) { r.SetupTTL = -time.Second }), prefix + "SetupTTL must be in (0, 1h], not -1s"},
		"ResendEvery over 10m":  {with(func(r *authkit.SecondFactorRules) { r.ResendEvery = 11 * time.Minute }), prefix + "ResendEvery must be in (0, 10m], not 11m0s"},
		"Reauth negative":       {with(func(r *authkit.SecondFactorRules) { r.Reauth = -time.Second }), prefix + "Reauth must be in (0, 10m], not -1s"},
		"MaxTries -1":           {with(func(r *authkit.SecondFactorRules) { r.MaxTries = -1 }), prefix + "MaxTries must be in [1, 10], not -1"},
		"MaxTries 11":           {with(func(r *authkit.SecondFactorRules) { r.MaxTries = 11 }), prefix + "MaxTries must be in [1, 10], not 11"},
		"MaxSends -1":           {with(func(r *authkit.SecondFactorRules) { r.MaxSends = -1 }), prefix + "MaxSends must be in [1, 20], not -1"},
		"MaxSends 21":           {with(func(r *authkit.SecondFactorRules) { r.MaxSends = 21 }), prefix + "MaxSends must be in [1, 20], not 21"},
		"RecoveryCodes 7":       {with(func(r *authkit.SecondFactorRules) { r.RecoveryCodes = 7 }), prefix + "RecoveryCodes must be in [8, 16], not 7"},
		"RecoveryCodes 17":      {with(func(r *authkit.SecondFactorRules) { r.RecoveryCodes = 17 }), prefix + "RecoveryCodes must be in [8, 16], not 17"},
	} {
		err := newWithSecondFactors(c.r)
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: New = %v, want %q", name, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), string(key)) {
			t.Errorf("%s: New's error carries the key: <redacted>", name)
		}
	}
}

func oneOrigin(rpid, origin string) passkey.Rules {
	return passkey.Rules{RPID: rpid, Origins: map[authkit.Audience][]string{"staff": {origin}}}
}

func wantPasskeyRefusal(t *testing.T, name string, p passkey.Rules, want string) {
	t.Helper()
	if err := newWithPasskeys(p); err == nil || err.Error() != want {
		t.Errorf("%s: New = %v, want %q", name, err, want)
	}
}

func TestNewAcceptsPasskeyRules(t *testing.T) {
	for name, p := range map[string]passkey.Rules{
		"passkeys off":         {},
		"production":           prodPasskeys,
		"development":          devPasskeys,
		"localhost over https": oneOrigin("localhost", "https://localhost"),
		"limits at their bounds": {RPID: "tasks.inostudio.lv", Origins: map[authkit.Audience][]string{
			"staff": {"https://tasks.inostudio.lv:8443", "https://tasks.inostudio.lv", "https://tasks.inostudio.lv"}},
			CeremonyTTL: 10 * time.Minute, Reauth: 10 * time.Minute, Max: 100},
		"smallest limits": {RPID: prodPasskeys.RPID, Origins: prodPasskeys.Origins, CeremonyTTL: time.Second, Reauth: time.Second, Max: 1},
	} {
		if err := newWithPasskeys(p); err != nil {
			t.Errorf("%s: New = %v, want nil", name, err)
		}
	}
}

func TestNewRefusesABadPasskeyRPID(t *testing.T) {
	for name, p := range map[string]passkey.Rules{
		"a scheme": oneOrigin("https://tasks.inostudio.lv", "https://tasks.inostudio.lv"),
		"a port":   oneOrigin("tasks.inostudio.lv:443", "https://tasks.inostudio.lv"),
		"a path":   oneOrigin("tasks.inostudio.lv/app", "https://tasks.inostudio.lv"),
		"an IP":    oneOrigin("127.0.0.1", "https://127.0.0.1"),
	} {
		err := newWithPasskeys(p)
		if err == nil || !strings.HasPrefix(err.Error(), "authkit: Config.Passkeys.RPID ") {
			t.Errorf("%s: New = %v, want a refusal naming Config.Passkeys.RPID", name, err)
		}
	}
	wantPasskeyRefusal(t, "upper case", oneOrigin("Tasks.Inostudio.lv", "https://Tasks.Inostudio.lv"),
		`authkit: Config.Passkeys.RPID "Tasks.Inostudio.lv" must be lower case`)
}

func TestNewRefusesPasskeyOriginsWithoutAnRPIDOrAnAudience(t *testing.T) {
	wantPasskeyRefusal(t, "origins without an RPID", passkey.Rules{Origins: map[authkit.Audience][]string{"staff": {"https://tasks.inostudio.lv"}}},
		"authkit: Config.Passkeys.Origins needs Config.Passkeys.RPID")
	wantPasskeyRefusal(t, "no origins", passkey.Rules{RPID: "tasks.inostudio.lv"},
		"authkit: Config.Passkeys.Origins is empty")
	wantPasskeyRefusal(t, "an audience without an origin", passkey.Rules{RPID: "tasks.inostudio.lv",
		Origins: map[authkit.Audience][]string{"staff": {"https://tasks.inostudio.lv"}, "client": {}}},
		`authkit: Config.Passkeys.Origins["client"] is empty`)
}

func TestNewRefusesAMalformedPasskeyOrigin(t *testing.T) {
	for _, o := range []string{
		"https://tasks.inostudio.lv/", "https://tasks.inostudio.lv/app", "https://tasks.inostudio.lv?x=1",
		"https://tasks.inostudio.lv#top", "https://user@tasks.inostudio.lv", "HTTPS://tasks.inostudio.lv",
		"//tasks.inostudio.lv", "tasks.inostudio.lv", "",
	} {
		wantPasskeyRefusal(t, fmt.Sprintf("origin %q", o), oneOrigin("tasks.inostudio.lv", o),
			fmt.Sprintf("authkit: Config.Passkeys.Origins[%q] %q is not an origin (scheme://host[:port])", "staff", o))
	}
}

func TestNewRefusesAPasskeyOriginWithoutHTTPS(t *testing.T) {
	for _, c := range []struct{ rpid, origin string }{
		{"tasks.inostudio.lv", "http://tasks.inostudio.lv"},
		{"tasks.inostudio.lv", "ftp://tasks.inostudio.lv"},
		{"tasks.inostudio.lv", "wss://tasks.inostudio.lv"},
		{"localhost", "ftp://localhost"},
	} {
		wantPasskeyRefusal(t, c.origin, oneOrigin(c.rpid, c.origin),
			fmt.Sprintf("authkit: Config.Passkeys.Origins[%q] %q must use https", "staff", c.origin))
	}
}

func TestNewRefusesAPasskeyOriginOutsideTheRPID(t *testing.T) {
	for _, o := range []string{
		"https://nottasks.inostudio.lv", "https://inostudio.lv", "https://tasks.inostudio.lv.evil.test", "https://Tasks.inostudio.lv",
	} {
		wantPasskeyRefusal(t, o, oneOrigin("tasks.inostudio.lv", o),
			fmt.Sprintf("authkit: Config.Passkeys.Origins[%q] %q is outside RPID %q", "staff", o, "tasks.inostudio.lv"))
	}
	wantPasskeyRefusal(t, "localhost IP", oneOrigin("localhost", "http://127.0.0.1:3000"),
		fmt.Sprintf("authkit: Config.Passkeys.Origins[%q] %q is outside RPID %q", "staff", "http://127.0.0.1:3000", "localhost"))
}

func TestNewRefusesAnOriginOnTwoAudiences(t *testing.T) {
	wantPasskeyRefusal(t, "one origin, two audiences", passkey.Rules{RPID: "tasks.inostudio.lv",
		Origins: map[authkit.Audience][]string{"staff": {"https://tasks.inostudio.lv"}, "client": {"https://tasks.inostudio.lv"}}},
		`authkit: Config.Passkeys.Origins "https://tasks.inostudio.lv" is listed for both "client" and "staff"`)
}

func TestNewRefusesPasskeyLimitsOutOfRange(t *testing.T) {
	with := func(f func(*passkey.Rules)) passkey.Rules {
		p := prodPasskeys
		f(&p)
		return p
	}
	for name, c := range map[string]struct {
		p    passkey.Rules
		want string
	}{
		"CeremonyTTL negative": {with(func(p *passkey.Rules) { p.CeremonyTTL = -time.Second }),
			"authkit: Config.Passkeys.CeremonyTTL must be in (0, 10m], not -1s"},
		"CeremonyTTL over 10m": {with(func(p *passkey.Rules) { p.CeremonyTTL = 10*time.Minute + time.Second }),
			"authkit: Config.Passkeys.CeremonyTTL must be in (0, 10m], not 10m1s"},
		"Reauth negative": {with(func(p *passkey.Rules) { p.Reauth = -time.Second }),
			"authkit: Config.Passkeys.Reauth must be in (0, 10m], not -1s"},
		"Reauth over 10m": {with(func(p *passkey.Rules) { p.Reauth = 11 * time.Minute }),
			"authkit: Config.Passkeys.Reauth must be in (0, 10m], not 11m0s"},
		"Max negative": {with(func(p *passkey.Rules) { p.Max = -1 }),
			"authkit: Config.Passkeys.Max must be in [1, 100], not -1"},
		"Max over 100": {with(func(p *passkey.Rules) { p.Max = 101 }),
			"authkit: Config.Passkeys.Max must be in [1, 100], not 101"},
	} {
		wantPasskeyRefusal(t, name, c.p, c.want)
	}
}
