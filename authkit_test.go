package authkit_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
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
	good := authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}
	p := authkittest.NewPrincipals()
	for name, f := range map[string]func(*authkit.Config){
		"a negative throttle window":  func(c *authkit.Config) { c.Throttle = authkit.Throttle{Failures: 5, Window: -time.Minute} },
		"a negative throttle lockout": func(c *authkit.Config) { c.Throttle = authkit.Throttle{Failures: 5, Lockout: -time.Minute} },
		"a negative throttle limit":   func(c *authkit.Config) { c.Throttle = authkit.Throttle{Failures: -1} },
		"a negative RefreshTTL":       func(c *authkit.Config) { c.RefreshTTL = -time.Hour },
		"a zero RefreshTTLFor":        func(c *authkit.Config) { c.RefreshTTLFor = map[authkit.Audience]time.Duration{"staff": 0} },
		"a negative ResetTTL":         func(c *authkit.Config) { c.ResetTTL = -time.Hour },
		"a negative ResetFloor":       func(c *authkit.Config) { c.ResetFloor = -time.Second },
		"a negative HashWait":         func(c *authkit.Config) { c.HashWait = -time.Second },
		"a negative ReuseGrace":       func(c *authkit.Config) { c.ReuseGrace = -time.Second },
		"a policy with no minimum":    func(c *authkit.Config) { c.Password = password.Policy{MaxRunes: 64} },
		"a policy with no maximum":    func(c *authkit.Config) { c.Password = password.Policy{MinRunes: 12} },
		"a minimum above the maximum": func(c *authkit.Config) { c.Password = password.Policy{MinRunes: 20, MaxRunes: 10} },
	} {
		cfg := good
		f(&cfg)
		if _, err := authkit.New(cfg, p); err == nil {
			t.Errorf("New accepted %s", name)
		}
	}
}

func TestNewNamesTheDurationItRefuses(t *testing.T) {
	good := authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}
	for field, f := range map[string]func(*authkit.Config){
		"RefreshTTL": func(c *authkit.Config) { c.RefreshTTL = -time.Hour },
		"ResetTTL":   func(c *authkit.Config) { c.ResetTTL = -time.Hour },
		"ResetFloor": func(c *authkit.Config) { c.ResetFloor = -time.Second },
		"HashWait":   func(c *authkit.Config) { c.HashWait = -time.Second },
		"ReuseGrace": func(c *authkit.Config) { c.ReuseGrace = -time.Second },
	} {
		cfg := good
		f(&cfg)
		if _, err := authkit.New(cfg, authkittest.NewPrincipals()); err == nil || !strings.Contains(err.Error(), "Config."+field) {
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
	bearer := authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}
	session := authkit.Config{Transport: authkit.TransportSession}
	for name, tc := range map[string]struct {
		base authkit.Config
		f    func(*authkit.Config)
		want string
	}{
		"an idle timeout past the cap": {bearer, func(c *authkit.Config) { c.Session = authkit.SessionRules{IdleTTL: 13 * time.Hour} }, "Config.Session.IdleTTL"},
		"a RefreshTTL past the cap":    {bearer, func(c *authkit.Config) { c.RefreshTTL = 7 * 24 * time.Hour }, "Config.Session.IdleTTL"},
		"an audience's idle past the cap": {bearer, func(c *authkit.Config) {
			c.RefreshTTLFor = map[authkit.Audience]time.Duration{"client": 13 * time.Hour}
		}, `RefreshTTLFor["client"]`},
		"a rotation as late as the idle timeout": {session, func(c *authkit.Config) {
			c.Session = authkit.SessionRules{IdleTTL: 10 * time.Minute, RotateEvery: 10 * time.Minute}
		}, "Config.Session.RotateEvery"},
		"a rotation after an audience's idle timeout": {session, func(c *authkit.Config) {
			c.RefreshTTLFor = map[authkit.Audience]time.Duration{"admin": 5 * time.Minute}
		}, "Config.Session.RotateEvery"},
		"a negative idle timeout": {session, func(c *authkit.Config) { c.Session.IdleTTL = -time.Minute }, "Config.Session.IdleTTL"},
		"an unknown transport":    {bearer, func(c *authkit.Config) { c.Transport = 2 }, "Config.Transport"},
		"an unknown revoke rule":  {bearer, func(c *authkit.Config) { c.RevokeOnPasswordChange = 2 }, "Config.RevokeOnPasswordChange"},
		"Bearer without a secret": {bearer, func(c *authkit.Config) { c.Secret = nil }, "Config.Secret"},
	} {
		cfg := tc.base
		tc.f(&cfg)
		if _, err := authkit.New(cfg, authkittest.NewPrincipals()); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: New = %v, want an error naming %s", name, err, tc.want)
		}
	}
}

func TestNewAcceptsTheConfigsTheAppsSet(t *testing.T) {
	for name, cfg := range map[string]authkit.Config{
		"ino-tasks' pins (spec §6)": {Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!"),
			Session:  authkit.SessionRules{IdleTTL: 7 * 24 * time.Hour, AbsoluteTTL: -1},
			Throttle: authkit.Throttle{Failures: 10, Window: 15 * time.Minute, Lockout: 15 * time.Minute, CountAfterVerify: true, PlainLoginKey: true},
			Events:   authkit.EventRules{ChangeLogsReset: true}, Reset: authkit.ResetRules{MayCreateCredential: true}, EventRetention: -1},
		"BMParts' Session mode, no issuer or secret": {Transport: authkit.TransportSession, RevokeOnPasswordChange: authkit.RevokeAll,
			Hashing: password.Params{Memory: 64 * 1024, Time: 3, Threads: 2, SaltLen: 16, KeyLen: 32}, Password: password.Policy{MinRunes: 12, MaxRunes: 256}},
		"Bearer ignores the rotation": {Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!"),
			Session: authkit.SessionRules{IdleTTL: 10 * time.Minute, RotateEvery: time.Hour}},
		"a session that never rotates": {Transport: authkit.TransportSession, Session: authkit.SessionRules{IdleTTL: time.Minute, RotateEvery: -1}},
	} {
		svc, err := authkit.New(cfg, authkittest.NewPrincipals())
		if err != nil {
			t.Errorf("%s: New = %v", name, err)
			continue
		}
		if (svc.Codec() == nil) != (cfg.Transport == authkit.TransportSession) {
			t.Errorf("%s: Codec() = %v; want one in Bearer mode only", name, svc.Codec())
		}
	}
}
