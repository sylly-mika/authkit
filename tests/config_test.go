package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/internal/kittest"
)

func pestSessions(c *kittest.Rules) {
	c.Session = authkit.SessionRules{IdleTTL: 2 * time.Hour, AbsoluteTTL: 12 * time.Hour,
		AbsoluteTTLFor: map[authkit.Audience]time.Duration{"field": -1}}
	c.RefreshTTLFor = map[authkit.Audience]time.Duration{"field": 90 * 24 * time.Hour}
}

func refused(t *testing.T, c kittest.Rules, want ...string) {
	t.Helper()
	_, err := kittest.NewKit(c, authkittest.NewPrincipals())
	if err == nil {
		t.Fatalf("New accepted the config, want a refusal naming %q", want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("New = %v, want an error naming %s", err, w)
		}
	}
}

func TestNewAcceptsAPerAudienceAbsoluteTTL(t *testing.T) {
	bearer := kittest.Rules{Config: authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}}
	session := bearer
	session.Transport = authkit.TransportSession
	for name, base := range map[string]kittest.Rules{"bearer": bearer, "session": session} {
		pestSessions(&base)
		if _, err := kittest.NewKit(base, authkittest.NewPrincipals()); err != nil {
			t.Errorf("%s: New = %v, want pest's per-audience rules accepted", name, err)
		}
	}
}

func TestNewRefusesAnIdleOverItsAudiencesCap(t *testing.T) {
	bearer := kittest.Rules{Config: authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}}
	t.Run("office idle over its own cap", func(t *testing.T) {
		c := bearer
		c.Session = authkit.SessionRules{IdleTTL: 2 * time.Hour, AbsoluteTTL: -1,
			AbsoluteTTLFor: map[authkit.Audience]time.Duration{"field": -1, "office": 12 * time.Hour}}
		c.RefreshTTLFor = map[authkit.Audience]time.Duration{"field": 90 * 24 * time.Hour, "office": 13 * time.Hour}
		refused(t, c, `RefreshTTLFor["office"]`, `Session.AbsoluteTTLFor["office"] (12h0m0s)`)
	})
	t.Run("default idle over an audience's cap", func(t *testing.T) {
		c := bearer
		c.Session = authkit.SessionRules{IdleTTL: 13 * time.Hour, AbsoluteTTL: -1,
			AbsoluteTTLFor: map[authkit.Audience]time.Duration{"office": 12 * time.Hour}}
		refused(t, c, "Config.Session.IdleTTL (13h0m0s)", `Session.AbsoluteTTLFor["office"]`)
	})
	t.Run("default pair still checked", func(t *testing.T) {
		c := bearer
		c.Session = authkit.SessionRules{IdleTTL: 13 * time.Hour, AbsoluteTTL: 12 * time.Hour,
			AbsoluteTTLFor: map[authkit.Audience]time.Duration{"field": -1}}
		refused(t, c, "Config.Session.IdleTTL", "exceeds Session.AbsoluteTTL (12h0m0s)")
	})
}

func TestNewRefusesAZeroAbsoluteTTLFor(t *testing.T) {
	bearer := kittest.Rules{Config: authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}}
	bearer.Session.AbsoluteTTLFor = map[authkit.Audience]time.Duration{"office": 0}
	refused(t, bearer, `Session.AbsoluteTTLFor["office"] is zero`)
}
