package authkit

import (
	"testing"
	"time"
)

func TestWithDefaultsAreTheSpecs(t *testing.T) {
	c := withDefaults(Config{})
	if c.Transport != TransportBearer || c.AccessTTL != 15*time.Minute || c.RefreshTTL != 0 ||
		c.Session.IdleTTL != 30*time.Minute || c.Session.AbsoluteTTL != 12*time.Hour || c.Session.RotateEvery != 15*time.Minute || c.Session.AbsoluteTTLFor != nil ||
		c.ReuseGrace != 30*time.Second ||
		c.Throttle != (Throttle{Failures: 5, Window: 15 * time.Minute, Lockout: 15 * time.Minute}) ||
		c.Events != (EventRules{}) ||
		c.EventRetention != 90*24*time.Hour || c.InviteRetention != 30*24*time.Hour || c.OnEvent != nil || c.Clock == nil || c.Rand == nil {
		t.Errorf("withDefaults(Config{}) = %+v, want spec §3.1's values", c)
	}
	if got, want := withDefaults(Config{Throttle: Throttle{Failures: 10}}).Throttle, (Throttle{Failures: 10, Window: 15 * time.Minute, Lockout: 15 * time.Minute}); got != want {
		t.Errorf("Throttle{Failures: 10} = %+v, want %+v: a zero window or lockout never locks", got, want)
	}
	if got := withDefaults(Config{RefreshTTL: 7 * 24 * time.Hour, Session: SessionRules{IdleTTL: time.Hour}}).Session.IdleTTL; got != 7*24*time.Hour {
		t.Errorf("Session.IdleTTL with RefreshTTL set = %v, want RefreshTTL's 168h: the deprecated alias wins", got)
	}
	if got := withDefaults(Config{Session: SessionRules{AbsoluteTTL: -1, RotateEvery: -1}, EventRetention: -1}); got.Session.AbsoluteTTL != -1 ||
		got.Session.RotateEvery != -1 || got.EventRetention != -1 {
		t.Errorf("negative durations = %+v, %v; want them kept: negative switches the rule off", got.Session, got.EventRetention)
	}
}
