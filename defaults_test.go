package authkit

import (
	"testing"
	"time"

	"github.com/sylly-mika/authkit/password"
)

func TestWithDefaultsAreTheSpecs(t *testing.T) {
	c := withDefaults(Config{})
	if c.AccessTTL != 15*time.Minute || c.RefreshTTL != 7*24*time.Hour || c.ResetTTL != time.Hour ||
		c.ResetFloor != 500*time.Millisecond || c.HashWait != 2*time.Second || c.ReuseGrace != 30*time.Second ||
		c.HashConcurrency != 4 || c.Password != password.DefaultPolicy || c.Hashing != password.Default ||
		c.Throttle != (Throttle{Failures: 10, Window: 15 * time.Minute, Lockout: 15 * time.Minute}) ||
		c.Clock == nil || c.Rand == nil {
		t.Errorf("withDefaults(Config{}) = %+v, want spec §8's values", c)
	}
	if got, want := withDefaults(Config{Throttle: Throttle{Failures: 5}}).Throttle, (Throttle{Failures: 5, Window: 15 * time.Minute, Lockout: 15 * time.Minute}); got != want {
		t.Errorf("Throttle{Failures: 5} = %+v, want %+v: a zero window or lockout never locks", got, want)
	}
}
