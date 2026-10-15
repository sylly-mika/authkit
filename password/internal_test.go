package password

import (
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
)

func TestConfigDefaultsAreTheSpecs(t *testing.T) {
	c := Config{}.withDefaults()
	if c.ResetTTL != time.Hour || c.ResetFloor != 500*time.Millisecond || c.HashWait != 2*time.Second ||
		c.HashConcurrency != 4 || c.Password != DefaultPolicy || c.Hashing != Default ||
		c.RevokeOnPasswordChange != authkit.RevokeOthers || c.Reset != (authkit.ResetRules{}) {
		t.Fatalf("zero Config defaults = %+v; want the specified defaults", c)
	}
	k := Config{HashWait: time.Second, HashConcurrency: 2, ResetTTL: time.Minute}.withDefaults()
	if k.HashWait != time.Second || k.HashConcurrency != 2 || k.ResetTTL != time.Minute {
		t.Fatalf("set fields = %+v; want HashWait 1s, HashConcurrency 2, ResetTTL 1m kept", k)
	}
}
