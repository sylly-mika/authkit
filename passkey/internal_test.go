package passkey

import (
	"testing"
	"time"
)

func TestWithDefaultsFillPasskeyRules(t *testing.T) {
	p := withDefaults(Rules{})
	if p.RPName != "authkit" || p.CeremonyTTL != 2*time.Minute || p.Reauth != 5*time.Minute || p.Max != 10 || p.RPID != "" || p.Origins != nil {
		t.Errorf("withDefaults(Rules{}) = %+v, want RPName authkit, CeremonyTTL 2m, Reauth 5m, Max 10", p)
	}
	kept := withDefaults(Rules{RPName: "ino-tasks", CeremonyTTL: time.Minute, Reauth: 3 * time.Minute, Max: 4})
	if kept.RPName != "ino-tasks" || kept.CeremonyTTL != time.Minute || kept.Reauth != 3*time.Minute || kept.Max != 4 {
		t.Errorf("withDefaults kept Passkeys = %+v, want the set values", kept)
	}
}
