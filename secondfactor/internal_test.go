package secondfactor

import (
	"reflect"
	"testing"
	"time"
)

func TestWithDefaultsFillSecondFactorRules(t *testing.T) {
	want := Rules{Issuer: "authkit", ChallengeTTL: 10 * time.Minute, EmailCodeTTL: 10 * time.Minute, SetupTTL: 15 * time.Minute, ResendEvery: time.Minute, Reauth: 5 * time.Minute, MaxTries: 5, MaxSends: 5, RecoveryCodes: 10}
	if got := withDefaults(Rules{}); !reflect.DeepEqual(got, want) {
		t.Errorf("withDefaults(Rules{}) = %+v, want %+v", got, want)
	}
	set := Rules{Key: []byte("0123456789abcdef0123456789abcdef"), Issuer: "Ino Tasks", ChallengeTTL: time.Minute, EmailCodeTTL: 2 * time.Minute, SetupTTL: 3 * time.Minute, ResendEvery: 30 * time.Second, Reauth: 4 * time.Minute, MaxTries: 3, MaxSends: 2, RecoveryCodes: 12}
	if got := withDefaults(set); !reflect.DeepEqual(got, set) {
		t.Errorf("withDefaults kept SecondFactors = %+v, want the set values %+v", got, set)
	}
}
