package secondfactor_test

import (
	"errors"
	"testing"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/secondfactor"
)

func newSecondFactorTestService(t *testing.T) *authkit.Service {
	t.Helper()
	svc, err := authkit.New(authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}, authkittest.NewPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestNewRefusesRulesAndKeepsTheNameFree(t *testing.T) {
	svc := newSecondFactorTestService(t)
	bad, err := secondfactor.New(svc, secondfactor.Rules{Key: make([]byte, 31)})
	if bad != nil || err == nil || err.Error() != "authkit: Config.SecondFactors.Key must be 32 bytes, not 31" {
		t.Fatalf("refused New = %v, %v; want nil and the 32-byte refusal", bad, err)
	}
	good, err := secondfactor.New(svc, secondfactor.Rules{Key: make([]byte, 32)})
	if good == nil || err != nil {
		t.Fatalf("New after a refusal = %v, %v; want a module and nil", good, err)
	}
	again, err := secondfactor.New(svc, secondfactor.Rules{})
	if again != nil || !errors.Is(err, authkit.ErrAttached) {
		t.Fatalf("second New = %v, %v; want nil and ErrAttached", again, err)
	}
}
