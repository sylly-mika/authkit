package authkit_test

import (
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

const modulePath = "github.com/sylly-mika/authkit"

func TestModuleDeps(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go is not on PATH, so go list -deps cannot run: %v", err)
	}
	heavy := []string{"github.com/go-webauthn/", "github.com/pquerna/otp", "github.com/coreos/go-oidc", "go-jose"}
	cases := []struct {
		name   string
		pkg    string
		forbid []string
		want   string
	}{
		{"authkit", modulePath, heavy, "github.com/google/uuid"},
		{"password", modulePath + "/password", heavy, "golang.org/x/crypto/argon2"},
		{"passkey", modulePath + "/passkey", []string{"github.com/pquerna/otp", "github.com/coreos/go-oidc", "go-jose"}, "github.com/go-webauthn/webauthn/webauthn"},
		{"secondfactor", modulePath + "/secondfactor", []string{"github.com/go-webauthn/", "github.com/coreos/go-oidc", "go-jose"}, "github.com/pquerna/otp/totp"},
		{"oidc", modulePath + "/oidc", []string{"github.com/go-webauthn/", "github.com/pquerna/otp"}, "github.com/coreos/go-oidc/v3/oidc"},
		{"register", modulePath + "/register", heavy, "golang.org/x/crypto/argon2"},
		{"authkittest", modulePath + "/authkittest", []string{"github.com/coreos/go-oidc", "go-jose"}, "github.com/lib/pq"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := goListDeps(t, tc.pkg)
			if !slices.Contains(deps, tc.pkg) || !slices.Contains(deps, tc.want) {
				t.Fatalf("go list -deps %s lists %d packages, without %s or %s", tc.pkg, len(deps), tc.pkg, tc.want)
			}
			for _, d := range deps {
				for _, f := range tc.forbid {
					if strings.Contains(d, f) {
						t.Errorf("%s depends on %s", tc.pkg, d)
					}
				}
			}
		})
	}
}

func goListDeps(t *testing.T, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("go list -deps %s: %v\n%s", pkg, err, ee.Stderr)
		}
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	return strings.Fields(string(out))
}
