package authkit_test

import (
	"testing"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/internal/kittest"
)

type world struct{ *kittest.World }

func newWorld(t *testing.T, tweaks ...func(*authkit.Config)) *world {
	t.Helper()
	return &world{kittest.New(t, tweaks...)}
}
