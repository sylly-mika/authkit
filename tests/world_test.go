package tests

import (
	"testing"

	"github.com/sylly-mika/authkit/internal/kittest"
)

type world struct{ *kittest.World }

func newWorld(t *testing.T, tweaks ...func(*kittest.Rules)) *world {
	t.Helper()
	return &world{kittest.New(t, tweaks...)}
}
