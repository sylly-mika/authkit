package tests

import (
	"errors"
	"testing"

	"github.com/sylly-mika/authkit"
)

func TestAttachTwice(t *testing.T) {
	w := newWorld(t)
	svc, err := authkit.New(w.Cfg, w.P)
	if err != nil {
		t.Fatal(err)
	}
	core, err := svc.Attach("password")
	if core == nil || err != nil {
		t.Fatalf("first Attach = %v, %v; want a Core and no error", core, err)
	}
	again, err := svc.Attach("password")
	if again != nil || !errors.Is(err, authkit.ErrAttached) {
		t.Fatalf("second Attach = %v, %v; want nil and ErrAttached", again, err)
	}
	if other, err := svc.Attach("passkey"); other == nil || err != nil {
		t.Fatalf("Attach passkey = %v, %v; want a Core and no error", other, err)
	}
}

func TestAttachNames(t *testing.T) {
	w := newWorld(t)
	first, err := authkit.New(w.Cfg, w.P)
	if err != nil {
		t.Fatal(err)
	}
	second, err := authkit.New(w.Cfg, w.P)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"password", "passkey", "secondfactor"} {
		if c, err := first.Attach(name); c == nil || err != nil {
			t.Fatalf("Attach %q = %v, %v; want a Core and no error", name, c, err)
		}
	}
	if c, err := first.Attach(""); c != nil || err == nil || errors.Is(err, authkit.ErrAttached) {
		t.Fatalf("Attach \"\" = %v, %v; want nil and an error other than ErrAttached", c, err)
	}
	if c, err := second.Attach("password"); c == nil || err != nil {
		t.Fatalf("second Service Attach password = %v, %v; want a Core: the registry is per Service", c, err)
	}
}
