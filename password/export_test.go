package password

import "context"

func DummyParams(h *Hasher) (Params, error) {
	d, err := decode(h.dummy)
	return d.params, err
}

func SetVerifyHook(s *Module, f func()) { s.onVerify = f }

func HoldHashSlot(ctx context.Context, s *Module) (release func(), err error) {
	return s.hasher.Acquire(ctx)
}
