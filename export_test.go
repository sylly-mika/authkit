package authkit

import "context"

func SetVerifyHook(s *Service, f func()) { s.onVerify = f }

func HoldHashSlot(ctx context.Context, s *Service) (release func(), err error) {
	return s.hasher.Acquire(ctx)
}
