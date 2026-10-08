package authkit

import "context"

// SetVerifyHook calls f before every argon2id verification Login,
// ChangePassword and VerifyPassword run, the dummy included.
func SetVerifyHook(s *Service, f func()) { s.onVerify = f }

// HoldHashSlot takes one of the Service's hash slots until release.
func HoldHashSlot(ctx context.Context, s *Service) (release func(), err error) {
	return s.hasher.Acquire(ctx)
}
