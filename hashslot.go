package authkit

import (
	"context"
	"errors"
)

// AcquireHashSlot takes one of the Service's argon2id slots before the app
// opens its transaction (spec §3.2). Under the returned context, Login,
// VerifyPassword, ChangePassword, CompleteReset and SetPassword hash on that
// slot and take no other, so a wait for a slot holds no connection. release
// is idempotent and always non-nil; call it when the request ends. A full
// ceiling after HashWait is Result.Refusal ErrBusy (count nothing, answer
// 503); error is only ctx's.
func (s *Service) AcquireHashSlot(ctx context.Context) (context.Context, func(), Result, error) {
	held, release, err := s.hasher.Hold(ctx)
	if errors.Is(err, ErrBusy) {
		return ctx, release, Result{Refusal: ErrBusy}, nil
	}
	if err != nil {
		return ctx, release, Result{}, err
	}
	return held, release, Result{}, nil
}
