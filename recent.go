package authkit

import (
	"context"
	"errors"
	"time"

	"github.com/sylly-mika/authkit/db"
)

// RequireRecent refuses with ErrReauthRequired unless the caller's session authenticated within window; zero window means Config.Recent.
func (s *Service) RequireRecent(ctx context.Context, q db.Querier, cl *Claims, window time.Duration) (Result, error) {
	if window == 0 {
		window = s.cfg.Recent
	}
	now := s.now()
	sess, err := s.core().LockSession(ctx, q, cl, now)
	if errors.Is(err, db.ErrNoRows) {
		return Result{Refusal: ErrSessionEnded}, nil
	}
	if err != nil {
		return Result{}, err
	}
	if now.Sub(sess.AuthenticatedAt) > window {
		return Result{Refusal: ErrReauthRequired}, nil
	}
	return Result{Principal: Principal{ID: cl.Subject}}, nil
}
