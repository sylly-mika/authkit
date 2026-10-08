package authkit

import (
	"context"
	"time"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/events"
	"github.com/sylly-mika/authkit/session"
	"github.com/sylly-mika/authkit/throttle"
)

const retention = 30 * 24 * time.Hour

// Prune deletes what no flow reads any more (spec §6): throttle counters
// whose window and lock have passed, sessions and one-time links dead for 30
// days, and sign-in events older than EventRetention unless it is negative.
// The app's worker runs it with no workspace bound.
func (s *Service) Prune(ctx context.Context, q db.Querier) error {
	if err := db.RequireTx(q); err != nil {
		return err
	}
	now := s.now()
	if _, err := throttle.Prune(ctx, q, now, s.cfg.Throttle); err != nil {
		return err
	}
	if _, err := session.Prune(ctx, q, now.Add(-retention)); err != nil {
		return err
	}
	if s.cfg.EventRetention > 0 {
		if _, err := events.Prune(ctx, q, now.Add(-s.cfg.EventRetention)); err != nil {
			return err
		}
	}
	_, err := s.links.Prune(ctx, q, now.Add(-retention))
	return err
}
