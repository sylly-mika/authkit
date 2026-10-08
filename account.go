package authkit

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/events"
	"github.com/sylly-mika/authkit/session"
)

// ListSessions is the caller's open sessions, newest first, with the one the
// token names marked Current, and their count. A bare pinned connection is fine.
func (s *Service) ListSessions(ctx context.Context, q db.Querier, c *Claims, limit, offset int) ([]Session, int, error) {
	list, total, err := session.ListOpen(ctx, q, c.Subject, s.now(), limit, offset)
	for i := range list {
		list[i].Current = list[i].ID == c.SessionID
	}
	return list, total, err
}

// RevokeSession ends one of the caller's own open sessions and logs revoked
// with the caller's scope; ErrSessionEnded when there is no such open session.
func (s *Service) RevokeSession(ctx context.Context, q db.Querier, c *Claims, id uuid.UUID, m Meta) (Result, error) {
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	m = m.clean()
	now := s.now()
	revoked, err := session.RevokeOpen(ctx, q, id, c.Subject, ReasonUser, now)
	if err != nil {
		return Result{}, err
	}
	if !revoked {
		return Result{Refusal: ErrSessionEnded}, nil
	}
	caller, err := session.Load(ctx, q, c.SessionID, c.Subject)
	if err != nil {
		return Result{}, err
	}
	return Result{}, s.record(ctx, q, now, SourceRevokeSession, events.Event{PrincipalID: &c.Subject, SessionID: &id, ScopeID: caller.ScopeID,
		Audience: c.Audience, Result: ResultRevoked, IP: m.IP, UserAgent: m.UserAgent})
}

// ListEvents is the principal's sign-in log, newest first, without the
// excluded results, and its count (ino-tasks excludes locked and
// reuse_detected until its admin labels them). A bare pinned connection is fine.
func (s *Service) ListEvents(ctx context.Context, q db.Querier, principal uuid.UUID, exclude []string, limit, offset int) ([]Event, int, error) {
	for _, r := range exclude {
		if r == "" || strings.Contains(r, ",") {
			return nil, 0, fmt.Errorf("authkit: %q is not a result name", r)
		}
	}
	return events.List(ctx, q, principal, exclude, limit, offset)
}
