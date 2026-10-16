package authkit

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/events"
	"github.com/sylly-mika/authkit/session"
)

// ListSessions is the caller's open sessions, newest first, with the one the
// token names marked Current, and their count. A bare pinned connection is fine.
func (s *Service) ListSessions(ctx context.Context, q db.Querier, c *Claims, limit, offset int) ([]Session, int, error) {
	q = s.names.Q(q)
	list, total, err := session.ListOpen(ctx, q, c.Subject, s.now(), limit, offset)
	for i := range list {
		list[i].Current = list[i].ID == c.SessionID
	}
	return list, total, err
}

// ListSessionsOf is the principal's open sessions, newest first, none marked Current, and their count; the app authorises the caller.
func (s *Service) ListSessionsOf(ctx context.Context, q db.Querier, principal uuid.UUID, limit, offset int) ([]Session, int, error) {
	return session.ListOpen(ctx, s.names.Q(q), principal, s.now(), limit, offset)
}

// RevokeSession ends one of the caller's own open sessions and logs revoked
// with the caller's scope; ErrSessionEnded when there is no such open session.
func (s *Service) RevokeSession(ctx context.Context, q db.Querier, c *Claims, id uuid.UUID, m Meta) (Result, error) {
	q = s.names.Q(q)
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
// excluded results, and its count. A bare pinned connection is fine.
func (s *Service) ListEvents(ctx context.Context, q db.Querier, principal uuid.UUID, exclude []string, limit, offset int) ([]Event, int, error) {
	q = s.names.Q(q)
	for _, r := range exclude {
		if r == "" || strings.Contains(r, ",") {
			return nil, 0, fmt.Errorf("authkit: %q is not a result name", r)
		}
	}
	return events.List(ctx, q, principal, exclude, limit, offset)
}

var revokeReasons = []string{ReasonLogout, ReasonUser, ReasonPasswordChanged, ReasonPasswordReset, ReasonReuseDetected, ReasonAdmin, ReasonPasskeyRemoved, ReasonIdentityRemoved}

// RevokeAllSessions ends every open session of the principal for reason,
// one of the revoke reasons (ReasonAdmin for an admin's action), and logs
// revoked for each. Any other reason is an error. Needs a transaction.
func (s *Service) RevokeAllSessions(ctx context.Context, q db.Querier, principal uuid.UUID, reason string, m Meta) (Result, error) {
	q = s.names.Q(q)
	if err := db.RequireTx(q); err != nil {
		return Result{}, err
	}
	if !slices.Contains(revokeReasons, reason) {
		return Result{}, fmt.Errorf("authkit: %q is not a revoke reason", reason)
	}
	m = m.clean()
	now := s.now()
	ended, err := session.RevokeOpenAll(ctx, q, principal, reason, now)
	if err != nil {
		return Result{}, err
	}
	for _, sess := range ended {
		if err := s.record(ctx, q, now, SourceRevokeAll, events.Event{PrincipalID: &principal, SessionID: &sess.ID, ScopeID: sess.ScopeID,
			Audience: sess.Audience, Result: ResultRevoked, IP: m.IP, UserAgent: m.UserAgent}); err != nil {
			return Result{}, err
		}
	}
	return Result{}, nil
}
