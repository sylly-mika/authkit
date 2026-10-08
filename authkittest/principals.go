package authkittest

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// NoMembership is the result Principals refuses with, ino-tasks' own.
const NoMembership = "no_membership"

// Principals is an authkit.Principals over the harness users table. Admit
// binds a login to Scope and grants {"ws": scope, "role": role}, with ws a
// uuid.UUID on purpose so the claim comparison's JSON round trip is exercised.
type Principals struct {
	Scope   uuid.UUID
	mu      sync.Mutex
	refused map[uuid.UUID]error
	roles   map[uuid.UUID]string
	extra   map[string]any
}

func NewPrincipals() *Principals {
	return &Principals{Scope: uuid.New(), refused: map[uuid.UUID]error{}, roles: map[uuid.UUID]string{}, extra: map[string]any{}}
}

// Refuse makes Admit refuse id with err, as an app refuses a deactivated member.
func (p *Principals) Refuse(id uuid.UUID, err error) { p.mu.Lock(); p.refused[id] = err; p.mu.Unlock() }
func (p *Principals) Allow(id uuid.UUID)             { p.mu.Lock(); delete(p.refused, id); p.mu.Unlock() }
func (p *Principals) SetRole(id uuid.UUID, role string) {
	p.mu.Lock()
	p.roles[id] = role
	p.mu.Unlock()
}

// SetClaim adds a claim to every admission.
func (p *Principals) SetClaim(name string, v any) { p.mu.Lock(); p.extra[name] = v; p.mu.Unlock() }

func (p *Principals) Lookup(ctx context.Context, q db.Querier, login string, _ authkit.Audience) (authkit.Principal, error) {
	return lookup(ctx, q, `SELECT id, email FROM users WHERE email = $1`, login)
}

func (p *Principals) ByID(ctx context.Context, q db.Querier, id uuid.UUID, _ authkit.Audience) (authkit.Principal, error) {
	return lookup(ctx, q, `SELECT id, email FROM users WHERE id = $1`, id)
}

func lookup(ctx context.Context, q db.Querier, query string, arg any) (authkit.Principal, error) {
	var out authkit.Principal
	err := q.QueryRow(ctx, query, arg).Scan(&out.ID, &out.Login)
	if errors.Is(err, db.ErrNoRows) {
		return authkit.Principal{}, authkit.ErrUnknownLogin
	}
	return out, err
}

func (p *Principals) Admit(_ context.Context, _ db.Querier, prop authkit.Proposal) (authkit.Admission, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err, ok := p.refused[prop.Principal.ID]; ok {
		return authkit.Admission{}, authkit.Refuse(NoMembership, err)
	}
	scope := p.Scope
	if prop.ScopeID != nil {
		scope = *prop.ScopeID
	}
	role := p.roles[prop.Principal.ID]
	if role == "" {
		role = "member"
	}
	claims := map[string]any{"ws": scope, "role": role}
	for k, v := range p.extra {
		claims[k] = v
	}
	return authkit.Admission{ScopeID: &scope, Claims: claims, Context: role}, nil
}
