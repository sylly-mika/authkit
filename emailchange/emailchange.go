package emailchange

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/pending"
	"github.com/sylly-mika/authkit/onetime"
)

const (
	defaultTTL = 24 * time.Hour
	startCap   = 3
	capWindow  = time.Hour
)

// Rules configures the email change module.
type Rules struct {
	// TTL is how long a change and its link stay valid. Zero is 24 hours.
	TTL time.Duration
	// Change sets the principal's login to newLogin when a change is confirmed.
	Change func(ctx context.Context, q db.Querier, p authkit.Principal, newLogin string) error
	// RevokeAll ends every session of the principal at confirm, the starter's too.
	RevokeAll bool
}

// Started is what Start and StartFor return.
type Started struct {
	authkit.Result
	// TokenID is the new link's id, for Mint at send time; nil when nothing was started.
	TokenID *uuid.UUID
	// Old is the principal's login when the change was asked for.
	Old string
	// AddressHeld says another principal holds the new address; nothing was written.
	AddressHeld bool
	// RetryAfter is how long until another change may start.
	RetryAfter time.Duration
}

// Mail is what the app needs to send the confirmation link to the new address.
type Mail struct {
	To, Raw, Old string
	ExpiresAt    time.Time
}

// Changed is what Confirm returns; Old is the address to notify.
type Changed struct {
	authkit.Result
	Old, New string
}

// Pending is a principal's unconfirmed change.
type Pending struct {
	Old, New  string
	ExpiresAt time.Time
}

// Module is the email change module attached to one Service.
type Module struct {
	svc        *authkit.Service
	core       *authkit.Core
	links      *onetime.Store
	principals authkit.Principals
	r          Rules
}

// New attaches the email change module.
func New(svc *authkit.Service, r Rules) (*Module, error) {
	if r.Change == nil {
		return nil, errors.New("emailchange: Rules.Change is nil")
	}
	if r.TTL < 0 {
		return nil, errors.New("emailchange: Rules.TTL is negative")
	}
	if r.TTL == 0 {
		r.TTL = defaultTTL
	}
	core, err := svc.Attach("emailchange")
	if err != nil {
		return nil, err
	}
	return &Module{svc: svc, core: core, links: svc.OneTime(), principals: core.Principals(), r: r}, nil
}

// Start records a change for the signed-in principal; its session must be recent.
func (m *Module) Start(ctx context.Context, q db.Querier, cl *authkit.Claims, newEmail string) (Started, error) {
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return Started{}, err
	}
	res, err := m.svc.RequireRecent(ctx, q, cl, 0)
	if err != nil || res.Refusal != nil {
		return Started{Result: res}, err
	}
	sess, err := m.core.LockSession(ctx, q, cl, m.core.Now())
	if err != nil {
		return Started{}, err
	}
	aud := authkit.Audience(sess.Audience)
	p, err := m.principals.ByID(ctx, q, cl.Subject, aud)
	if err != nil {
		return Started{}, err
	}
	return m.start(ctx, q, p, aud, newEmail, &sess.ID)
}

// StartFor records a change an admin asked for; the new address must still confirm it.
func (m *Module) StartFor(ctx context.Context, q db.Querier, p authkit.Principal, aud authkit.Audience, newEmail string) (Started, error) {
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return Started{}, err
	}
	p, err := m.principals.ByID(ctx, q, p.ID, aud)
	if err != nil {
		return Started{}, err
	}
	return m.start(ctx, q, p, aud, newEmail, nil)
}

func (m *Module) start(ctx context.Context, q db.Querier, p authkit.Principal, aud authkit.Audience, newEmail string, sessionID *uuid.UUID) (Started, error) {
	now := m.core.Now()
	n := authkit.Normalize(newEmail)
	if n == authkit.Normalize(p.Login) {
		return Started{Result: authkit.Result{Principal: p, Refusal: ErrSameAddress}}, nil
	}
	if err := m.links.Lock(ctx, q, authkit.PurposeEmailChange, p.ID); err != nil {
		return Started{}, err
	}
	since := now.Add(-capWindow)
	count, err := m.links.CreatedSince(ctx, q, authkit.PurposeEmailChange, p.ID, since)
	if err != nil {
		return Started{}, err
	}
	if count >= startCap {
		var oldest time.Time
		if err := q.QueryRow(ctx, `SELECT min(created_at) FROM auth_tokens WHERE purpose = $1 AND owner_id = $2 AND created_at > $3`,
			authkit.PurposeEmailChange, p.ID, since).Scan(&oldest); err != nil {
			return Started{}, err
		}
		return Started{Result: authkit.Result{Principal: p}, Old: p.Login, RetryAfter: oldest.Add(capWindow).Sub(now)}, nil
	}
	_, err = m.principals.Lookup(ctx, q, n, aud)
	switch {
	case err == nil:
		return Started{Result: authkit.Result{Principal: p}, Old: p.Login, AddressHeld: true}, nil
	case !errors.Is(err, authkit.ErrUnknownLogin):
		return Started{}, err
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO auth_email_changes (principal_id, audience, old_email, new_email, session_id, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (principal_id) DO UPDATE SET
		  audience = EXCLUDED.audience, old_email = EXCLUDED.old_email, new_email = EXCLUDED.new_email,
		  session_id = EXCLUDED.session_id, created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at`,
		p.ID, string(aud), authkit.Normalize(p.Login), n, sessionID, now, now.Add(m.r.TTL)); err != nil {
		return Started{}, err
	}
	id, err := m.links.Create(ctx, q, authkit.PurposeEmailChange, p.ID, m.r.TTL)
	if err != nil {
		return Started{}, err
	}
	return Started{Result: authkit.Result{Principal: p}, TokenID: &id, Old: p.Login}, nil
}

// Mint makes the raw confirmation link for a started change.
func (m *Module) Mint(ctx context.Context, q db.Querier, tokenID uuid.UUID) (Mail, error) {
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return Mail{}, err
	}
	now := m.core.Now()
	var owner uuid.UUID
	err := q.QueryRow(ctx, `SELECT owner_id FROM auth_tokens WHERE id = $1 AND purpose = $2`,
		tokenID, authkit.PurposeEmailChange).Scan(&owner)
	switch {
	case errors.Is(err, db.ErrNoRows):
		return Mail{}, ErrNothingToSend
	case err != nil:
		return Mail{}, err
	}
	var oldEmail, newEmail string
	var expires time.Time
	err = q.QueryRow(ctx, `SELECT old_email, new_email, expires_at FROM auth_email_changes WHERE principal_id = $1 AND expires_at > $2 FOR UPDATE`,
		owner, now).Scan(&oldEmail, &newEmail, &expires)
	switch {
	case errors.Is(err, db.ErrNoRows):
		return Mail{}, ErrNothingToSend
	case err != nil:
		return Mail{}, err
	}
	mt, ok, err := pending.Mint(ctx, q, m.links, tokenID, expires)
	switch {
	case err != nil:
		return Mail{}, err
	case !ok:
		return Mail{}, ErrNothingToSend
	}
	return Mail{To: newEmail, Raw: mt.Raw, Old: oldEmail, ExpiresAt: mt.ExpiresAt}, nil
}

// Cancel drops a principal's pending change and its link.
func (m *Module) Cancel(ctx context.Context, q db.Querier, p authkit.Principal) error {
	q = m.core.Q(q)
	if err := db.RequireTx(q); err != nil {
		return err
	}
	if err := m.links.Lock(ctx, q, authkit.PurposeEmailChange, p.ID); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `DELETE FROM auth_email_changes WHERE principal_id = $1`, p.ID); err != nil {
		return err
	}
	return m.links.Revoke(ctx, q, authkit.PurposeEmailChange, p.ID)
}

// Pending returns the principal's unconfirmed change, or nil.
func (m *Module) Pending(ctx context.Context, q db.Querier, p authkit.Principal) (*Pending, error) {
	q = m.core.Q(q)
	var pd Pending
	err := q.QueryRow(ctx, `SELECT old_email, new_email, expires_at FROM auth_email_changes WHERE principal_id = $1 AND expires_at > $2`,
		p.ID, m.core.Now()).Scan(&pd.Old, &pd.New, &pd.ExpiresAt)
	switch {
	case errors.Is(err, db.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return &pd, nil
}

var (
	// ErrSameAddress reports a new address equal to the current login.
	ErrSameAddress = errors.New("emailchange: that is already the address")
	// ErrAddressHeld reports, at confirm, that another principal took the new address meanwhile.
	ErrAddressHeld = errors.New("emailchange: address already has an account")
	// ErrStale reports that the principal's login changed after the change was started.
	ErrStale = errors.New("emailchange: the account changed since this link was sent")
	// ErrNothingToSend reports that Mint found no live change or link for the token.
	ErrNothingToSend = errors.New("emailchange: nothing to send")
)
