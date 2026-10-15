// Package register is self-service registration: a pending row and a one-time link per address, mail counts, and the link minted at send time.
package register

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/onetime"
	"github.com/sylly-mika/authkit/password"
)

// Rules configures registration. A zero field takes its default.
type Rules struct {
	// TTL is how long a registration and its link stay valid. Zero is 48 hours.
	TTL time.Duration
	// MailCap is how many activation mails one address may get per MailWindow. Zero is 3.
	MailCap int
	// MailWindow is the span the mail cap counts over; at most 24 hours. Zero is 1 hour.
	MailWindow time.Duration
	// Floor is the minimum time the app's register handler takes. Zero is 500 milliseconds.
	Floor time.Duration
	// Create makes the principal when a registration is activated.
	Create func(ctx context.Context, q db.Querier, p Pending) (authkit.Principal, error)
}

// Pending is a registration waiting for its link.
type Pending struct {
	ID        uuid.UUID
	Audience  authkit.Audience
	Email     string
	Payload   json.RawMessage
	CreatedAt time.Time
}

// Started says what Start decided; exactly one field is set.
type Started struct {
	// TokenID is the new link's id, for Mint at send time.
	TokenID *uuid.UUID
	// Holder is the principal already holding the address.
	Holder *authkit.Principal
	// RetryAfter is how long to wait before the next mail to the address.
	RetryAfter time.Duration
}

// Module is the registration module attached to one Service.
type Module struct {
	core       *authkit.Core
	pw         *password.Module
	links      *onetime.Store
	principals authkit.Principals
	r          Rules
}

// ErrAddressHeld says a principal holds the address already.
var ErrAddressHeld = errors.New("register: address already held")

// New attaches the registration module to svc as "register"; pw sets the password at activation.
func New(svc *authkit.Service, pw *password.Module, r Rules) (*Module, error) {
	if r.Create == nil {
		return nil, errors.New("register: Rules.Create is nil")
	}
	if pw == nil {
		return nil, errors.New("register: the password module is nil")
	}
	negative := []struct {
		name string
		bad  bool
	}{{"TTL", r.TTL < 0}, {"MailCap", r.MailCap < 0}, {"MailWindow", r.MailWindow < 0}, {"Floor", r.Floor < 0}}
	for _, c := range negative {
		if c.bad {
			return nil, fmt.Errorf("register: Rules.%s is negative", c.name)
		}
	}
	if r.MailWindow > 24*time.Hour {
		return nil, errors.New("register: Rules.MailWindow is longer than 24h")
	}
	if r.TTL == 0 {
		r.TTL = 48 * time.Hour
	}
	if r.MailCap == 0 {
		r.MailCap = 3
	}
	if r.MailWindow == 0 {
		r.MailWindow = time.Hour
	}
	if r.Floor == 0 {
		r.Floor = 500 * time.Millisecond
	}
	core, err := svc.Attach("register")
	if err != nil {
		return nil, err
	}
	return &Module{core: core, pw: pw, links: svc.OneTime(), principals: core.Principals(), r: r}, nil
}

// Floor is the minimum time the app's register handler takes.
func (m *Module) Floor() time.Duration { return m.r.Floor }
