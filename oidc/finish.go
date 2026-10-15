package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

// claims is the part of an ID token, and of the provider's user fields, that Finish reads.
type claims struct {
	Email         string    `json:"email"`
	EmailVerified *flexBool `json:"email_verified"`
	PrivateEmail  *flexBool `json:"is_private_email"`
	AZP           string    `json:"azp"`
	Name          string    `json:"name"`
	GivenName     string    `json:"given_name"`
	FamilyName    string    `json:"family_name"`
}

// Finish checks the provider's callback against the ceremony Begin stored, and answers the sign-in it names. A refused callback is a Result with a nil error, so the caller commits the spent ceremony. A first sign-in with no account returns the SignUp whose Ticket redeems it.
func (m *Module) Finish(ctx context.Context, q db.Querier, cb Callback, binding string, meta authkit.Meta) (authkit.Result, *SignUp, error) {
	qc := m.core.Q(q)
	if err := db.RequireTx(qc); err != nil {
		return authkit.Result{}, nil, err
	}
	now := m.core.Now()
	c, err := spendCeremony(ctx, qc, digest(cb.State), now)
	if err != nil {
		return authkit.Result{}, nil, err
	}
	if c == nil {
		return refuseBad(ctx, q, m.core.BeginVerified(authkit.SourceOIDC, "", meta))
	}
	a := m.core.BeginVerified(authkit.SourceOIDC, c.audience, meta)
	now = a.Now()
	aud := c.audience
	p, ok := m.providers[c.provider]
	if !ok {
		return refuseBad(ctx, q, a)
	}
	if subtle.ConstantTimeCompare(digest(binding), c.bindingHash) != 1 {
		return refuseBad(ctx, q, a)
	}
	if cb.Error == "user_cancelled_authorize" || cb.Error == "access_denied" {
		return authkit.Result{Refusal: ErrCancelled}, nil, nil
	}
	if cb.Error != "" || cb.Code == "" {
		return refuseBad(ctx, q, a)
	}
	secret := p.ClientSecret
	if p.Secret != nil {
		s, err := p.Secret(now)
		if err != nil {
			return refuseBad(ctx, q, a)
		}
		secret = s
	}
	cfg := p.config()
	cfg.ClientSecret = secret
	xctx := context.WithValue(ctx, oauth2.HTTPClient, m.client)
	// WHY: the exchange error can carry the provider's response body, which may echo the secret or the code, so it is dropped unread.
	tok, err := cfg.Exchange(xctx, cb.Code, oauth2.VerifierOption(c.verifier))
	if err != nil {
		return refuseBad(ctx, q, a)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return refuseBad(ctx, q, a)
	}
	verifier := gooidc.NewVerifier("", p.keys, &gooidc.Config{
		ClientID:             p.ClientID,
		SupportedSigningAlgs: []string{gooidc.RS256},
		SkipIssuerCheck:      true,
		Now:                  func() time.Time { return now },
	})
	idTok, err := verifier.Verify(xctx, raw)
	if err != nil {
		return refuseBad(ctx, q, a)
	}
	var cl claims
	if err := idTok.Claims(&cl); err != nil {
		return refuseBad(ctx, q, a)
	}
	if !slices.Contains(p.Issuers, idTok.Issuer) ||
		(cl.AZP != "" || len(idTok.Audience) > 1) && cl.AZP != p.ClientID ||
		idTok.Nonce == "" || subtle.ConstantTimeCompare(digest(idTok.Nonce), c.nonceHash) != 1 ||
		idTok.IssuedAt.After(now.Add(m.rules.Skew)) ||
		idTok.Subject == "" {
		return refuseBad(ctx, q, a)
	}
	if c.kind != "signin" {
		return refuseBad(ctx, q, a)
	}
	sub := idTok.Subject
	verified := cl.EmailVerified != nil && bool(*cl.EmailVerified)

	id, found, err := findIdentity(ctx, qc, c.provider, sub)
	if err != nil {
		return authkit.Result{}, nil, err
	}
	if found {
		who, err := m.core.Principals().ByID(ctx, q, id, aud)
		if errors.Is(err, authkit.ErrUnknownLogin) {
			return refuseBad(ctx, q, a)
		}
		if err != nil {
			return authkit.Result{}, nil, err
		}
		a.SetPrincipal(&who)
		if p.SkipSecondFactor {
			a.SkipSecondFactor()
		}
		a.Commit(func(ctx context.Context, q db.Querier) error {
			return touchIdentity(ctx, q, c.provider, sub, now)
		})
		res, err := m.core.SignIn(ctx, q, a, who, authkit.FactorOIDC)
		return res, nil, err
	}
	if !verified || cl.Email == "" {
		return authkit.Result{Refusal: ErrEmailUnverified}, nil, nil
	}
	_, err = m.core.Principals().Lookup(ctx, q, authkit.Normalize(cl.Email), aud)
	if err == nil {
		return authkit.Result{Refusal: ErrSignInToLink}, nil, nil
	}
	if !errors.Is(err, authkit.ErrUnknownLogin) {
		return authkit.Result{}, nil, err
	}

	ticket, err := randomToken(m.core.Rand())
	if err != nil {
		return authkit.Result{}, nil, err
	}
	s := &SignUp{
		Ticket:       ticket,
		Provider:     c.provider,
		Email:        cl.Email,
		Name:         cl.Name,
		GivenName:    cl.GivenName,
		FamilyName:   cl.FamilyName,
		PrivateEmail: cl.PrivateEmail != nil && bool(*cl.PrivateEmail),
	}
	var user struct {
		Name struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"name"`
	}
	if json.Unmarshal([]byte(cb.User), &user) == nil {
		if s.GivenName == "" {
			s.GivenName = user.Name.FirstName
		}
		if s.FamilyName == "" {
			s.FamilyName = user.Name.LastName
		}
	}
	if s.Name == "" {
		s.Name = strings.TrimSpace(s.GivenName + " " + s.FamilyName)
	}
	ticketID, err := uuid.NewRandomFromReader(m.core.Rand())
	if err != nil {
		return authkit.Result{}, nil, err
	}
	if err := insertSignup(ctx, qc, ticketID, digest(ticket), s, sub, aud, now, now.Add(m.rules.CeremonyTTL)); err != nil {
		return authkit.Result{}, nil, err
	}
	return authkit.Result{Refusal: ErrIdentityUnknown}, s, nil
}

// refuseBad records the callback as a bad identity on a and refuses it with no detail.
func refuseBad(ctx context.Context, q db.Querier, a *authkit.Attempt) (authkit.Result, *SignUp, error) {
	res, err := a.Refuse(ctx, q, authkit.ResultBadIdentity, authkit.ErrInvalidCredentials)
	return res, nil, err
}
