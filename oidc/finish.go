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
	ck, err := m.checkCallback(ctx, c, cb, binding, now)
	if errors.Is(err, ErrCancelled) {
		return authkit.Result{Refusal: ErrCancelled}, nil, nil
	}
	if err != nil {
		return refuseBad(ctx, q, a)
	}
	p, cl, sub := ck.p, ck.cl, ck.tok.Subject
	if c.kind == "link" {
		who, err := m.core.Principals().ByID(ctx, q, c.principal.UUID, aud)
		if errors.Is(err, authkit.ErrUnknownLogin) {
			return refuseBad(ctx, q, a)
		}
		if err != nil {
			return authkit.Result{}, nil, err
		}
		linked, err := linkIdentity(ctx, qc, uuid.New(), who.ID, c.provider, sub, cl.Email, now)
		if err != nil {
			return authkit.Result{}, nil, err
		}
		if !linked {
			return authkit.Result{Refusal: ErrIdentityTaken}, nil, nil
		}
		ev := authkit.Event{PrincipalID: &who.ID, Audience: string(aud), Login: who.Login, Result: authkit.ResultIdentityLinked, IP: meta.IP, UserAgent: meta.UserAgent}
		if err := m.core.Record(ctx, q, authkit.SourceOIDC, ev); err != nil {
			return authkit.Result{}, nil, err
		}
		return authkit.Result{Principal: who}, nil, nil
	}
	if c.kind != "signin" {
		return refuseBad(ctx, q, a)
	}
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

var errBadIdentity = errors.New("oidc: bad identity")

type checked struct {
	p   *provider
	tok *gooidc.IDToken
	cl  claims
}

func (m *Module) checkCallback(ctx context.Context, c *ceremony, cb Callback, binding string, now time.Time) (checked, error) {
	p, ok := m.providers[c.provider]
	if !ok {
		return checked{}, errBadIdentity
	}
	if subtle.ConstantTimeCompare(digest(binding), c.bindingHash) != 1 {
		return checked{}, errBadIdentity
	}
	if cb.Error == "user_cancelled_authorize" || cb.Error == "access_denied" {
		return checked{}, ErrCancelled
	}
	if cb.Error != "" || cb.Code == "" {
		return checked{}, errBadIdentity
	}
	secret := p.ClientSecret
	if p.Secret != nil {
		s, err := p.Secret(now)
		if err != nil {
			return checked{}, errBadIdentity
		}
		secret = s
	}
	cfg := p.config()
	cfg.ClientSecret = secret
	xctx := context.WithValue(ctx, oauth2.HTTPClient, m.client)
	// WHY: the exchange error can carry the provider's response body, which may echo the secret or the code, so it is dropped unread.
	tok, err := cfg.Exchange(xctx, cb.Code, oauth2.VerifierOption(c.verifier))
	if err != nil {
		return checked{}, errBadIdentity
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return checked{}, errBadIdentity
	}
	verifier := gooidc.NewVerifier("", p.keys, &gooidc.Config{
		ClientID:             p.ClientID,
		SupportedSigningAlgs: []string{gooidc.RS256},
		SkipIssuerCheck:      true,
		Now:                  func() time.Time { return now },
	})
	idTok, err := verifier.Verify(xctx, raw)
	if err != nil {
		return checked{}, errBadIdentity
	}
	var cl claims
	if err := idTok.Claims(&cl); err != nil {
		return checked{}, errBadIdentity
	}
	if !slices.Contains(p.Issuers, idTok.Issuer) ||
		(cl.AZP != "" || len(idTok.Audience) > 1) && cl.AZP != p.ClientID ||
		idTok.Nonce == "" || subtle.ConstantTimeCompare(digest(idTok.Nonce), c.nonceHash) != 1 ||
		idTok.IssuedAt.After(now.Add(m.rules.Skew)) ||
		idTok.Subject == "" {
		return checked{}, errBadIdentity
	}
	return checked{p: p, tok: idTok, cl: cl}, nil
}

// refuseBad records the callback as a bad identity on a and refuses it with no detail.
func refuseBad(ctx context.Context, q db.Querier, a *authkit.Attempt) (authkit.Result, *SignUp, error) {
	res, err := a.Refuse(ctx, q, authkit.ResultBadIdentity, authkit.ErrInvalidCredentials)
	return res, nil, err
}
