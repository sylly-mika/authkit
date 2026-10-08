// Package bearer is authkit's access-token transport: HS256 JWTs carrying
// sub, sid, iss, aud (<issuer>:<audience>), iat and exp beside the app's own
// claims, parsed strictly (spec §8.4).
package bearer

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrMissing       = errors.New("authkit: missing or malformed bearer token")
	ErrInvalid       = errors.New("authkit: invalid or expired token")
	ErrWrongAudience = errors.New("authkit: the token belongs to another audience")
	ErrReservedClaim = errors.New("authkit: an app claim uses a registered claim's name")
)

// Reserved are the claim names the library owns.
var Reserved = []string{"sub", "sid", "iss", "aud", "iat", "exp", "nbf", "jti"}

// Claims is a parsed access token.
type Claims struct {
	Subject   uuid.UUID
	SessionID uuid.UUID
	Issuer    string
	Audience  string // the app's audience, without the issuer prefix
	IssuedAt  time.Time
	ExpiresAt time.Time
	App       map[string]any // every other claim, as JSON decoded it
}

// Codec mints and parses one issuer's access tokens under one secret.
type Codec struct {
	issuer string
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

// NewCodec refuses a setup that would mint weak tokens: an empty issuer (jwt
// then skips the issuer check), a secret under 32 bytes, a ttl that is not
// positive or a nil clock.
func NewCodec(issuer string, secret []byte, ttl time.Duration, now func() time.Time) (*Codec, error) {
	switch {
	case issuer == "":
		return nil, errors.New("bearer: the issuer is empty")
	case len(secret) < 32:
		return nil, errors.New("bearer: the secret must be at least 32 bytes")
	case ttl <= 0:
		return nil, errors.New("bearer: the access-token ttl must be positive")
	case now == nil:
		return nil, errors.New("bearer: the clock is nil")
	}
	return &Codec{issuer: issuer, secret: secret, ttl: ttl, now: now}, nil
}

// Mint signs an access token for the session sid of sub on audience, with the
// app's claims beside the registered ones, and returns it with its expiry.
func (c *Codec) Mint(sub, sid uuid.UUID, audience string, app map[string]any) (string, time.Time, error) {
	return c.MintAt(c.now(), sub, sid, audience, app)
}

// MintAt is Mint issued at now, so a caller signs at its own one instant
// (Decision P3).
func (c *Codec) MintAt(now time.Time, sub, sid uuid.UUID, audience string, app map[string]any) (string, time.Time, error) {
	if err := CheckAppClaims(app); err != nil {
		return "", time.Time{}, err
	}
	exp := jwt.NewNumericDate(now.Add(c.ttl))
	claims := jwt.MapClaims{}
	for k, v := range app {
		claims[k] = v
	}
	claims["sub"], claims["sid"], claims["iss"] = sub.String(), sid.String(), c.issuer
	claims["aud"], claims["iat"], claims["exp"] = c.issuer+":"+audience, jwt.NewNumericDate(now), exp
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(c.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("authkit: sign access token: %w", err)
	}
	return token, exp.Time, nil
}

// Parse accepts only an HS256 token under the codec's secret and issuer with
// exp, iat, aud, sub and sid present and well-formed, unexpired and not issued
// in the future. Only an otherwise valid token of another audience of the
// same issuer is ErrWrongAudience; every other failure is ErrInvalid. A
// Codec that NewCodec did not build, such as the zero value, refuses every token.
func (c *Codec) Parse(token, audience string) (*Claims, error) {
	if c.issuer == "" || len(c.secret) < 32 {
		return nil, ErrInvalid
	}
	mc := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(token, mc, func(*jwt.Token) (any, error) { return c.secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithIssuer(c.issuer),
		jwt.WithTimeFunc(c.now), jwt.WithStrictDecoding()); err != nil {
		return nil, ErrInvalid
	}
	iat, err := mc.GetIssuedAt()
	if err != nil || iat == nil {
		return nil, ErrInvalid
	}
	exp, err := mc.GetExpirationTime()
	if err != nil || exp == nil {
		return nil, ErrInvalid
	}
	sub, okSub := uuidClaim(mc, "sub")
	sid, okSid := uuidClaim(mc, "sid")
	aud, okAud := mc["aud"].(string)
	prefix := c.issuer + ":"
	if !okSub || !okSid || !okAud || !strings.HasPrefix(aud, prefix) || aud == prefix {
		return nil, ErrInvalid
	}
	if aud != prefix+audience {
		return nil, ErrWrongAudience
	}
	app := map[string]any{}
	for k, v := range mc {
		if !slices.Contains(Reserved, k) {
			app[k] = v
		}
	}
	return &Claims{Subject: sub, SessionID: sid, Issuer: c.issuer, Audience: audience,
		IssuedAt: iat.Time, ExpiresAt: exp.Time, App: app}, nil
}

func uuidClaim(mc jwt.MapClaims, name string) (uuid.UUID, bool) {
	s, ok := mc[name].(string)
	if !ok {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(s)
	return id, err == nil && id != uuid.Nil && id.String() == s
}

// FromHeader takes the token from an Authorization header: the scheme Bearer
// in any case, one space, then a non-empty token.
func FromHeader(h string) (string, error) {
	scheme, token, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", ErrMissing
	}
	return token, nil
}
