// Package echov5 mounts authkit on echo v5. In Bearer mode ParseBearer and
// Guard sit around the app's own connection middleware (ino-tasks:
// WorkspaceRLS between them). In Session mode SessionCookie loads the
// session, RequireSession and RequireOrigin guard each route, and HashSlot
// holds a hash slot before the app's transaction. RateLimit is the per-IP
// limiter for the auth routes. Refusals come back as authkit's sentinels for
// the app's error handler to render.
package echov5

import (
	"errors"
	"fmt"

	"github.com/labstack/echo/v5"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/transport/bearer"
)

const (
	claimsKey    = "authkit.claims"
	admissionKey = "authkit.admission"
)

// ParseBearer admits a request carrying a strict, valid access token of aud
// and puts its claims on the context. A valid token of another audience is
// authkit.ErrWrongAudience; any other failure ErrMissingToken or
// ErrInvalidToken. It reads no database. A Session-mode Service has no codec:
// every request is then a server error.
func ParseBearer(s *authkit.Service, aud authkit.Audience) echo.MiddlewareFunc {
	codec := s.Codec()
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if codec == nil {
				return errors.New("authkit: ParseBearer needs a Bearer-mode Service")
			}
			raw, err := bearer.FromHeader(c.Request().Header.Get("Authorization"))
			if err != nil {
				return err
			}
			claims, err := codec.Parse(raw, string(aud))
			if err != nil {
				return err
			}
			c.Set(claimsKey, claims)
			return next(c)
		}
	}
}

// Guard admits a request only while its session is open and Admit grants
// exactly the token's claims (spec §8.5), checked on the querier the app
// supplies for the request. It puts the Admission on the context. A refusal
// is authkit.ErrSessionEnded or authkit.ErrStale itself; a missing
// ParseBearer or querier, or a database failure, is any other error, for the
// app to render as a 500.
func Guard(s *authkit.Service, querier func(*echo.Context) db.Querier) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			claims := Claims(c)
			if claims == nil {
				return errors.New("authkit: Guard must run after ParseBearer")
			}
			q := querier(c)
			if q == nil {
				return errors.New("authkit: Guard has no querier for this request")
			}
			res, err := s.Authenticate(c.Request().Context(), q, claims)
			if err != nil {
				return fmt.Errorf("authkit: guard: %w", err)
			}
			if res.Refusal != nil {
				return res.Refusal
			}
			c.Set(admissionKey, *res.Admission)
			return next(c)
		}
	}
}

// Claims is the request's parsed access token, or nil before ParseBearer.
func Claims(c *echo.Context) *authkit.Claims {
	claims, _ := c.Get(claimsKey).(*authkit.Claims)
	return claims
}

// Admission is what Admit granted this request; false before Guard admitted it.
func Admission(c *echo.Context) (authkit.Admission, bool) {
	adm, ok := c.Get(admissionKey).(authkit.Admission)
	return adm, ok
}
