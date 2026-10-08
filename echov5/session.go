package echov5

import (
	"context"
	"fmt"

	"github.com/labstack/echo/v5"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/transport/cookie"
)

const sessionKey = "authkit.session"

// Sessions is what SessionCookie needs; *authkit.Service implements it, and a
// test fakes it.
type Sessions interface {
	AuthenticateSession(ctx context.Context, q db.Querier, aud authkit.Audience, raw string, m authkit.Meta) (authkit.Result, error)
}

// HashSlots is what HashSlot needs; *authkit.Service implements it.
type HashSlots interface {
	AcquireHashSlot(ctx context.Context) (context.Context, func(), authkit.Result, error)
}

// SessionCookie is a pass-through loader for the routes of one audience. With
// no cookie it opens no transaction. Otherwise it runs AuthenticateSession
// inside inTx (the app's hook: begin, fn, commit when fn returns nil, else
// roll back), with the request's RealIP and User-Agent. On success it sets
// the rotated cookie, if any, and stores the Result, its Claims and its
// Admission (Session, Claims, Admission read them). A refusal is committed,
// stores nothing and continues; an infrastructure error is returned wrapped
// (a 500).
func SessionCookie(s Sessions, aud authkit.Audience, opts cookie.Options, inTx func(ctx context.Context, fn func(q db.Querier) error) error) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			raw := opts.Read(c.Request())
			if raw == "" {
				return next(c)
			}
			ctx := c.Request().Context()
			m := authkit.Meta{IP: c.RealIP(), UserAgent: c.Request().UserAgent()}
			var res authkit.Result
			if err := inTx(ctx, func(q db.Querier) error {
				var err error
				res, err = s.AuthenticateSession(ctx, q, aud, raw, m)
				return err
			}); err != nil {
				return fmt.Errorf("authkit: session: %w", err)
			}
			if res.Refusal != nil {
				return next(c)
			}
			if res.SessionToken != "" {
				opts.Set(c.Response(), res.SessionToken, res.Session.AbsoluteExpiresAt)
			}
			c.Set(sessionKey, res)
			c.Set(claimsKey, res.Claims())
			c.Set(admissionKey, *res.Admission)
			return next(c)
		}
	}
}

// RequireSession is per route: with no stored session it returns
// authkit.ErrSessionEnded (render 401), first clearing the cookie the request
// carried, unless keepCookie. A request that carried none gets no Set-Cookie.
func RequireSession(opts cookie.Options, keepCookie bool) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if _, ok := Session(c); !ok {
				if !keepCookie && opts.Read(c.Request()) != "" {
					opts.Clear(c.Response())
				}
				return authkit.ErrSessionEnded
			}
			return next(c)
		}
	}
}

// RequireOrigin is cookie.RequireOrigin as middleware: cookie.ErrForeignOrigin (render 403).
func RequireOrigin(allow []string) echo.MiddlewareFunc {
	check := cookie.RequireOrigin(allow)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if err := check(c.Request()); err != nil {
				return err
			}
			return next(c)
		}
	}
}

// HashSlot holds one hash slot for the rest of the request, taken before the
// app's transaction middleware: authkit.ErrBusy (render 503) when the ceiling
// stays full.
func HashSlot(s HashSlots) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			ctx, release, res, err := s.AcquireHashSlot(c.Request().Context())
			defer release()
			if err != nil {
				return fmt.Errorf("authkit: hash slot: %w", err)
			}
			if res.Refusal != nil {
				return res.Refusal
			}
			c.SetRequest(c.Request().WithContext(ctx))
			return next(c)
		}
	}
}

// Session is the Result SessionCookie stored; false before it admitted the request.
func Session(c *echo.Context) (authkit.Result, bool) {
	res, ok := c.Get(sessionKey).(authkit.Result)
	return res, ok
}
