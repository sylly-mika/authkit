// Package cookie is authkit's session-cookie transport for Session mode (P3
// spec §3.5): the HttpOnly cookie that carries the session token, and the
// Origin check that keeps another site from riding it.
package cookie

import (
	"errors"
	"net/http"
	"time"
)

// Options name the session cookie. The default is __Host-<Name>: Secure,
// HttpOnly, Path=/, no Domain.
type Options struct {
	Name     string
	SameSite http.SameSite // zero is http.SameSiteStrictMode
	Insecure bool          // dev only: plain <Name>, without the prefix and Secure
}

func (o Options) name() string {
	if o.Insecure {
		return o.Name
	}
	return "__Host-" + o.Name
}

func (o Options) cookie(value string) *http.Cookie {
	sameSite := o.SameSite
	if sameSite == 0 {
		sameSite = http.SameSiteStrictMode
	}
	return &http.Cookie{Name: o.name(), Value: value, Path: "/", Secure: !o.Insecure, HttpOnly: true, SameSite: sameSite}
}

// Set writes the session cookie. Its Max-Age runs to absoluteExpiry (the
// session's AbsoluteExpiresAt) on the server's clock; nil makes a
// browser-session cookie. The server enforces the idle timeout.
func (o Options) Set(w http.ResponseWriter, token string, absoluteExpiry *time.Time) {
	c := o.cookie(token)
	if absoluteExpiry != nil {
		c.MaxAge = max(int(time.Until(*absoluteExpiry)/time.Second), 1)
	}
	http.SetCookie(w, c)
}

// Clear deletes the cookie.
func (o Options) Clear(w http.ResponseWriter) {
	c := o.cookie("")
	c.MaxAge = -1
	http.SetCookie(w, c)
}

// Read is the request's session token, "" when it carries none.
func (o Options) Read(r *http.Request) string {
	c, err := r.Cookie(o.name())
	if err != nil {
		return ""
	}
	return c.Value
}

// ErrForeignOrigin refuses a request whose Origin is absent or not allowed (403).
var ErrForeignOrigin = errors.New("authkit: the request's Origin is absent or not allowed")

// RequireOrigin builds the check for cookie-authenticated requests: every
// method but GET, HEAD and OPTIONS needs an Origin header exactly equal to an
// entry of allow, else ErrForeignOrigin. "*" and empty entries are dropped,
// since a wildcard cannot vouch for a credentialed request; there is no
// Referer fallback.
func RequireOrigin(allow []string) func(r *http.Request) error {
	allowed := map[string]bool{}
	for _, origin := range allow {
		if origin != "" && origin != "*" {
			allowed[origin] = true
		}
	}
	return func(r *http.Request) error {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			return nil
		}
		if !allowed[r.Header.Get("Origin")] {
			return ErrForeignOrigin
		}
		return nil
	}
}
