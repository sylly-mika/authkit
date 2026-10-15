package oidc

import (
	"errors"
	"net/http"
	"net/url"
)

const callbackLimit = 64 << 10

// Redirect is where Begin sends the browser and the binding cookie the app sets.
type Redirect struct {
	URL, Binding string
	SameSite     http.SameSite
}

// Callback holds the provider's answer as the browser delivered it.
type Callback struct{ State, Code, Error, User string }

// ErrBadCallback is returned for a callback ParseCallback cannot read.
var ErrBadCallback = errors.New("oidc: the callback is malformed")

// ParseCallback reads a callback from a GET query or a form POST of at most 64 KiB; call it before anything else reads the body.
func ParseCallback(r *http.Request) (Callback, error) {
	var values url.Values
	switch r.Method {
	case http.MethodGet:
		values = r.URL.Query()
	case http.MethodPost:
		r.Body = http.MaxBytesReader(nil, r.Body, callbackLimit)
		if err := r.ParseForm(); err != nil {
			return Callback{}, ErrBadCallback
		}
		values = r.PostForm
	default:
		return Callback{}, ErrBadCallback
	}
	for _, key := range []string{"state", "code", "error", "user"} {
		if len(values[key]) > 1 {
			return Callback{}, ErrBadCallback
		}
	}
	c := Callback{
		State: values.Get("state"),
		Code:  values.Get("code"),
		Error: values.Get("error"),
		User:  values.Get("user"),
	}
	if c.State == "" || (c.Code == "") == (c.Error == "") {
		return Callback{}, ErrBadCallback
	}
	return c, nil
}
