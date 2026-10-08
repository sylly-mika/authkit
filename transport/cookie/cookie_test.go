package cookie_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sylly-mika/authkit/transport/cookie"
)

func set(o cookie.Options, token string, absolute *time.Time) *http.Cookie {
	rec := httptest.NewRecorder()
	o.Set(rec, token, absolute)
	return rec.Result().Cookies()[0]
}

// TestSetWritesAHostCookie is spec §3.5: __Host-<Name>, Secure, HttpOnly,
// Path=/, no Domain, SameSite=Strict, alive until the cap.
func TestSetWritesAHostCookie(t *testing.T) {
	capAt := time.Now().Add(12 * time.Hour)
	c := set(cookie.Options{Name: "bmparts_session"}, "the-token", &capAt)
	if c.Name != "__Host-bmparts_session" || c.Value != "the-token" || c.Path != "/" || c.Domain != "" || !c.Secure || !c.HttpOnly ||
		c.SameSite != http.SameSiteStrictMode || c.MaxAge < 12*3600-2 || c.MaxAge > 12*3600 {
		t.Fatalf("cookie = %+v", c)
	}
}

func TestInsecureDropsThePrefixAndSecure(t *testing.T) {
	c := set(cookie.Options{Name: "bmparts_session", Insecure: true, SameSite: http.SameSiteLaxMode}, "the-token", nil)
	if c.Name != "bmparts_session" || c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 0 {
		t.Fatalf("an insecure cookie = %+v; want the plain name, no Secure, the chosen SameSite and a browser-session cookie", c)
	}
}

// TestSetWithoutAnExpiryIsABrowserSessionCookie is spec §3.5: nil writes
// neither Max-Age nor Expires.
func TestSetWithoutAnExpiryIsABrowserSessionCookie(t *testing.T) {
	c := set(cookie.Options{Name: "bmparts_session"}, "the-token", nil)
	if c.MaxAge != 0 || !c.Expires.IsZero() {
		t.Fatalf("a cookie without an absolute expiry = %+v; want neither Max-Age nor Expires", c)
	}
}

func TestClearDeletesTheCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	cookie.Options{Name: "bmparts_session"}.Clear(rec)
	c := rec.Result().Cookies()[0]
	if c.Name != "__Host-bmparts_session" || c.Value != "" || c.MaxAge >= 0 || !c.Secure || c.Path != "/" {
		t.Fatalf("the clearing cookie = %+v; want the same cookie with Max-Age=0", c)
	}
}

func TestClearWithInsecureDeletesThePlainCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	cookie.Options{Name: "bmparts_session", Insecure: true}.Clear(rec)
	c := rec.Result().Cookies()[0]
	if c.Name != "bmparts_session" || c.Value != "" || c.MaxAge >= 0 || c.Secure || !c.HttpOnly || c.Path != "/" {
		t.Fatalf("the insecure clearing cookie = %+v; want the plain name with Max-Age=0", c)
	}
}

func TestReadFindsOnlyItsOwnCookie(t *testing.T) {
	for name, tc := range map[string]struct {
		o      cookie.Options
		cookie string
		want   string
	}{
		"the host cookie":                 {cookie.Options{Name: "s"}, "__Host-s=tok", "tok"},
		"a plain cookie under the prefix": {cookie.Options{Name: "s"}, "s=tok", ""},
		"the insecure cookie":             {cookie.Options{Name: "s", Insecure: true}, "s=tok", "tok"},
		"no cookie":                       {cookie.Options{Name: "s"}, "", ""},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.cookie != "" {
			r.Header.Set("Cookie", tc.cookie)
		}
		if got := tc.o.Read(r); got != tc.want {
			t.Errorf("%s: Read = %q, want %q", name, got, tc.want)
		}
	}
}

// TestRequireOriginRefusesAnAbsentOrForeignOrigin is spec §3.5: no Referer
// fallback, and a wildcard vouches for nobody.
func TestRequireOriginRefusesAnAbsentOrForeignOrigin(t *testing.T) {
	check := cookie.RequireOrigin([]string{"https://admin.example.invalid", "*", ""})
	for name, tc := range map[string]struct {
		method, origin string
		ok             bool
	}{
		"a GET without Origin":       {http.MethodGet, "", true},
		"a HEAD without Origin":      {http.MethodHead, "", true},
		"an OPTIONS without Origin":  {http.MethodOptions, "", true},
		"a POST from the admin":      {http.MethodPost, "https://admin.example.invalid", true},
		"a POST without Origin":      {http.MethodPost, "", false},
		"a POST from another site":   {http.MethodPost, "https://evil.example.invalid", false},
		"a POST from a null origin":  {http.MethodPost, "null", false},
		"a POST with a trailing /":   {http.MethodPost, "https://admin.example.invalid/", false},
		"a DELETE from another site": {http.MethodDelete, "https://evil.example.invalid", false},
		"a PATCH without Origin":     {http.MethodPatch, "", false},
		"a PUT without Origin":       {http.MethodPut, "", false},
		"a DELETE without Origin":    {http.MethodDelete, "", false},
		"a POST from a lookalike":    {http.MethodPost, "https://admin.example.invalid.evil.example.invalid", false},
		"a POST on another port":     {http.MethodPost, "https://admin.example.invalid:8443", false},
	} {
		r := httptest.NewRequest(tc.method, "/admin/x", nil)
		r.Header.Set("Referer", "https://admin.example.invalid/page")
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if err := check(r); (err == nil) != tc.ok || (err != nil && !errors.Is(err, cookie.ErrForeignOrigin)) {
			t.Errorf("%s = %v, want allowed %v", name, err, tc.ok)
		}
	}
	if err := cookie.RequireOrigin([]string{"*"})(httptest.NewRequest(http.MethodPost, "/", nil)); !errors.Is(err, cookie.ErrForeignOrigin) {
		t.Fatalf("an allow-list of only a wildcard let a POST through: %v", err)
	}
}

// TestRequireOriginDropsWildcardAndEmptyEntries is spec §3.5: a "*" or an
// empty entry vouches for nobody, not even a present-but-empty Origin.
func TestRequireOriginDropsWildcardAndEmptyEntries(t *testing.T) {
	wild := cookie.RequireOrigin([]string{"*"})
	for _, origin := range []string{"https://x.example.invalid", "*"} {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Header.Set("Origin", origin)
		if err := wild(r); !errors.Is(err, cookie.ErrForeignOrigin) {
			t.Errorf("allow [*]: a POST from %q = %v, want ErrForeignOrigin", origin, err)
		}
	}
	empty := cookie.RequireOrigin([]string{"", "https://a.example.invalid"})
	for name, present := range map[string]bool{"a present but empty Origin": true, "no Origin": false} {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		if present {
			r.Header.Set("Origin", "")
		}
		if err := empty(r); !errors.Is(err, cookie.ErrForeignOrigin) {
			t.Errorf("allow [\"\", a]: a POST with %s = %v, want ErrForeignOrigin", name, err)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Origin", "https://a.example.invalid")
	if err := empty(r); err != nil {
		t.Fatalf("allow [\"\", a]: a POST from a = %v, want allowed", err)
	}
}
