package echov5_test

import (
	"context"
	crand "crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/echov5"
	"github.com/sylly-mika/authkit/password"
	"github.com/sylly-mika/authkit/transport/cookie"
)

var opts = cookie.Options{Name: "s"}

type sessionFixture struct {
	d     *authkittest.DB
	p     *authkittest.Principals
	clock *authkittest.Clock
	svc   *authkit.Service
	txs   int
}

func sessionSetup(t *testing.T, tweak func(*authkit.Config)) *sessionFixture {
	t.Helper()
	f := &sessionFixture{d: authkittest.NewDB(t), p: authkittest.NewPrincipals(), clock: authkittest.NewClock()}
	cfg := authkit.Config{Transport: authkit.TransportSession, Hashing: cheap, Clock: f.clock, Rand: authkittest.Rand(5)}
	if tweak != nil {
		tweak(&cfg)
	}
	svc, err := authkit.New(cfg, f.p)
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	return f
}

// inTx is the app's transaction hook: commit when fn returns nil.
func (f *sessionFixture) inTx(ctx context.Context, fn func(q db.Querier) error) error {
	f.txs++
	return f.d.InAuthTx(ctx, fn)
}

func (f *sessionFixture) signIn(t *testing.T) (uuid.UUID, authkit.Result) {
	t.Helper()
	id := f.d.NewPrincipal(t, "ada@example.invalid")
	hash, err := password.Encode(cheap, crand.Reader, "the right password")
	if err != nil {
		t.Fatal(err)
	}
	f.d.Exec(t, `INSERT INTO auth_credentials (principal_id, password_hash, changed_at) VALUES ($1, $2, $3)`, id, hash, f.clock.Now())
	var res authkit.Result
	if err := f.d.InAuthTx(context.Background(), func(q db.Querier) error {
		var err error
		res, err = f.svc.Login(context.Background(), q, "admin", "ada@example.invalid", "the right password", authkit.Meta{})
		return err
	}); err != nil || res.Refusal != nil {
		t.Fatalf("sign in: %v %v", err, res.Refusal)
	}
	return id, res
}

// serve runs req through the chain by hand and returns the recorder and the error.
func serve(req *http.Request, chain []echo.MiddlewareFunc, last echo.HandlerFunc) (*httptest.ResponseRecorder, error) {
	rec := httptest.NewRecorder()
	h := last
	for i := len(chain) - 1; i >= 0; i-- {
		h = chain[i](h)
	}
	return rec, h(echo.New().NewContext(req, rec))
}

func withCookie(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/admin/x", nil)
	if token != "" {
		req.Header.Set("Cookie", "__Host-s="+token)
	}
	return req
}

func TestSessionCookieOpensNoTransactionWithoutACookie(t *testing.T) {
	f := sessionSetup(t, nil)
	reached := false
	rec, err := serve(withCookie(""), []echo.MiddlewareFunc{echov5.SessionCookie(f.svc, "admin", opts, f.inTx)}, func(c *echo.Context) error {
		_, ok := echov5.Session(c)
		reached = !ok
		return nil
	})
	if err != nil || !reached || f.txs != 0 || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("no cookie = %v, reached without a session %v, %d transactions, cookies %v; want none", err, reached, f.txs, rec.Result().Cookies())
	}
}

// TestSessionCookieStoresTheResultAndSetsTheRotatedCookie is spec §3.5: the
// handler finds the Result, its Claims and its Admission, and the response
// carries the rotated token, alive until the cap.
func TestSessionCookieStoresTheResultAndSetsTheRotatedCookie(t *testing.T) {
	f := sessionSetup(t, nil)
	id, signed := f.signIn(t)
	f.clock.Advance(15 * time.Minute)
	var res authkit.Result
	var claims *authkit.Claims
	var adm authkit.Admission
	rec, err := serve(withCookie(signed.SessionToken), []echo.MiddlewareFunc{echov5.SessionCookie(f.svc, "admin", opts, f.inTx)}, func(c *echo.Context) error {
		res, _ = echov5.Session(c)
		claims = echov5.Claims(c)
		adm, _ = echov5.Admission(c)
		return nil
	})
	if err != nil || res.Session == nil || claims == nil || claims.Subject != id || claims.SessionID != signed.Session.ID || adm.Context != "member" {
		t.Fatalf("SessionCookie = %v; stored %+v, claims %+v, admission %+v", err, res, claims, adm)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-s" || cookies[0].Value != res.SessionToken || res.SessionToken == "" || cookies[0].MaxAge < 1 {
		t.Fatalf("Set-Cookie = %+v; want the rotated token %q", cookies, res.SessionToken)
	}
	if _, err := serve(withCookie(signed.SessionToken), []echo.MiddlewareFunc{echov5.SessionCookie(f.svc, "admin", opts, f.inTx)}, func(c *echo.Context) error {
		if _, ok := echov5.Session(c); !ok {
			t.Error("the previous token within the grace was not admitted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestSessionCookieCommitsARefusalAndContinues is spec §3.5: the reuse of a
// token past the grace revokes its session through the app's hook, and the
// request goes on with no session.
func TestSessionCookieCommitsARefusalAndContinues(t *testing.T) {
	f := sessionSetup(t, nil)
	_, signed := f.signIn(t)
	f.clock.Advance(15 * time.Minute)
	chain := []echo.MiddlewareFunc{echov5.SessionCookie(f.svc, "admin", opts, f.inTx)}
	if _, err := serve(withCookie(signed.SessionToken), chain, func(*echo.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(31 * time.Second)
	reached := false
	errNext := errors.New("the handler's own result")
	rec, err := serve(withCookie(signed.SessionToken), chain, func(c *echo.Context) error {
		_, ok := echov5.Session(c)
		reached = !ok && echov5.Claims(c) == nil
		return errNext
	})
	if !errors.Is(err, errNext) || !reached || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("a replay = %v, reached without a session %v, cookies %v", err, reached, rec.Result().Cookies())
	}
	var reason string
	if err := f.d.Row(t, `SELECT revoke_reason FROM auth_sessions WHERE id = $1`, signed.Session.ID).Scan(&reason); err != nil || reason != "reuse_detected" {
		t.Fatalf("the session's revoke reason = %q (%v), want reuse_detected, committed by the hook", reason, err)
	}
}

type failingSessions struct{ err error }

func (f failingSessions) AuthenticateSession(context.Context, db.Querier, authkit.Audience, string, authkit.Meta) (authkit.Result, error) {
	return authkit.Result{}, f.err
}

func TestSessionCookieWrapsInfrastructureErrors(t *testing.T) {
	down := errors.New("pq: the database at 192.0.2.10 is down")
	hook := func(ctx context.Context, fn func(q db.Querier) error) error { return fn(nil) }
	_, err := serve(withCookie("a-token"), []echo.MiddlewareFunc{echov5.SessionCookie(failingSessions{down}, "admin", opts, hook)},
		func(*echo.Context) error { t.Error("a failed session check reached the handler"); return nil })
	if !errors.Is(err, down) || !serverError(err) {
		t.Fatalf("SessionCookie on a failing database = %v, want the failure wrapped", err)
	}
}

// TestRequireSessionAnswersEndedAndClearsTheCookie is spec §3.5.
func TestRequireSessionAnswersEndedAndClearsTheCookie(t *testing.T) {
	f := sessionSetup(t, nil)
	for name, keep := range map[string]bool{"clearing": false, "keepCookie": true} {
		rec, err := serve(withCookie("a-stale-token"), []echo.MiddlewareFunc{echov5.SessionCookie(f.svc, "admin", opts, f.inTx), echov5.RequireSession(opts, keep)},
			func(*echo.Context) error {
				t.Errorf("%s: a request without a session reached the handler", name)
				return nil
			})
		cleared := len(rec.Result().Cookies()) == 1 && rec.Result().Cookies()[0].MaxAge < 0
		if err != authkit.ErrSessionEnded || cleared == keep {
			t.Errorf("%s: RequireSession = %v, cleared %v; want ErrSessionEnded and the cookie cleared unless keepCookie", name, err, cleared)
		}
	}
	_, signed := f.signIn(t)
	if _, err := serve(withCookie(signed.SessionToken), []echo.MiddlewareFunc{echov5.SessionCookie(f.svc, "admin", opts, f.inTx), echov5.RequireSession(opts, false)},
		func(*echo.Context) error { return nil }); err != nil {
		t.Fatalf("RequireSession with a session = %v", err)
	}
}

func TestRequireOriginRefusesAForeignMutation(t *testing.T) {
	mw := []echo.MiddlewareFunc{echov5.RequireOrigin([]string{"https://admin.example.invalid"})}
	for origin, want := range map[string]error{"": cookie.ErrForeignOrigin, "https://evil.example.invalid": cookie.ErrForeignOrigin, "https://admin.example.invalid": nil} {
		req := httptest.NewRequest(http.MethodPost, "/admin/x", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if _, err := serve(req, mw, func(*echo.Context) error { return nil }); err != want {
			t.Errorf("a POST from %q = %v, want %v", origin, err, want)
		}
	}
}

// TestHashSlotHoldsASlotForTheRequest is spec §3.2: the handler hashes on
// the slot the middleware took, so a ceiling of one serves it, and the slot
// is released when the request ends.
func TestHashSlotHoldsASlotForTheRequest(t *testing.T) {
	f := sessionSetup(t, func(c *authkit.Config) { c.HashConcurrency, c.HashWait = 1, 50*time.Millisecond })
	f.signIn(t)
	login := func(c *echo.Context) error {
		ctx := c.Request().Context()
		return f.d.InAuthTx(ctx, func(q db.Querier) error {
			res, err := f.svc.Login(ctx, q, "admin", "ada@example.invalid", "the right password", authkit.Meta{})
			if err == nil && res.Refusal != nil {
				return res.Refusal
			}
			return err
		})
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", nil)
	if _, err := serve(req, []echo.MiddlewareFunc{echov5.HashSlot(f.svc)}, login); err != nil {
		t.Fatalf("a login under HashSlot with a ceiling of one = %v", err)
	}
	_, release, res, err := f.svc.AcquireHashSlot(context.Background())
	if err != nil || res.Refusal != nil {
		t.Fatalf("the slot was not released after the request: %v, %v", res.Refusal, err)
	}
	if _, err := serve(req, []echo.MiddlewareFunc{echov5.HashSlot(f.svc)}, func(*echo.Context) error {
		t.Error("a request reached the handler with the ceiling full")
		return nil
	}); err != authkit.ErrBusy {
		t.Fatalf("HashSlot with the ceiling full = %v, want authkit.ErrBusy", err)
	}
	release()
}

func TestParseBearerOnASessionModeServiceIsAServerError(t *testing.T) {
	f := sessionSetup(t, nil)
	err := run("Bearer x.y.z", []echo.MiddlewareFunc{echov5.ParseBearer(f.svc, "admin")},
		func(*echo.Context) error { t.Error("ParseBearer without a codec reached the handler"); return nil })
	if !serverError(err) {
		t.Fatalf("ParseBearer on a Session-mode Service = %v, want a wiring error", err)
	}
}

// fakeSessions records what SessionCookie handed AuthenticateSession and
// answers with a canned Result.
type fakeSessions struct {
	res     authkit.Result
	err     error
	gotRaw  string
	gotAud  authkit.Audience
	gotQ    db.Querier
	gotMeta authkit.Meta
}

func (f *fakeSessions) AuthenticateSession(_ context.Context, q db.Querier, aud authkit.Audience, raw string, m authkit.Meta) (authkit.Result, error) {
	f.gotQ, f.gotAud, f.gotRaw, f.gotMeta = q, aud, raw, m
	return f.res, f.err
}

// fakeHashSlots hands out a slot whose context is marked and counts its releases.
type fakeHashSlots struct {
	err      error
	releases int
}

type slotKey struct{}

func (f *fakeHashSlots) AcquireHashSlot(ctx context.Context) (context.Context, func(), authkit.Result, error) {
	return context.WithValue(ctx, slotKey{}, "held"), func() { f.releases++ }, authkit.Result{}, f.err
}

// passThrough is an app hook for a test that needs no transaction: it hands fn q.
func passThrough(q db.Querier) func(context.Context, func(q db.Querier) error) error {
	return func(_ context.Context, fn func(q db.Querier) error) error { return fn(q) }
}

// TestSessionCookieHandsAuthenticateSessionTheRequest is spec §3.5: the
// cookie's value, the audience, the hook's Querier and the request's RealIP
// and User-Agent reach AuthenticateSession, and the handler finds the Result,
// its Claims and its Admission.
func TestSessionCookieHandsAuthenticateSessionTheRequest(t *testing.T) {
	id, sid := uuid.New(), uuid.New()
	fake := &fakeSessions{res: authkit.Result{Session: &authkit.Session{ID: sid, PrincipalID: id}, Admission: &authkit.Admission{Context: "member"}}}
	q := &failing{}
	req := withCookie("the-token")
	req.Header.Set("User-Agent", "ua-test/1")
	wantIP := echo.New().NewContext(req, httptest.NewRecorder()).RealIP()
	var got authkit.Result
	var ok bool
	var claims *authkit.Claims
	var adm authkit.Admission
	_, err := serve(req, []echo.MiddlewareFunc{echov5.SessionCookie(fake, "admin", opts, passThrough(q))}, func(c *echo.Context) error {
		got, ok = echov5.Session(c)
		claims = echov5.Claims(c)
		adm, _ = echov5.Admission(c)
		return nil
	})
	if err != nil || fake.gotRaw != "the-token" || fake.gotAud != "admin" || fake.gotQ != db.Querier(q) || fake.gotMeta != (authkit.Meta{IP: wantIP, UserAgent: "ua-test/1"}) {
		t.Fatalf("SessionCookie = %v; AuthenticateSession got token %q, audience %q, querier %v, meta %+v", err, fake.gotRaw, fake.gotAud, fake.gotQ, fake.gotMeta)
	}
	if !ok || got.Session != fake.res.Session || claims == nil || claims.Subject != id || claims.SessionID != sid || adm.Context != "member" {
		t.Fatalf("the handler found session %v %+v, claims %+v, admission %+v", ok, got, claims, adm)
	}
}

// TestSessionCookieSetsTheRotatedCookieToTheCap is spec §3.5: a Result with a
// SessionToken sets the new cookie, alive to the session's cap; one without
// sets none.
func TestSessionCookieSetsTheRotatedCookieToTheCap(t *testing.T) {
	capAt := time.Now().Add(2 * time.Hour)
	for name, tc := range map[string]struct {
		token   string
		rotated bool
	}{
		"a rotated token":  {"the-new-token", true},
		"no rotated token": {"", false},
	} {
		admit := authkit.Admission{Context: "member"}
		fake := &fakeSessions{res: authkit.Result{SessionToken: tc.token, Session: &authkit.Session{ID: uuid.New(), AbsoluteExpiresAt: &capAt}, Admission: &admit}}
		rec, err := serve(withCookie("the-token"), []echo.MiddlewareFunc{echov5.SessionCookie(fake, "admin", opts, passThrough(nil))}, func(*echo.Context) error { return nil })
		if err != nil {
			t.Fatalf("%s: SessionCookie = %v", name, err)
		}
		cookies := rec.Result().Cookies()
		if !tc.rotated {
			if len(cookies) != 0 {
				t.Errorf("%s: Set-Cookie = %+v; want none", name, cookies)
			}
			continue
		}
		if len(cookies) != 1 || cookies[0].Name != "__Host-s" || cookies[0].Value != tc.token || cookies[0].MaxAge < 2*3600-2 || cookies[0].MaxAge > 2*3600 {
			t.Errorf("%s: Set-Cookie = %+v; want the new token alive for about two hours to the cap", name, cookies)
		}
	}
}

// TestRequireOriginRunsTheHandlerOnlyWhenItAdmits is spec §3.5 through the
// middleware: an allowed POST and a GET without Origin run on, and a foreign
// POST stops with cookie.ErrForeignOrigin before the handler.
func TestRequireOriginRunsTheHandlerOnlyWhenItAdmits(t *testing.T) {
	mw := []echo.MiddlewareFunc{echov5.RequireOrigin([]string{"https://admin.example.invalid"})}
	for name, tc := range map[string]struct {
		method, origin string
		runs           bool
	}{
		"an allowed POST":      {http.MethodPost, "https://admin.example.invalid", true},
		"a GET with no Origin": {http.MethodGet, "", true},
		"a foreign POST":       {http.MethodPost, "https://evil.example.invalid", false},
	} {
		req := httptest.NewRequest(tc.method, "/admin/x", nil)
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		ran := false
		_, err := serve(req, mw, func(*echo.Context) error {
			ran = true
			return nil
		})
		var want error
		if !tc.runs {
			want = cookie.ErrForeignOrigin
		}
		if ran != tc.runs || err != want {
			t.Errorf("%s: handler ran %v, error %v; want %v, %v", name, ran, err, tc.runs, want)
		}
	}
}

// TestHashSlotHandsOnTheHeldContextAndReleasesOnce is spec §3.2 with a fake
// ceiling: the handler sees the context the slot came with, and the slot is
// released once, also when the handler fails.
func TestHashSlotHandsOnTheHeldContextAndReleasesOnce(t *testing.T) {
	failure := errors.New("the handler failed")
	for name, want := range map[string]error{"a handler that succeeds": nil, "a handler that fails": failure} {
		fake := &fakeHashSlots{}
		held := false
		req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", nil)
		_, err := serve(req, []echo.MiddlewareFunc{echov5.HashSlot(fake)}, func(c *echo.Context) error {
			held = c.Request().Context().Value(slotKey{}) == "held"
			return want
		})
		if err != want || !held || fake.releases != 1 {
			t.Errorf("%s: error %v, saw the held context %v, releases %d; want %v, true, 1", name, err, held, fake.releases, want)
		}
	}
}

// TestHashSlotReturnsAnAcquireErrorWithoutRunningTheHandler is spec §3.2: a
// failing slot check is returned and the handler does not run.
func TestHashSlotReturnsAnAcquireErrorWithoutRunningTheHandler(t *testing.T) {
	down := errors.New("pq: the slot store is down")
	fake := &fakeHashSlots{err: down}
	_, err := serve(httptest.NewRequest(http.MethodPost, "/admin/auth/login", nil), []echo.MiddlewareFunc{echov5.HashSlot(fake)}, func(*echo.Context) error {
		t.Error("a failed slot check reached the handler")
		return nil
	})
	if !errors.Is(err, down) {
		t.Fatalf("HashSlot on a failing slot store = %v, want the failure wrapped", err)
	}
}
