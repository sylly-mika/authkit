package echov5_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
	"golang.org/x/time/rate"

	"github.com/sylly-mika/authkit/echov5"
)

func ok(c *echo.Context) error { return c.NoContent(http.StatusOK) }

func limited() func(ip string) *httptest.ResponseRecorder {
	e := echo.New()
	e.GET("/limited", ok, echov5.RateLimit(rate.Every(15*time.Second), 2))
	e.GET("/other", ok, echov5.RateLimit(rate.Every(15*time.Second), 2))
	return func(target string) *httptest.ResponseRecorder {
		path, ip, _ := strings.Cut(target, "@")
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = ip + ":40000"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
}

func TestRefusedRequestsSayWhenToRetry(t *testing.T) {
	send := limited()
	for i := range 2 {
		if rec := send("/limited@192.0.2.7"); rec.Code != http.StatusOK || rec.Header().Get("Retry-After") != "" {
			t.Fatalf("attempt %d: %d with Retry-After %q", i+1, rec.Code, rec.Header().Get("Retry-After"))
		}
	}
	for i := range 2 {
		rec := send("/limited@192.0.2.7")
		after, err := strconv.Atoi(rec.Header().Get("Retry-After"))
		if rec.Code != http.StatusTooManyRequests || err != nil || after < 1 || after > 15 {
			t.Fatalf("refusal %d: %d with Retry-After %q; a refusal must not spend a token", i+1, rec.Code, rec.Header().Get("Retry-After"))
		}
	}
	if rec := send("/limited@192.0.2.8"); rec.Code != http.StatusOK {
		t.Fatalf("another IP was limited: %d", rec.Code)
	}
	if rec := send("/other@192.0.2.7"); rec.Code != http.StatusOK {
		t.Fatalf("another route shared the bucket: %d", rec.Code)
	}
}

func TestConcurrentRefusalsSpendNothing(t *testing.T) {
	send := limited()
	for range 2 {
		send("/limited@192.0.2.7")
	}
	var wg sync.WaitGroup
	for range 200 {
		wg.Go(func() {
			if rec := send("/limited@192.0.2.7"); rec.Code != http.StatusTooManyRequests {
				t.Errorf("concurrent refusal: %d", rec.Code)
			}
		})
	}
	wg.Wait()
	rec := send("/limited@192.0.2.7")
	if after, err := strconv.Atoi(rec.Header().Get("Retry-After")); rec.Code != http.StatusTooManyRequests || err != nil || after < 1 || after > 15 {
		t.Fatalf("after 200 concurrent refusals: %d with Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
}

// TestOneClientIPIsOneBucket: every connection of an address shares its
// bucket, and without an IPExtractor a forwarded header changes nothing.
func TestOneClientIPIsOneBucket(t *testing.T) {
	e := echo.New()
	e.GET("/limited", ok, echov5.RateLimit(rate.Every(15*time.Second), 2))
	for i, want := range []int{http.StatusOK, http.StatusOK, http.StatusTooManyRequests} {
		req := httptest.NewRequest(http.MethodGet, "/limited", nil)
		req.RemoteAddr = "192.0.2.7:" + strconv.Itoa(40000+i)
		req.Header.Set(echo.HeaderXForwardedFor, "192.0.2.9"+strconv.Itoa(i))
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("request %d from 192.0.2.7: %d, want %d", i+1, rec.Code, want)
		}
	}
}

// TestASubSecondWaitSaysOneSecond: Retry-After rounds up, so a client never
// reads 0 and never retries before its token is back.
func TestASubSecondWaitSaysOneSecond(t *testing.T) {
	e := echo.New()
	e.GET("/limited", ok, echov5.RateLimit(rate.Every(500*time.Millisecond), 1))
	for i, want := range []string{"", "1"} {
		req := httptest.NewRequest(http.MethodGet, "/limited", nil)
		req.RemoteAddr = "192.0.2.7:40000"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if got := rec.Header().Get("Retry-After"); got != want {
			t.Fatalf("request %d: %d with Retry-After %q, want %q", i+1, rec.Code, got, want)
		}
	}
}

func TestIdleBucketsAreEvicted(t *testing.T) {
	e := echo.New()
	e.GET("/limited", ok, echov5.RateLimitSweeping(rate.Every(15*time.Second), 1, 10*time.Millisecond, 50*time.Millisecond))
	send := func() int {
		req := httptest.NewRequest(http.MethodGet, "/limited", nil)
		req.RemoteAddr = "192.0.2.7:40000"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec.Code
	}
	if first, second := send(), send(); first != http.StatusOK || second != http.StatusTooManyRequests {
		t.Fatalf("burst 1: %d then %d, want 200 then 429", first, second)
	}
	time.Sleep(250 * time.Millisecond)
	if code := send(); code != http.StatusOK {
		t.Fatalf("after 250 ms idle: %d, want 200 from a fresh bucket", code)
	}
}
