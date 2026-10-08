package echov5

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
	"golang.org/x/time/rate"
)

// RateLimit is a token bucket per client IP for one route: burst requests,
// then one more every 1/r (spec §8.9: burst 5, one per 15 s). Each call makes
// its own buckets; idle ones are evicted in the background. A refusal carries
// Retry-After, the whole seconds until the next token, and spends nothing.
// The client IP is c.RealIP(): the connection's peer unless the app sets
// e.IPExtractor. Behind a reverse proxy the app must set one that trusts only
// the proxy (ino-tasks: echo.ExtractIPFromXFFHeader with its private network
// trusted), or every client shares the proxy's bucket.
func RateLimit(r rate.Limit, burst int) echo.MiddlewareFunc {
	return rateLimit(r, burst, 10*time.Minute, 30*time.Minute)
}

func rateLimit(r rate.Limit, burst int, sweepEvery, idle time.Duration) echo.MiddlewareFunc {
	type entry struct {
		lim  *rate.Limiter
		seen time.Time
	}
	var mu sync.Mutex
	limiters := map[string]*entry{}
	go func() {
		for range time.Tick(sweepEvery) {
			mu.Lock()
			for ip, e := range limiters {
				if time.Since(e.seen) > idle {
					delete(limiters, ip)
				}
			}
			mu.Unlock()
		}
	}()
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			ip := c.RealIP()
			mu.Lock()
			e, ok := limiters[ip]
			if !ok {
				e = &entry{lim: rate.NewLimiter(r, burst)}
				limiters[ip] = e
			}
			e.seen = time.Now()
			res := e.lim.Reserve()
			wait := res.Delay()
			if wait > 0 {
				res.Cancel()
			}
			mu.Unlock()
			if wait > 0 {
				c.Response().Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
				return echo.NewHTTPError(http.StatusTooManyRequests, "Too many requests")
			}
			return next(c)
		}
	}
}
