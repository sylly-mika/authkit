package authkit_test

import (
	"testing"
	"time"

	"github.com/sylly-mika/authkit"
)

// WHY: PostgreSQL rounds timestamptz to the nearest microsecond, so this clock's 700ns tail is stored 300ns later than it reads in Go.
type roundingClock struct{}

func (roundingClock) Now() time.Time {
	return time.Date(2040, time.January, 1, 12, 0, 0, 1_000_700, time.UTC)
}

func withRoundingClock(c *authkit.Config) { c.Clock = roundingClock{} }

func TestAFreshEmailCodeIsNotRefusedAsSentTooSoon(t *testing.T) {
	rows := []struct {
		name string
		send func(t *testing.T) authkit.Result
	}{
		{"begin email setup", func(t *testing.T) authkit.Result {
			w := newWorld(t, withSecondFactors, withRoundingClock)
			w.user("ada@example.invalid", "the right password")
			c := w.claims(w.signIn("ada@example.invalid", "the right password"))
			return w.beginEmail(c)
		}},
		{"second step email", func(t *testing.T) authkit.Result {
			login := "ada@example.invalid"
			w := emailWorld(t, withRoundingClock)
			w.emailUser()
			return w.stepSend("staff", w.challenge(login))
		}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			res := r.send(t)
			if res.Refusal != nil || res.EmailCode == nil {
				t.Fatalf("first send: refusal %v, email code %v; want a code and no refusal", res.Refusal, res.EmailCode)
			}
		})
	}
}
