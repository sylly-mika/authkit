package authkittest

import (
	"encoding/binary"
	"io"
	"math/rand/v2"
	"sync"
	"time"
)

// Clock is a settable clock for authkit.Config.Clock.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

func NewClock() *Clock { return &Clock{now: time.Date(2040, time.January, 1, 12, 0, 0, 0, time.UTC)} }

func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Rand is a deterministic, goroutine-safe source for authkit.Config.Rand.
func Rand(seed uint64) io.Reader {
	var key [32]byte
	binary.LittleEndian.PutUint64(key[:], seed)
	return &lockedReader{r: rand.NewChaCha8(key)}
}

type lockedReader struct {
	mu sync.Mutex
	r  *rand.ChaCha8
}

func (l *lockedReader) Read(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Read(p)
}
