// Package password hashes and verifies passwords with argon2id in PHC string
// format, behind a ceiling on concurrent hashes (spec §8.7).
package password

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// Params are argon2id's costs. Memory is in KiB.
type Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

// Default is m = 19 MiB, t = 2, p = 1, a 16-byte salt and a 32-byte key.
var Default = Params{Memory: 19 * 1024, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}

var (
	ErrBusy      = errors.New("authkit: too many password hashes at once")
	ErrMalformed = errors.New("authkit: the stored hash is not an argon2id PHC string")
)

var b64 = base64.RawStdEncoding

// The highest stored costs Verify spends: a tampered row must not exhaust memory.
const maxMemory, maxTime = 1 << 20, 16

func phcString(p Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key))
}

// Encode hashes pw under p with a salt read from rand. It takes no slot;
// Hasher.Hash is the bounded form. Test fixtures call it directly.
func Encode(p Params, rand io.Reader, pw string) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := io.ReadFull(rand, salt); err != nil {
		return "", fmt.Errorf("authkit: password salt: %w", err)
	}
	key := argon2.IDKey([]byte(norm.NFC.String(pw)), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return phcString(p, salt, key), nil
}

type phc struct {
	params Params
	salt   []byte
	key    []byte
}

func decode(s string) (phc, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return phc{}, ErrMalformed
	}
	var h phc
	var threads uint32
	if n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &h.params.Memory, &h.params.Time, &threads); err != nil || n != 3 ||
		threads == 0 || threads > 255 || h.params.Time == 0 || h.params.Memory < 8*threads {
		return phc{}, ErrMalformed
	}
	h.params.Threads = uint8(threads)
	var err error
	if h.salt, err = b64.DecodeString(parts[4]); err != nil || len(h.salt) == 0 {
		return phc{}, ErrMalformed
	}
	if h.key, err = b64.DecodeString(parts[5]); err != nil || len(h.key) == 0 {
		return phc{}, ErrMalformed
	}
	h.params.SaltLen, h.params.KeyLen = uint32(len(h.salt)), uint32(len(h.key))
	if h.params.Memory > maxMemory || h.params.Time > maxTime || phcString(h.params, h.salt, h.key) != s {
		return phc{}, ErrMalformed
	}
	return h, nil
}

// Hasher bounds argon2id work: at most the given number of hashes or
// verifications at once, each waiting up to wait for a slot.
type Hasher struct {
	params Params
	slots  chan struct{}
	wait   time.Duration
	rand   io.Reader
	dummy  string
}

// NewHasher computes the dummy hash up front, under the same parameters, so
// the first unknown login pays one hash like every other (spec §8.6).
func NewHasher(p Params, concurrency int, wait time.Duration, rand io.Reader) (*Hasher, error) {
	if concurrency < 1 || p.Time < 1 || p.Threads < 1 || p.KeyLen < 1 {
		return nil, fmt.Errorf("authkit: hashing needs a slot, a pass, a lane and a key: %d slots, %+v", concurrency, p)
	}
	dummy, err := Encode(p, rand, "authkit-timing-equaliser")
	if err != nil {
		return nil, err
	}
	if _, err := decode(dummy); err != nil {
		return nil, fmt.Errorf("authkit: hashes under %+v would not verify: %w", p, err)
	}
	return &Hasher{params: p, slots: make(chan struct{}, concurrency), wait: wait, rand: rand, dummy: dummy}, nil
}

// Acquire takes one slot, waiting at most the Hasher's wait (ErrBusy) or
// until ctx ends. Hash, Verify and VerifyDummy take their own.
func (h *Hasher) Acquire(ctx context.Context) (release func(), err error) {
	timer := time.NewTimer(h.wait)
	defer timer.Stop()
	select {
	case h.slots <- struct{}{}:
		return func() { <-h.slots }, nil
	case <-timer.C:
		return nil, ErrBusy
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Hash encodes pw under the Hasher's parameters once it holds a slot
// (ErrBusy after the wait).
func (h *Hasher) Hash(ctx context.Context, pw string) (string, error) {
	release, err := h.Acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	return Encode(h.params, h.rand, pw)
}

// Verify reports whether pw matches the stored PHC string, under the
// string's own parameters, comparing in constant time.
func (h *Hasher) Verify(ctx context.Context, encoded, pw string) (bool, error) {
	stored, err := decode(encoded)
	if err != nil {
		return false, err
	}
	release, err := h.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	key := argon2.IDKey([]byte(norm.NFC.String(pw)), stored.salt, stored.params.Time, stored.params.Memory, stored.params.Threads, stored.params.KeyLen)
	return subtle.ConstantTimeCompare(key, stored.key) == 1, nil
}

// VerifyDummy spends what Verify spends, for a login with no hash to check
// (spec §8.6). Its outcome is discarded: it never admits anyone.
func (h *Hasher) VerifyDummy(ctx context.Context, pw string) error {
	_, err := h.Verify(ctx, h.dummy, pw)
	return err
}

// NeedsRehash reports a stored hash made under weaker parameters (spec §8.7).
func (h *Hasher) NeedsRehash(encoded string) bool {
	stored, err := decode(encoded)
	if err != nil {
		return false
	}
	p, want := stored.params, h.params
	return p.Memory < want.Memory || p.Time < want.Time || p.Threads < want.Threads || p.KeyLen < want.KeyLen || p.SaltLen < want.SaltLen
}
