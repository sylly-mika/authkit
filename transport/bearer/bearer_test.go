package bearer_test

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/sylly-mika/authkit/transport/bearer"
)

const secret = "a-test-secret-of-at-least-32-bytes!"

var (
	t0  = time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	sub = uuid.MustParse("6f1c1a2e-3b4d-4c5e-8f60-718293a4b5c6")
	sid = uuid.MustParse("0a1b2c3d-4e5f-4061-8273-8495a6b7c8d9")
)

func codec(t testing.TB) *bearer.Codec {
	t.Helper()
	c, err := bearer.NewCodec("test", []byte(secret), 15*time.Minute, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func valid() jwt.MapClaims {
	return jwt.MapClaims{"sub": sub.String(), "sid": sid.String(), "iss": "test", "aud": "test:staff",
		"iat": t0.Unix(), "exp": t0.Add(time.Minute).Unix(), "role": "member"}
}

func sign(t *testing.T, method jwt.SigningMethod, key any, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewCodecRefusesAWeakSetup(t *testing.T) {
	now := func() time.Time { return t0 }
	for name, tc := range map[string]struct {
		issuer string
		secret []byte
		ttl    time.Duration
		now    func() time.Time
	}{
		"an empty issuer":  {"", []byte(secret), 15 * time.Minute, now},
		"a 31-byte secret": {"test", []byte(secret[:31]), 15 * time.Minute, now},
		"a zero ttl":       {"test", []byte(secret), 0, now},
		"a negative ttl":   {"test", []byte(secret), -time.Minute, now},
		"a nil clock":      {"test", []byte(secret), 15 * time.Minute, nil},
	} {
		if _, err := bearer.NewCodec(tc.issuer, tc.secret, tc.ttl, tc.now); err == nil {
			t.Errorf("NewCodec accepted %s", name)
		}
	}
	if _, err := bearer.NewCodec("test", []byte(secret[:32]), 15*time.Minute, now); err != nil {
		t.Fatalf("a 32-byte secret was refused: %v", err)
	}
}

func TestAZeroCodecRefusesAForgedToken(t *testing.T) {
	now := time.Now()
	forged := sign(t, jwt.SigningMethodHS256, []byte{}, jwt.MapClaims{"sub": sub.String(), "sid": sid.String(),
		"aud": ":staff", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix()})
	if _, err := new(bearer.Codec).Parse(forged, "staff"); !errors.Is(err, bearer.ErrInvalid) {
		t.Errorf("a zero Codec accepted a token signed with an empty key: %v", err)
	}
}

func TestMintAndParseRoundTrip(t *testing.T) {
	ws := uuid.New()
	token, exp, err := codec(t).Mint(sub, sid, "staff", map[string]any{"ws": ws, "role": "member"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := codec(t).Parse(token, "staff")
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != sub || c.SessionID != sid || c.Issuer != "test" || c.Audience != "staff" ||
		!c.IssuedAt.Equal(t0) || !c.ExpiresAt.Equal(t0.Add(15*time.Minute)) || !exp.Equal(c.ExpiresAt) {
		t.Fatalf("claims = %+v, expiry %v", c, exp)
	}
	if len(c.App) != 2 || c.App["ws"] != ws.String() || c.App["role"] != "member" {
		t.Fatalf("app claims = %v", c.App)
	}
}

func TestParseRefusesEveryNonStrictToken(t *testing.T) {
	without := func(name string) jwt.MapClaims { c := valid(); delete(c, name); return c }
	with := func(name string, v any) jwt.MapClaims { c := valid(); c[name] = v; return c }
	for name, token := range map[string]string{
		"alg none":            sign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, valid()),
		"HS384":               sign(t, jwt.SigningMethodHS384, []byte(secret), valid()),
		"HS512":               sign(t, jwt.SigningMethodHS512, []byte(secret), valid()),
		"another secret":      sign(t, jwt.SigningMethodHS256, []byte("another-secret-of-at-least-32-bytes"), valid()),
		"no exp":              sign(t, jwt.SigningMethodHS256, []byte(secret), without("exp")),
		"no iat":              sign(t, jwt.SigningMethodHS256, []byte(secret), without("iat")),
		"no iss":              sign(t, jwt.SigningMethodHS256, []byte(secret), without("iss")),
		"no aud":              sign(t, jwt.SigningMethodHS256, []byte(secret), without("aud")),
		"no sub":              sign(t, jwt.SigningMethodHS256, []byte(secret), without("sub")),
		"no sid":              sign(t, jwt.SigningMethodHS256, []byte(secret), without("sid")),
		"another issuer":      sign(t, jwt.SigningMethodHS256, []byte(secret), with("iss", "other")),
		"aud as an array":     sign(t, jwt.SigningMethodHS256, []byte(secret), with("aud", []string{"test:staff"})),
		"aud of an issuer":    sign(t, jwt.SigningMethodHS256, []byte(secret), with("aud", "other:staff")),
		"aud without surface": sign(t, jwt.SigningMethodHS256, []byte(secret), with("aud", "test:")),
		"sub not a uuid":      sign(t, jwt.SigningMethodHS256, []byte(secret), with("sub", "ada")),
		"sub in braces":       sign(t, jwt.SigningMethodHS256, []byte(secret), with("sub", "{"+sub.String()+"}")),
		"expired":             sign(t, jwt.SigningMethodHS256, []byte(secret), with("exp", t0.Add(-time.Second).Unix())),
		"issued in future":    sign(t, jwt.SigningMethodHS256, []byte(secret), with("iat", t0.Add(time.Minute).Unix())),
		"issued past leeway":  sign(t, jwt.SigningMethodHS256, []byte(secret), with("iat", t0.Add(bearer.IssuedAtLeeway+time.Second).Unix())),
		"not yet valid":       sign(t, jwt.SigningMethodHS256, []byte(secret), with("nbf", t0.Add(time.Minute).Unix())),
		"exp as text":         sign(t, jwt.SigningMethodHS256, []byte(secret), with("exp", "soon")),
		"garbage":             "a.b.c",
	} {
		if _, err := codec(t).Parse(token, "staff"); !errors.Is(err, bearer.ErrInvalid) {
			t.Errorf("%s: Parse = %v, want ErrInvalid (spec §8.4)", name, err)
		}
	}
}

// TestParseAcceptsAnIatWithinTheLeeway: a token minted by a host whose clock
// runs ahead, or parsed just after this host's clock was stepped back, is
// accepted up to IssuedAtLeeway; its exp still has no leeway.
func TestParseAcceptsAnIatWithinTheLeeway(t *testing.T) {
	for _, ahead := range []time.Duration{time.Second, bearer.IssuedAtLeeway} {
		claims := valid()
		claims["iat"] = t0.Add(ahead).Unix()
		if _, err := codec(t).Parse(sign(t, jwt.SigningMethodHS256, []byte(secret), claims), "staff"); err != nil {
			t.Errorf("iat %v ahead: Parse = %v, want accepted", ahead, err)
		}
	}
	claims := valid()
	claims["iat"], claims["exp"] = t0.Add(bearer.IssuedAtLeeway).Unix(), t0.Unix()
	if _, err := codec(t).Parse(sign(t, jwt.SigningMethodHS256, []byte(secret), claims), "staff"); !errors.Is(err, bearer.ErrInvalid) {
		t.Errorf("exp at now with an iat ahead: Parse = %v, want ErrInvalid", err)
	}
}

func TestWrongAudienceOnlyForAnOtherwiseValidToken(t *testing.T) {
	client := sign(t, jwt.SigningMethodHS256, []byte(secret), func() jwt.MapClaims { c := valid(); c["aud"] = "test:client"; return c }())
	if _, err := codec(t).Parse(client, "staff"); !errors.Is(err, bearer.ErrWrongAudience) {
		t.Fatalf("a valid client token on staff = %v, want ErrWrongAudience", err)
	}
	expired := valid()
	expired["aud"], expired["exp"] = "test:client", t0.Add(-time.Second).Unix()
	if _, err := codec(t).Parse(sign(t, jwt.SigningMethodHS256, []byte(secret), expired), "staff"); !errors.Is(err, bearer.ErrInvalid) {
		t.Fatalf("an expired client token on staff = %v, want ErrInvalid: 401 comes before 403", err)
	}
}

func TestMintRefusesReservedAppClaims(t *testing.T) {
	for _, name := range []string{"sub", "sid", "iss", "aud", "iat", "exp", "nbf", "jti"} {
		if _, _, err := codec(t).Mint(sub, sid, "staff", map[string]any{name: "x"}); !errors.Is(err, bearer.ErrReservedClaim) {
			t.Errorf("app claim %q = %v, want ErrReservedClaim (spec §8.4)", name, err)
		}
	}
}

func TestSameClaimsComparesAfterAJSONRoundTrip(t *testing.T) {
	ws := uuid.New()
	presented := map[string]any{"ws": ws.String(), "role": "member", "n": float64(3)}
	for _, tc := range []struct {
		name    string
		granted map[string]any
		same    bool
	}{
		{"a uuid and its string", map[string]any{"ws": ws, "role": "member", "n": 3}, true},
		{"a changed role", map[string]any{"ws": ws, "role": "admin", "n": 3}, false},
		{"an added claim", map[string]any{"ws": ws, "role": "member", "n": 3, "x": true}, false},
		{"a missing claim", map[string]any{"ws": ws, "role": "member"}, false},
	} {
		same, err := bearer.SameClaims(tc.granted, presented)
		if err != nil || same != tc.same {
			t.Errorf("%s: SameClaims = %v, %v; want %v (spec §5.1)", tc.name, same, err, tc.same)
		}
	}
	if same, err := bearer.SameClaims(nil, map[string]any{}); !same || err != nil {
		t.Errorf("no claims on either side = %v, %v", same, err)
	}
}

func TestFromHeader(t *testing.T) {
	for h, want := range map[string]string{"Bearer abc": "abc", "bearer abc": "abc", "BEARER a.b.c": "a.b.c"} {
		if got, err := bearer.FromHeader(h); got != want || err != nil {
			t.Errorf("FromHeader(%q) = %q, %v", h, got, err)
		}
	}
	for _, h := range []string{"", "Bearer", "Bearer ", "Basic abc", "abc"} {
		if _, err := bearer.FromHeader(h); !errors.Is(err, bearer.ErrMissing) {
			t.Errorf("FromHeader(%q) = %v, want ErrMissing", h, err)
		}
	}
}
