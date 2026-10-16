package password_test

import (
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/password"
	"golang.org/x/crypto/bcrypt"
)

func legacyWorld(t *testing.T, l ...password.Legacy) *world {
	t.Helper()
	return newWorld(t, func(c *kittest.Rules) { c.Password.Legacy = l })
}

func bcryptOf(t *testing.T, pw string, cost int) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func (w *world) legacyUser(login, hash string, at time.Time) uuid.UUID {
	w.T.Helper()
	id := w.User(login, "")
	w.D.Exec(w.T, `INSERT INTO auth_credentials (principal_id, password_hash, changed_at) VALUES ($1, $2, $3)`, id, hash, at)
	return id
}

func (w *world) legacyLoginErr(login, pw string) error {
	return w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		_, err := w.Svc.Password.Login(w.Ctx, q, "staff", login, pw, authkit.Meta{IP: "192.0.2.1", UserAgent: "authkit-test"})
		return err
	})
}

type plainLegacy struct{ prefix string }

func (l plainLegacy) Owns(e string) bool                { return strings.HasPrefix(e, l.prefix) }
func (l plainLegacy) Verify(e, pw string) (bool, error) { return e == l.prefix+pw, nil }

func TestABcryptRowSignsInAndBecomesArgon2id(t *testing.T) {
	w := legacyWorld(t, password.Bcrypt())
	at := w.Clock.Now().Truncate(time.Second)
	hash := bcryptOf(t, "correct horse", 12)
	id := w.legacyUser("ada@example.invalid", hash, at)
	w.Clock.Advance(time.Second)

	w.SignIn("ada@example.invalid", "correct horse")
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, id) == 0 {
		t.Fatal("the first sign-in left no session")
	}
	first := w.StoredHash(id)
	if !strings.HasPrefix(first, "$argon2id$") {
		t.Fatal("the first sign-in did not rewrite the row as argon2id")
	}
	if w.Count(`SELECT count(*) FROM auth_credentials WHERE principal_id = $1 AND changed_at = $2`, id, at) != 1 {
		t.Error("the rehash changed changed_at")
	}

	w.SignIn("ada@example.invalid", "correct horse")
	if w.StoredHash(id) != first {
		t.Error("the second sign-in rewrote the argon2id row")
	}
	if got := w.Results(id); !slices.Equal(got, []string{"signed_in", "signed_in"}) {
		t.Errorf("auth events = %v; want [signed_in signed_in]", got)
	}
}

func TestAWrongPasswordOnABcryptRowCountsAndKeepsTheRow(t *testing.T) {
	w := legacyWorld(t, password.Bcrypt())
	at := w.Clock.Now().Truncate(time.Second)
	hash := bcryptOf(t, "correct horse", bcrypt.MinCost)
	id := w.legacyUser("ada@example.invalid", hash, at)
	w.Clock.Advance(time.Second)

	res := w.Login("staff", "ada@example.invalid", "a wrong password")
	if !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("refusal = %v; want ErrInvalidCredentials", res.Refusal)
	}
	if got := w.Results(id); !slices.Equal(got, []string{"bad_password"}) {
		t.Errorf("auth events = %v; want [bad_password]", got)
	}
	if n := w.Count(`SELECT COALESCE(sum(failures), 0)::int FROM auth_throttle`); n != 1 {
		t.Errorf("throttle failures = %d; want 1", n)
	}
	if w.StoredHash(id) != hash {
		t.Error("the row changed on a wrong password")
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, id) != 0 {
		t.Error("a wrong password left a session")
	}
}

func TestABcryptRowWithoutLegacyIsMalformed(t *testing.T) {
	w := newWorld(t)
	at := w.Clock.Now().Truncate(time.Second)
	hash := bcryptOf(t, "correct horse", bcrypt.MinCost)
	id := w.legacyUser("ada@example.invalid", hash, at)

	err := w.legacyLoginErr("ada@example.invalid", "correct horse")
	if !errors.Is(err, password.ErrMalformed) {
		t.Fatalf("err = %v; want ErrMalformed", err)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, id) != 0 {
		t.Error("a malformed row left a session")
	}
	if w.StoredHash(id) != hash {
		t.Error("the row changed on a malformed hash")
	}
	if w.Count(`SELECT count(*) FROM auth_events`) != 0 {
		t.Error("a malformed hash wrote an auth event")
	}
}

func TestABcryptCostAbove14IsMalformed(t *testing.T) {
	w := legacyWorld(t, password.Bcrypt())
	at := w.Clock.Now().Truncate(time.Second)
	h := bcryptOf(t, "correct horse", 4)
	for _, c := range []struct{ login, hash string }{
		{"u15@example.invalid", strings.Replace(h, "$04$", "$15$", 1)},
		{"u31@example.invalid", strings.Replace(h, "$04$", "$31$", 1)},
	} {
		id := w.legacyUser(c.login, c.hash, at)
		err := w.legacyLoginErr(c.login, "correct horse")
		if !errors.Is(err, password.ErrMalformed) {
			t.Fatalf("err = %v; want ErrMalformed for a bcrypt cost above 14", err)
		}
		if w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, id) != 0 {
			t.Fatal("a bcrypt cost above 14 left a session")
		}
		if w.StoredHash(id) != c.hash {
			t.Fatal("the row changed on a bcrypt cost above 14")
		}
	}
}

func TestAPasswordOver72BytesIsAMismatch(t *testing.T) {
	w := legacyWorld(t, password.Bcrypt())
	at := w.Clock.Now().Truncate(time.Second)
	p72 := strings.Repeat("correct horse ", 6)[:72]
	hash := bcryptOf(t, p72, bcrypt.MinCost)
	id := w.legacyUser("ada@example.invalid", hash, at)
	w.Clock.Advance(time.Second)

	res := w.Login("staff", "ada@example.invalid", p72+"x")
	if !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("refusal = %v; want ErrInvalidCredentials for a password over 72 bytes", res.Refusal)
	}
	if got := w.Results(id); !slices.Equal(got, []string{"bad_password"}) {
		t.Errorf("auth events = %v; want [bad_password]", got)
	}
	if w.StoredHash(id) != hash {
		t.Error("the row changed on an over-long password")
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, id) != 0 {
		t.Error("an over-long password left a session")
	}

	w.SignIn("ada@example.invalid", p72)
	if !strings.HasPrefix(w.StoredHash(id), "$argon2id$") {
		t.Error("the 72-byte sign-in did not rewrite the row as argon2id")
	}
}

func TestAnAppLegacyVerifierSignsInAndAnUnownedHashIsMalformed(t *testing.T) {
	w := legacyWorld(t, plainLegacy{"$plain$"})
	at := w.Clock.Now().Truncate(time.Second)
	a := w.legacyUser("ada@example.invalid", "$plain$the old password", at)
	b := w.legacyUser("bob@example.invalid", "$1$salt$abcdef", at)

	w.SignIn("ada@example.invalid", "the old password")
	if !strings.HasPrefix(w.StoredHash(a), "$argon2id$") {
		t.Error("the app verifier's sign-in did not rewrite the row as argon2id")
	}

	err := w.legacyLoginErr("bob@example.invalid", "x")
	if !errors.Is(err, password.ErrMalformed) {
		t.Fatalf("err = %v; want ErrMalformed for a hash no verifier owns", err)
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, b) != 0 {
		t.Error("an unowned hash left a session")
	}
}

func TestTheFirstOwningVerifierDecides(t *testing.T) {
	w := legacyWorld(t, plainLegacy{"$plain$"}, plainLegacy{"$plain$the"})
	at := w.Clock.Now().Truncate(time.Second)
	hash := "$plain$the old password"
	id := w.legacyUser("ada@example.invalid", hash, at)

	res := w.Login("staff", "ada@example.invalid", " old password")
	if !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("refusal = %v; want ErrInvalidCredentials", res.Refusal)
	}
	if w.StoredHash(id) != hash {
		t.Error("the row changed after the first owning verifier refused")
	}
	if w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, id) != 0 {
		t.Error("a later verifier signed in after the first refused")
	}
}

func TestVerifyPasswordChecksABcryptRow(t *testing.T) {
	w := legacyWorld(t, password.Bcrypt())
	at := w.Clock.Now().Truncate(time.Second)
	id := w.legacyUser("ada@example.invalid", bcryptOf(t, "correct horse", bcrypt.MinCost), at)
	p := authkit.Principal{ID: id, Login: "ada@example.invalid"}

	res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Password.VerifyPassword(w.Ctx, q, p, "staff", "correct horse", authkit.Meta{})
	})
	if res.Refusal != nil || res.Principal.ID != id {
		t.Fatalf("VerifyPassword with the right password: refusal = %v, principal = %v", res.Refusal, res.Principal.ID)
	}

	res = w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Password.VerifyPassword(w.Ctx, q, p, "staff", "a wrong password", authkit.Meta{})
	})
	if !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
		t.Fatalf("refusal = %v; want ErrInvalidCredentials", res.Refusal)
	}
	if got := w.Results(id); !slices.Equal(got, []string{"bad_password"}) {
		t.Errorf("auth events = %v; want [bad_password]", got)
	}
}

func TestBcryptOwnsItsFormatsAndVerifiesRawBytes(t *testing.T) {
	l := password.Bcrypt()
	h := bcryptOf(t, "correct horse", 4)
	nfd := "pārole ar čūsku"
	hn := bcryptOf(t, nfd, 4)
	argon, err := password.Encode(cheap, rand.Reader, "x")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []string{h, "$2b$" + h[4:], "$2y$" + h[4:]} {
		if !l.Owns(e) {
			t.Error("Owns is false for a bcrypt hash of a $2a$, $2b$ or $2y$ format")
		}
	}
	for _, e := range []string{argon, "", "$2x$" + h[4:]} {
		if l.Owns(e) {
			t.Error("Owns is true for a string that is not a bcrypt hash")
		}
	}
	if ok, err := l.Verify(h, "correct horse"); !ok || err != nil {
		t.Errorf("Verify of the right password = %v, %v; want true, nil", ok, err)
	}
	if ok, err := l.Verify(h, "correct horsE"); ok || err != nil {
		t.Errorf("Verify of a wrong password = %v, %v; want false, nil", ok, err)
	}
	if ok, err := l.Verify("$2y$"+h[4:], "correct horse"); !ok || err != nil {
		t.Errorf("Verify of a $2y$ hash = %v, %v; want true, nil", ok, err)
	}
	if ok, err := l.Verify(hn, nfd); !ok || err != nil {
		t.Errorf("Verify of a non-ASCII password = %v, %v; want true, nil", ok, err)
	}
	if ok, err := l.Verify("$2a$04$short", "x"); ok || !errors.Is(err, password.ErrMalformed) {
		t.Errorf("Verify of a truncated hash = %v, %v; want false, ErrMalformed", ok, err)
	}
}

func TestNewRefusesANilLegacy(t *testing.T) {
	svc := newSvc(t)
	m, err := password.New(svc, password.Config{Hashing: cheap, Legacy: []password.Legacy{password.Bcrypt(), nil}})
	if m != nil || err == nil || !strings.Contains(err.Error(), "Config.Legacy[1]") {
		t.Fatalf("New with a nil Legacy: module = %v, err = %v; want no module and an error naming Config.Legacy[1]", m, err)
	}
	m, err = password.New(svc, password.Config{Hashing: cheap, Legacy: []password.Legacy{password.Bcrypt()}})
	if m == nil || err != nil {
		t.Fatalf("New with a Bcrypt Legacy: module = %v, err = %v; want a module and no error", m, err)
	}
}
