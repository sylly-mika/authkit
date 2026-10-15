package authkit_test

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/password"
)

type world struct{ *kittest.World }

func newWorld(t *testing.T, tweaks ...func(*authkit.Config)) *world {
	t.Helper()
	return &world{kittest.New(t, tweaks...)}
}

func TestTheSixthAttemptIsRefusedUnverified(t *testing.T) {
	w := newWorld(t, kittest.DefaultRules)
	id := w.User("ada@example.invalid", "the right password")
	var calls atomic.Int64
	authkit.SetVerifyHook(w.Svc, func() { calls.Add(1) })
	for i := range 5 {
		if res := w.Login("staff", "ada@example.invalid", "a wrong password"); !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
			t.Fatalf("attempt %d = %v, want ErrInvalidCredentials", i+1, res.Refusal)
		}
	}
	w.Clock.Advance(time.Minute)
	var locked authkit.ErrLocked
	if res := w.Login("staff", "ada@example.invalid", "the right password"); !errors.As(res.Refusal, &locked) || locked.RetryAfter != 15*time.Minute {
		t.Fatalf("the sixth attempt = %v, want ErrLocked{15m}", res.Refusal)
	}
	if n := calls.Load(); n != 5 {
		t.Fatalf("%d verifications, want 5: the sixth attempt must not verify", n)
	}
	if w.Count(`SELECT count(*) FROM auth_events WHERE result = 'locked' AND principal_id = $1`, id) != 1 {
		t.Fatal("the locked event does not name the principal")
	}
	w.Clock.Advance(10 * time.Minute)
	if res := w.Login("staff", "ada@example.invalid", "the right password"); !errors.As(res.Refusal, &locked) || locked.RetryAfter != 5*time.Minute {
		t.Fatalf("an attempt 10 minutes into the lockout = %v, want ErrLocked{5m}: the lockout is kept, not extended", res.Refusal)
	}
	w.Clock.Advance(5 * time.Minute)
	w.SignIn("ada@example.invalid", "the right password")
	if w.Count(`SELECT count(*) FROM auth_throttle`) != 0 {
		t.Fatal("a sign-in left the counter behind")
	}
}

func TestABusyLoginCountsNothing(t *testing.T) {
	w := newWorld(t, kittest.DefaultRules, func(c *authkit.Config) { c.HashConcurrency, c.HashWait = 1, 50*time.Millisecond })
	w.User("ada@example.invalid", "the right password")
	release, err := authkit.HoldHashSlot(w.Ctx, w.Svc)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if res := w.Login("staff", "ada@example.invalid", "a wrong password"); !errors.Is(res.Refusal, authkit.ErrBusy) {
		t.Fatalf("Login with the ceiling full = %v, want ErrBusy", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_throttle`)+w.Count(`SELECT count(*) FROM auth_events`) != 0 {
		t.Fatal("a Busy refusal counted or logged")
	}
}

func TestTheCountComesBeforeTheVerify(t *testing.T) {
	for name, tc := range map[string]struct {
		tweak    func(*authkit.Config)
		key      string
		verified int64
	}{
		"count-before":     {kittest.DefaultRules, kittest.HashedKey("ada@example.invalid"), 0},
		"CountAfterVerify": {func(*authkit.Config) {}, "ada@example.invalid", 1},
	} {
		w := newWorld(t, tc.tweak)
		w.User("ada@example.invalid", "the right password")
		w.D.Exec(t, `INSERT INTO auth_throttle (login, audience, failures, window_start) VALUES ($1, 'staff', 1, $2)`, tc.key, w.Clock.Now())
		holder, err := w.D.Owner.BeginTx(w.Ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := holder.ExecContext(w.Ctx, `SELECT 1 FROM auth_throttle WHERE login = $1 FOR UPDATE`, tc.key); err != nil {
			t.Fatal(err)
		}
		var calls atomic.Int64
		authkit.SetVerifyHook(w.Svc, func() { calls.Add(1) })
		done := make(chan error, 1)
		var res authkit.Result
		go func() {
			done <- w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
				var err error
				res, err = w.Svc.Login(w.Ctx, q, "staff", "ada@example.invalid", "a wrong password", authkit.Meta{})
				return err
			})
		}()
		w.D.WaitForLockWaiters(t, 1)
		if n := calls.Load(); n != tc.verified {
			t.Errorf("%s: %d verifications while the login waits on its throttle row, want %d", name, n, tc.verified)
		}
		if err := holder.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil || !errors.Is(res.Refusal, authkit.ErrInvalidCredentials) {
			t.Fatalf("%s: Login = %v, %v", name, res.Refusal, err)
		}
	}
}

func TestLoginVerifiesExactlyOncePerAttempt(t *testing.T) {
	w := newWorld(t)
	w.User("known@example.invalid", "the right password")
	w.User("invited@example.invalid", "")
	var calls atomic.Int64
	authkit.SetVerifyHook(w.Svc, func() { calls.Add(1) })
	for name, tc := range map[string][2]string{
		"unknown login":  {"nobody@example.invalid", "whatever it is"},
		"no credential":  {"invited@example.invalid", "whatever it is"},
		"wrong password": {"known@example.invalid", "a wrong password"},
		"right password": {"known@example.invalid", "the right password"},
	} {
		calls.Store(0)
		w.Login("client", tc[0], tc[1])
		if n := calls.Load(); n != 1 {
			t.Errorf("%s: %d argon2id verifications, want exactly 1", name, n)
		}
	}
}

func TestTheLockoutEngagesAfterTenFailures(t *testing.T) {
	w := newWorld(t)
	w.User("ada@example.invalid", "the right password")
	for range 10 {
		w.Login("staff", "ada@example.invalid", "a wrong password")
	}
	var calls atomic.Int64
	authkit.SetVerifyHook(w.Svc, func() { calls.Add(1) })
	w.Clock.Advance(5 * time.Minute)
	var locked authkit.ErrLocked
	if res := w.Login("staff", "ada@example.invalid", "the right password"); !errors.As(res.Refusal, &locked) || locked.RetryAfter != 10*time.Minute {
		t.Fatalf("the 11th attempt = %v, want ErrLocked{10m}", res.Refusal)
	}
	if calls.Load() != 0 {
		t.Fatal("a locked login ran the hash; the check must come first")
	}
	if w.Count(`SELECT count(*) FROM auth_events WHERE result = 'locked' AND login = 'ada@example.invalid'`) != 1 {
		t.Fatal("no locked event")
	}
	w.Clock.Advance(10 * time.Minute)
	if res := w.Login("staff", "ada@example.invalid", "the right password"); res.Refusal != nil {
		t.Fatalf("after the lockout = %v", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_throttle WHERE login = 'ada@example.invalid'`) != 0 {
		t.Fatal("a sign-in left the counter behind")
	}
}

func TestARehashKeepsAPasswordChangedDuringTheLogin(t *testing.T) {
	w := newWorld(t)
	id := w.User("ada@example.invalid", "the old password")
	changed, err := password.Encode(w.Cfg.Hashing, crand.Reader, "the new password")
	if err != nil {
		t.Fatal(err)
	}
	stronger := w.Cfg
	stronger.Hashing.Time = 2
	w.Svc = w.Service(stronger)
	var once sync.Once
	authkit.SetVerifyHook(w.Svc, func() {
		once.Do(func() {
			w.D.Exec(t, `UPDATE auth_credentials SET password_hash = $2 WHERE principal_id = $1`, id, changed)
		})
	})
	w.Login("staff", "ada@example.invalid", "the old password")
	if got := w.StoredHash(id); got != changed {
		t.Fatalf("the rehash overwrote a password changed during the login: stored %q, want %q", got, changed)
	}
}

// WHY: the hook runs after the verify releases its hash slot and before the rehash asks for one.
type admitHook struct {
	*authkittest.Principals
	before func()
}

func (p admitHook) Admit(ctx context.Context, q db.Querier, prop authkit.Proposal) (authkit.Admission, error) {
	p.before()
	return p.Principals.Admit(ctx, q, prop)
}

func TestLoginSkipsTheRehashWhenTheCeilingIsFull(t *testing.T) {
	w := newWorld(t, func(c *authkit.Config) { c.HashConcurrency, c.HashWait = 1, 50*time.Millisecond })
	id := w.User("ada@example.invalid", "the right password")
	stronger := w.Cfg
	stronger.Hashing.Time = 2
	var svc *authkit.Service
	var release func()
	hold := true
	svc, err := authkit.New(stronger, admitHook{w.P, func() {
		if !hold {
			return
		}
		r, err := authkit.HoldHashSlot(w.Ctx, svc)
		if err != nil {
			t.Fatal(err)
		}
		release = r
	}})
	if err != nil {
		t.Fatal(err)
	}
	w.Svc = svc
	w.SignIn("ada@example.invalid", "the right password")
	if h := w.StoredHash(id); !strings.Contains(h, ",t=1,") {
		t.Fatalf("hash after a sign-in with the ceiling full = %q; want the rehash skipped", h)
	}
	release()
	hold = false
	w.SignIn("ada@example.invalid", "the right password")
	if h := w.StoredHash(id); !strings.Contains(h, ",t=2,") {
		t.Fatalf("hash after the next sign-in = %q; want it rehashed at t=2", h)
	}
}

func TestLoginAnswersBusyWhenTheCeilingIsFull(t *testing.T) {
	w := newWorld(t, func(c *authkit.Config) { c.HashConcurrency, c.HashWait = 1, 50*time.Millisecond })
	w.User("ada@example.invalid", "the right password")
	release, err := authkit.HoldHashSlot(w.Ctx, w.Svc)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if res := w.Login("staff", "ada@example.invalid", "the right password"); !errors.Is(res.Refusal, authkit.ErrBusy) {
		t.Fatalf("Login with the ceiling full = %v, want ErrBusy", res.Refusal)
	}
	if w.Count(`SELECT count(*) FROM auth_events`)+w.Count(`SELECT count(*) FROM auth_throttle`) != 0 {
		t.Fatal("a busy refusal wrote")
	}
}

func TestPasskeyOwnerHandlerRefusesAnotherUsersHandle(t *testing.T) {
	w := newWorld(t, kittest.Passkeys)
	adaID := w.User("ada@example.invalid", "")
	bobID := w.User("bob@example.invalid", "")
	cred := w.SeedPasskey(adaID, authkittest.NewAuthenticator("localhost", kittest.StaffOrigin))
	lookup := func(userHandle []byte) (webauthn.User, error) {
		var user webauthn.User
		var err error
		if txErr := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
			user, err = authkit.PasskeyOwnerHandler(w.Ctx, q, cred.ID, userHandle)
			return nil
		}); txErr != nil {
			t.Fatalf("lookup: %v", txErr)
		}
		return user, err
	}
	if user, err := lookup(adaID[:]); err != nil || user == nil {
		t.Fatalf("the handler refused Ada's own handle: user %v, err %v", user, err)
	}
	user, err := lookup(bobID[:])
	if err == nil {
		t.Error("the handler accepted Bob's user handle for Ada's passkey")
	}
	if user != nil {
		t.Errorf("the handler returned user %s with a refusal", user.WebAuthnName())
	}
}

func passkeyWorld(t *testing.T, ttl time.Duration) *world {
	return newWorld(t, func(c *authkit.Config) {
		c.Passkeys = authkit.PasskeyRules{
			RPID:   "localhost",
			RPName: "ino-tasks",
			Origins: map[authkit.Audience][]string{
				"staff":  {"http://localhost:3000"},
				"client": {"http://localhost:3100"},
			},
			CeremonyTTL: ttl,
		}
	})
}

func optionsMap(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m["publicKey"].(map[string]any)
}

func TestPasskeyRelyingPartyPerAudience(t *testing.T) {
	w := passkeyWorld(t, 2*time.Minute)
	staff, ok, err := authkit.PasskeyRP(w.Svc, "staff")
	if !ok || err != nil {
		t.Fatalf("staff relying party: ok=%v err=%v", ok, err)
	}
	if staff.Config.RPID != "localhost" {
		t.Fatalf("staff RPID %q, want localhost", staff.Config.RPID)
	}
	if got := staff.Config.RPOrigins; len(got) != 1 || got[0] != "http://localhost:3000" {
		t.Fatalf("staff RPOrigins %v, want [http://localhost:3000]", got)
	}
	if _, _, err := staff.BeginDiscoverableLogin(webauthn.WithLoginOrigin("http://localhost:3100")); err == nil {
		t.Error("the staff relying party began a login from the client origin")
	}
	if _, _, err := staff.BeginDiscoverableLogin(webauthn.WithLoginOrigin("http://localhost:3000")); err != nil {
		t.Errorf("the staff relying party refused its own origin: %v", err)
	}

	client, ok, err := authkit.PasskeyRP(w.Svc, "client")
	if !ok || err != nil {
		t.Fatalf("client relying party: ok=%v err=%v", ok, err)
	}
	if got := client.Config.RPOrigins; len(got) != 1 || got[0] != "http://localhost:3100" {
		t.Fatalf("client RPOrigins %v, want [http://localhost:3100]", got)
	}
	if _, _, err := client.BeginDiscoverableLogin(webauthn.WithLoginOrigin("http://localhost:3000")); err == nil {
		t.Error("the client relying party began a login from the staff origin")
	}

	rp, ok, err := authkit.PasskeyRP(w.Svc, "agent")
	if rp != nil || ok || err != nil {
		t.Fatalf("an audience with no relying party: rp=%v ok=%v err=%v", rp != nil, ok, err)
	}
}

var ada = authkit.Principal{ID: uuid.MustParse("6f1c2a52-8a43-4c1e-9d6f-0b7e2f6c9a10"), Login: "ada@example.invalid"}

func TestPasskeyRegistrationOptions(t *testing.T) {
	w := passkeyWorld(t, 2*time.Minute)
	rp, _, err := authkit.PasskeyRP(w.Svc, "staff")
	if err != nil {
		t.Fatal(err)
	}
	creation, sess, err := rp.BeginRegistration(authkit.NewPasskeyUser(ada, nil))
	if err != nil {
		t.Fatal(err)
	}
	pk := optionsMap(t, creation)
	rpOpt := pk["rp"].(map[string]any)
	user := pk["user"].(map[string]any)
	sel := pk["authenticatorSelection"].(map[string]any)
	if rpOpt["id"] != "localhost" || rpOpt["name"] != "ino-tasks" {
		t.Errorf("rp is %v, want localhost and ino-tasks", rpOpt)
	}
	if user["id"] != base64.RawURLEncoding.EncodeToString(ada.ID[:]) || user["name"] != "ada@example.invalid" {
		t.Errorf("user is %v", user)
	}
	if sel["residentKey"] != "required" || sel["requireResidentKey"] != true || sel["userVerification"] != "required" {
		t.Errorf("authenticatorSelection is %v, want required resident key and user verification", sel)
	}
	if pk["attestation"] != "none" {
		t.Errorf("attestation %v, want none", pk["attestation"])
	}
	if pk["timeout"] != float64(120000) {
		t.Errorf("timeout %v, want 120000", pk["timeout"])
	}
	if sess.UserVerification != protocol.VerificationRequired {
		t.Errorf("session UserVerification %q, want required", sess.UserVerification)
	}
	if !bytes.Equal(sess.UserID, ada.ID[:]) {
		t.Error("session UserID is not the principal's id")
	}
	if sess.Expires.IsZero() {
		t.Error("session has no expiry")
	}
}

func TestPasskeyLoginOptionsUseTheCeremonyTTL(t *testing.T) {
	w := passkeyWorld(t, 90*time.Second)
	rp, _, err := authkit.PasskeyRP(w.Svc, "staff")
	if err != nil {
		t.Fatal(err)
	}
	assertion, sess, err := rp.BeginDiscoverableLogin()
	if err != nil {
		t.Fatal(err)
	}
	pk := optionsMap(t, assertion)
	if pk["rpId"] != "localhost" || pk["userVerification"] != "required" {
		t.Errorf("login options are %v, want localhost and required user verification", pk)
	}
	if pk["timeout"] != float64(90000) {
		t.Errorf("login timeout %v, want 90000", pk["timeout"])
	}
	if _, ok := pk["allowCredentials"]; ok {
		t.Error("a discoverable login lists allowCredentials")
	}
	now := time.Now()
	if sess.Expires.Before(now.Add(85*time.Second)) || sess.Expires.After(now.Add(95*time.Second)) {
		t.Errorf("login expiry %v is not about 90s from now", sess.Expires)
	}

	creation, _, err := rp.BeginRegistration(authkit.NewPasskeyUser(ada, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := optionsMap(t, creation)["timeout"]; got != float64(90000) {
		t.Errorf("registration timeout %v, want 90000", got)
	}
}

func TestPasskeysOffWithoutRPID(t *testing.T) {
	w := newWorld(t)
	rp, ok, err := authkit.PasskeyRP(w.Svc, "staff")
	if rp != nil || ok || !errors.Is(err, authkit.ErrPasskeysOff) {
		t.Fatalf("passkeys off: rp=%v ok=%v err=%v, want ErrPasskeysOff", rp != nil, ok, err)
	}
}

func TestPasskeyUserCarriesTheHandleAndCredentials(t *testing.T) {
	w := passkeyWorld(t, 2*time.Minute)
	rp, _, err := authkit.PasskeyRP(w.Svc, "staff")
	if err != nil {
		t.Fatal(err)
	}
	assertion, sess, err := rp.BeginLogin(authkit.NewPasskeyUser(ada, []webauthn.Credential{{ID: []byte{1, 2, 3, 4}}}))
	if err != nil {
		t.Fatal(err)
	}
	pk := optionsMap(t, assertion)
	allow, ok := pk["allowCredentials"].([]any)
	if !ok || len(allow) != 1 || allow[0].(map[string]any)["id"] != "AQIDBA" {
		t.Errorf("allowCredentials %v, want one credential AQIDBA", pk["allowCredentials"])
	}
	if len(sess.UserID) != 16 || !bytes.Equal(sess.UserID, ada.ID[:]) {
		t.Error("session UserID is not the 16-byte principal id")
	}
	if got := authkit.NewPasskeyUser(ada, nil).WebAuthnDisplayName(); got != "ada@example.invalid" {
		t.Errorf("display name %q, want the login", got)
	}
}

func TestChangePasswordHashesBeforeItLocks(t *testing.T) {
	w := newWorld(t, func(c *authkit.Config) { c.HashConcurrency = 1 })
	id := w.User("ada@example.invalid", "the old password")
	keep := w.SignIn("ada@example.invalid", "the old password")
	holder, err := w.D.Owner.BeginTx(w.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(w.Ctx, `SELECT 1 FROM auth_credentials WHERE principal_id = $1 FOR UPDATE`, id); err != nil {
		t.Fatal(err)
	}
	conn, c := w.Pinned(id), w.Claims(keep)
	var res authkit.Result
	done := make(chan error, 1)
	go func() {
		done <- authkittest.InConnTx(w.Ctx, conn, func(q db.Querier) error {
			var err error
			res, err = w.Svc.ChangePassword(w.Ctx, q, c, "the old password", "the changed password", authkit.Meta{})
			return err
		})
	}()
	w.D.WaitForLockWaiters(t, 1)
	release, err := authkit.HoldHashSlot(w.Ctx, w.Svc)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if res.Refusal != nil {
		t.Fatalf("a change that waited on the credential row = %v; it hashed under the lock", res.Refusal)
	}
}
