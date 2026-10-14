package authkit_test

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
)

const staffOrigin, clientOrigin = "http://localhost:3000", "http://localhost:3100"

var (
	passkeyMeta    = authkit.Meta{IP: "192.0.2.1", UserAgent: "authkit-test"}
	errDeactivated = errors.New("deactivated")
)

func passkeys(c *authkit.Config) {
	c.Passkeys = authkit.PasskeyRules{RPID: "localhost", Origins: map[authkit.Audience][]string{"staff": {staffOrigin}, "client": {clientOrigin}}, CeremonyTTL: 2 * time.Minute}
}

type testUser struct {
	id    uuid.UUID
	creds []webauthn.Credential
}

func (u testUser) WebAuthnID() []byte                         { return u.id[:] }
func (u testUser) WebAuthnName() string                       { return u.id.String() }
func (u testUser) WebAuthnDisplayName() string                { return u.id.String() }
func (u testUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (w *world) seedPasskey(id uuid.UUID, a *authkittest.Authenticator) webauthn.Credential {
	w.t.Helper()
	rp, err := webauthn.New(&webauthn.Config{RPID: "localhost", RPDisplayName: "authkit", RPOrigins: []string{staffOrigin, clientOrigin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}})
	if err != nil {
		w.t.Fatalf("seed a passkey: %v", err)
	}
	creation, session, err := rp.BeginRegistration(testUser{id: id})
	if err != nil {
		w.t.Fatalf("seed a passkey: %v", err)
	}
	opts, err := json.Marshal(creation)
	if err != nil {
		w.t.Fatalf("seed a passkey: %v", err)
	}
	resp, err := a.Create(opts)
	if err != nil {
		w.t.Fatalf("seed a passkey: %v", err)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(resp)
	if err != nil {
		w.t.Fatalf("seed a passkey: %v", err)
	}
	cred, err := rp.CreateCredential(testUser{id: id}, *session, parsed)
	if err != nil {
		w.t.Fatalf("seed a passkey: %v", err)
	}
	data, err := json.Marshal(cred)
	if err != nil {
		w.t.Fatalf("seed a passkey: %v", err)
	}
	w.d.Exec(w.t, "INSERT INTO auth_passkeys (id, principal_id, credential_id, label, data, created_at) VALUES ($1, $2, $3, 'Seed', $4, $5)", uuid.New(), id, cred.ID, string(data), w.clock.Now())
	return *cred
}

func (w *world) begin(aud authkit.Audience) authkit.Result {
	w.t.Helper()
	return w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.BeginPasskeyLogin(w.ctx, q, aud, passkeyMeta)
	})
}

func (w *world) finish(aud authkit.Audience, ceremonyID string, resp []byte) authkit.Result {
	w.t.Helper()
	return w.inAuth(func(q db.Querier) (authkit.Result, error) {
		return w.svc.FinishPasskeyLogin(w.ctx, q, aud, ceremonyID, resp, passkeyMeta)
	})
}

func (w *world) passkeySignIn(aud authkit.Audience, a *authkittest.Authenticator) authkit.Result {
	w.t.Helper()
	res := w.begin(aud)
	if res.Ceremony == nil {
		w.t.Fatalf("begin refused: %v", res.Refusal)
	}
	resp, err := a.Get(res.Ceremony.Options)
	if err != nil {
		w.t.Fatalf("authenticator: %v", err)
	}
	return w.finish(aud, res.Ceremony.ID, resp)
}

func (w *world) loginEvents(id uuid.UUID) []string {
	w.t.Helper()
	rows, err := w.d.Owner.Query(`SELECT result FROM auth_events WHERE principal_id = $1 AND source = 'passkey_login' ORDER BY at, id`, id)
	if err != nil {
		w.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			w.t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		w.t.Fatal(err)
	}
	return out
}

func (w *world) passkeyState(id uuid.UUID) string {
	w.t.Helper()
	var s string
	if err := w.d.Row(w.t, `SELECT COALESCE(string_agg(COALESCE(data->'authenticator'->>'signCount', '') || '|' || COALESCE(last_used_at::text, ''), ';' ORDER BY id), '') FROM auth_passkeys WHERE principal_id = $1`, id).Scan(&s); err != nil {
		w.t.Fatal(err)
	}
	return s
}

func (w *world) throttleRows() []string {
	w.t.Helper()
	rows, err := w.d.Owner.Query(`SELECT concat_ws('|', login, audience, failures, window_start, locked_until) FROM auth_throttle ORDER BY login, audience`)
	if err != nil {
		w.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			w.t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		w.t.Fatal(err)
	}
	return out
}

func refusedNoSession(t *testing.T, w *world, id uuid.UUID, res authkit.Result) {
	t.Helper()
	if !errors.Is(res.Refusal, authkit.ErrPasskeyRejected) {
		t.Errorf("sign-in refusal = %v, want ErrPasskeyRejected", res.Refusal)
	}
	if n := w.count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", id); n != 0 {
		t.Errorf("%d sessions opened by a refused sign-in, want 0", n)
	}
}

func TestBeginPasskeyLoginReturnsDiscoverableOptions(t *testing.T) {
	w := newWorld(t, passkeys)
	first := w.begin("staff")
	second := w.begin("staff")
	var options []map[string]any
	for _, res := range []authkit.Result{first, second} {
		if res.Refusal != nil || res.Ceremony == nil {
			t.Fatalf("begin refused: %v", res.Refusal)
		}
		c := res.Ceremony
		if len(c.ID) != 43 {
			t.Errorf("ceremony ID is %d characters, want 43", len(c.ID))
		}
		if !c.ExpiresAt.Equal(w.clock.Now().Add(2 * time.Minute)) {
			t.Errorf("ceremony expires at %v, want %v", c.ExpiresAt, w.clock.Now().Add(2*time.Minute))
		}
		var doc map[string]any
		if err := json.Unmarshal(c.Options, &doc); err != nil {
			t.Fatalf("options are not JSON: %v", err)
		}
		pk, ok := doc["publicKey"].(map[string]any)
		if !ok {
			t.Fatal("options have no publicKey object")
		}
		if pk["rpId"] != "localhost" {
			t.Errorf("rpId = %v, want localhost", pk["rpId"])
		}
		if pk["userVerification"] != "required" {
			t.Errorf("userVerification = %v, want required", pk["userVerification"])
		}
		if pk["timeout"] != float64(120000) {
			t.Errorf("timeout = %v, want 120000", pk["timeout"])
		}
		if ch, _ := pk["challenge"].(string); ch == "" {
			t.Error("options have no challenge")
		}
		if _, has := pk["allowCredentials"]; has {
			t.Error("discoverable options carry allowCredentials")
		}
		options = append(options, pk)
	}
	if first.Ceremony.ID == second.Ceremony.ID {
		t.Error("two begins returned one ceremony ID")
	}
	if !slices.Equal(slices.Sorted(maps.Keys(options[0])), slices.Sorted(maps.Keys(options[1]))) {
		t.Error("the two options have different key sets")
	}
	if n := w.count("SELECT count(*) FROM auth_passkey_ceremonies"); n != 2 {
		t.Errorf("%d ceremony rows, want 2", n)
	}
	if n := w.count("SELECT count(*) FROM auth_passkey_ceremonies WHERE kind = 'login' AND audience = 'staff' AND principal_id IS NULL AND session_id IS NULL"); n != 2 {
		t.Errorf("%d login ceremony rows for staff with no principal or session, want 2", n)
	}
	if n := w.count("SELECT count(*) FROM auth_events"); n != 0 {
		t.Errorf("%d events after begin, want 0", n)
	}
}

func TestPasskeyLoginRefusesAnAudienceWithoutOrigins(t *testing.T) {
	w := newWorld(t, passkeys)
	res := w.begin("partner")
	if !errors.Is(res.Refusal, authkit.ErrPasskeyRejected) || res.Ceremony != nil {
		t.Errorf("begin on partner = %v, want ErrPasskeyRejected and no ceremony", res.Refusal)
	}
	res = w.finish("partner", "x", []byte("{}"))
	if !errors.Is(res.Refusal, authkit.ErrPasskeyRejected) {
		t.Errorf("finish on partner = %v, want ErrPasskeyRejected", res.Refusal)
	}
	if n := w.count("SELECT count(*) FROM auth_passkey_ceremonies"); n != 0 {
		t.Errorf("%d ceremony rows, want 0", n)
	}
	if n := w.count("SELECT count(*) FROM auth_events"); n != 0 {
		t.Errorf("%d events, want 0", n)
	}
}

func TestPasskeyLoginIsOffWithoutAnRPID(t *testing.T) {
	w := newWorld(t)
	calls := map[string]func(q db.Querier) (authkit.Result, error){
		"BeginPasskeyLogin": func(q db.Querier) (authkit.Result, error) {
			return w.svc.BeginPasskeyLogin(w.ctx, q, "staff", passkeyMeta)
		},
		"FinishPasskeyLogin": func(q db.Querier) (authkit.Result, error) {
			return w.svc.FinishPasskeyLogin(w.ctx, q, "staff", "x", []byte("{}"), passkeyMeta)
		},
	}
	for name, call := range calls {
		var res authkit.Result
		err := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
			var err error
			res, err = call(q)
			return err
		})
		if !errors.Is(err, authkit.ErrPasskeysOff) {
			t.Errorf("%s = %v, want ErrPasskeysOff", name, err)
		}
		if !reflect.ValueOf(res).IsZero() {
			t.Errorf("%s returned a non-zero result with an error", name)
		}
	}
	if n := w.count("SELECT count(*) FROM auth_passkey_ceremonies"); n != 0 {
		t.Errorf("%d ceremony rows, want 0", n)
	}
}

func TestPasskeyLoginSignsIn(t *testing.T) {
	w := newWorld(t, passkeys)
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	a.SetCounter(4)
	res := w.passkeySignIn("staff", a)
	if res.Refusal != nil || res.Tokens == nil || res.Session == nil {
		t.Fatalf("sign-in: refusal %v, want signed in with tokens", res.Refusal)
	}
	if res.Session.Audience != "staff" {
		t.Errorf("session audience %q, want staff", res.Session.Audience)
	}
	if got := w.claims(res).Subject; got != id {
		t.Errorf("token subject %v, want %v", got, id)
	}
	if n := w.count("SELECT count(*) FROM auth_sessions WHERE id = $1 AND authenticated_at = $2", res.Session.ID, w.clock.Now()); n != 1 {
		t.Errorf("%d sessions with authenticated_at = now, want 1", n)
	}
	if n := w.count("SELECT count(*) FROM auth_events"); n != 1 {
		t.Errorf("%d events, want 1", n)
	}
	if n := w.count("SELECT count(*) FROM auth_events WHERE source = 'passkey_login' AND result = 'signed_in' AND session_id = $1 AND login = 'ada@example.invalid' AND ip = '192.0.2.1'", res.Session.ID); n != 1 {
		t.Errorf("%d signed_in passkey_login events for the session, want 1", n)
	}
	if n := w.count("SELECT count(*) FROM auth_passkeys WHERE principal_id = $1 AND last_used_at = $2", id, w.clock.Now()); n != 1 {
		t.Errorf("%d passkeys used at now, want 1", n)
	}
	if n := w.count("SELECT count(*) FROM auth_passkeys WHERE principal_id = $1 AND (data->'authenticator'->>'signCount')::int >= 4", id); n != 1 {
		t.Errorf("the stored sign count is below 4")
	}
	t.Run("session mode", func(t *testing.T) {
		w := newWorld(t, passkeys, func(c *authkit.Config) { c.Transport = authkit.TransportSession })
		id := w.user("ada@example.invalid", "")
		a := authkittest.NewAuthenticator("localhost", staffOrigin)
		w.seedPasskey(id, a)
		res := w.passkeySignIn("staff", a)
		if res.Refusal != nil {
			t.Fatalf("sign-in refused: %v", res.Refusal)
		}
		if res.SessionToken == "" {
			t.Error("no session token in session mode")
		}
		if res.Tokens != nil {
			t.Error("tokens returned in session mode")
		}
	})
}

func TestPasskeyLoginCeremonyIsSpentOnce(t *testing.T) {
	w := newWorld(t, passkeys)
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	res := w.begin("staff")
	if res.Ceremony == nil {
		t.Fatalf("begin refused: %v", res.Refusal)
	}
	a.SetCounter(0)
	r1, err := a.Get(res.Ceremony.Options)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	a.SetCounter(0)
	r2, err := a.Get(res.Ceremony.Options)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	if first := w.finish("staff", res.Ceremony.ID, r1); first.Refusal != nil {
		t.Fatalf("first finish refused: %v", first.Refusal)
	}
	if second := w.finish("staff", res.Ceremony.ID, r2); !errors.Is(second.Refusal, authkit.ErrPasskeyRejected) {
		t.Errorf("second finish = %v, want ErrPasskeyRejected", second.Refusal)
	}
	if n := w.count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", id); n != 1 {
		t.Errorf("%d sessions, want 1", n)
	}
	if got := w.loginEvents(id); !slices.Equal(got, []string{"signed_in"}) {
		t.Errorf("passkey_login events %v, want [signed_in]", got)
	}
	if n := w.count("SELECT count(*) FROM auth_passkey_ceremonies WHERE used_at IS NOT NULL"); n != 1 {
		t.Errorf("%d spent ceremonies, want 1", n)
	}
}

func TestPasskeyLoginLocksThePasskeyRow(t *testing.T) {
	w := newWorld(t, passkeys)
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	a.SetCounter(5)
	res := w.begin("staff")
	if res.Ceremony == nil {
		t.Fatalf("begin refused: %v", res.Refusal)
	}
	resp, err := a.Get(res.Ceremony.Options)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	holder, err := w.d.Owner.BeginTx(w.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(w.ctx, "UPDATE auth_passkeys SET data = jsonb_set(data, '{authenticator,signCount}', '8') WHERE principal_id = $1", id); err != nil {
		t.Fatal(err)
	}
	var got authkit.Result
	errc := make(chan error, 1)
	go func() {
		errc <- w.d.InAuthTx(w.ctx, func(q db.Querier) error {
			var err error
			got, err = w.svc.FinishPasskeyLogin(w.ctx, q, "staff", res.Ceremony.ID, resp, passkeyMeta)
			return err
		})
	}()
	w.d.WaitForLockWaiters(t, 1)
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("finish: %v", err)
	}
	if !errors.Is(got.Refusal, authkit.ErrPasskeyRejected) {
		t.Errorf("finish after the clone's commit = %v, want ErrPasskeyRejected", got.Refusal)
	}
	refusedNoSession(t, w, id, got)
	if n := w.count("SELECT count(*) FROM auth_passkeys WHERE principal_id = $1 AND (data->'authenticator'->>'signCount')::int = 8", id); n != 1 {
		t.Errorf("the stored sign count changed by a refused sign-in")
	}
	if events := w.loginEvents(id); !slices.Equal(events, []string{"bad_passkey"}) {
		t.Errorf("passkey_login events %v, want [bad_passkey]", events)
	}
}

func TestAFailedPasskeyFinishBurnsTheCeremony(t *testing.T) {
	w := newWorld(t, passkeys)
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	res := w.begin("staff")
	if res.Ceremony == nil {
		t.Fatalf("begin refused: %v", res.Refusal)
	}
	if first := w.finish("staff", res.Ceremony.ID, []byte("{")); !errors.Is(first.Refusal, authkit.ErrPasskeyRejected) {
		t.Errorf("finish with a malformed response = %v, want ErrPasskeyRejected", first.Refusal)
	}
	resp, err := a.Get(res.Ceremony.Options)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	if second := w.finish("staff", res.Ceremony.ID, resp); !errors.Is(second.Refusal, authkit.ErrPasskeyRejected) {
		t.Errorf("finish on a burnt ceremony = %v, want ErrPasskeyRejected", second.Refusal)
	}
	if n := w.count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", id); n != 0 {
		t.Errorf("%d sessions, want 0", n)
	}
	if n := w.count("SELECT count(*) FROM auth_events"); n != 0 {
		t.Errorf("%d events, want 0", n)
	}
}

func TestPasskeyLoginRefusesAnExpiredCeremony(t *testing.T) {
	w := newWorld(t, passkeys)
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	res := w.begin("staff")
	if res.Ceremony == nil {
		t.Fatalf("begin refused: %v", res.Refusal)
	}
	resp, err := a.Get(res.Ceremony.Options)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	w.clock.Advance(2*time.Minute + time.Second)
	expired := w.finish("staff", res.Ceremony.ID, resp)
	if !errors.Is(expired.Refusal, authkit.ErrPasskeyRejected) {
		t.Errorf("finish after the TTL = %v, want ErrPasskeyRejected", expired.Refusal)
	}
	refusedNoSession(t, w, id, expired)
	if n := w.count("SELECT count(*) FROM auth_events"); n != 0 {
		t.Errorf("%d events, want 0", n)
	}
	fresh := w.passkeySignIn("staff", a)
	if fresh.Refusal != nil {
		t.Errorf("a fresh sign-in after the expired one = %v, want signed in", fresh.Refusal)
	}
}

func TestPasskeyLoginCeremonyIsBoundToItsAudience(t *testing.T) {
	w := newWorld(t, passkeys)
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	a.Origin = clientOrigin
	res := w.begin("staff")
	if res.Ceremony == nil {
		t.Fatalf("begin refused: %v", res.Refusal)
	}
	resp, err := a.Get(res.Ceremony.Options)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	refusedNoSession(t, w, id, w.finish("client", res.Ceremony.ID, resp))
	if n := w.count("SELECT count(*) FROM auth_events"); n != 0 {
		t.Errorf("%d events, want 0", n)
	}
}

func TestPasskeyLoginChecksOriginAndRPPerAudience(t *testing.T) {
	w := newWorld(t, passkeys)
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	c := authkittest.NewAuthenticator("localhost", clientOrigin)
	w.seedPasskey(id, c)
	t.Run("staff with the client origin", func(t *testing.T) {
		a.Origin = clientOrigin
		refusedNoSession(t, w, id, w.passkeySignIn("staff", a))
	})
	t.Run("client with the staff origin", func(t *testing.T) {
		c.Origin = staffOrigin
		refusedNoSession(t, w, id, w.passkeySignIn("client", c))
	})
	t.Run("staff with a foreign RP ID", func(t *testing.T) {
		a.Origin = staffOrigin
		h := sha256.Sum256([]byte("example.com"))
		a.RPIDHash = h[:]
		refusedNoSession(t, w, id, w.passkeySignIn("staff", a))
	})
	a.Origin, a.RPIDHash = staffOrigin, nil
	if res := w.passkeySignIn("staff", a); res.Refusal != nil {
		t.Errorf("staff sign-in with its own origin = %v, want signed in", res.Refusal)
	}
	c.Origin = clientOrigin
	if res := w.passkeySignIn("client", c); res.Refusal != nil {
		t.Errorf("client sign-in with its own origin = %v, want signed in", res.Refusal)
	}
}

func TestPasskeyLoginRequiresUserVerification(t *testing.T) {
	w := newWorld(t, passkeys)
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	before := w.passkeyState(id)
	a.NoUV = true
	res := w.passkeySignIn("staff", a)
	refusedNoSession(t, w, id, res)
	if after := w.passkeyState(id); after != before {
		t.Error("a refused sign-in changed the passkey row")
	}
	if got := w.loginEvents(id); !slices.Equal(got, []string{"bad_passkey"}) {
		t.Errorf("passkey_login events %v, want [bad_passkey]", got)
	}
}

func TestPasskeyLoginRefusesAnotherUsersHandle(t *testing.T) {
	w := newWorld(t, passkeys)
	adaID := w.user("ada@example.invalid", "")
	bobID := w.user("bob@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(adaID, a)
	w.seedPasskey(bobID, authkittest.NewAuthenticator("localhost", staffOrigin))
	before := w.passkeyState(adaID)
	a.UserHandle = bobID[:]
	res := w.passkeySignIn("staff", a)
	refusedNoSession(t, w, bobID, res)
	refusedNoSession(t, w, adaID, res)
	if after := w.passkeyState(adaID); after != before {
		t.Error("a refused sign-in changed Ada's passkey row")
	}
	if got := w.loginEvents(adaID); !slices.Equal(got, []string{"bad_passkey"}) {
		t.Errorf("Ada's passkey_login events %v, want [bad_passkey]", got)
	}
	if got := w.loginEvents(bobID); len(got) != 0 {
		t.Errorf("Bob's passkey_login events %v, want none", got)
	}
}

func TestPasskeyOwnerHandlerRefusesAnotherUsersHandle(t *testing.T) {
	w := newWorld(t, passkeys)
	adaID := w.user("ada@example.invalid", "")
	bobID := w.user("bob@example.invalid", "")
	cred := w.seedPasskey(adaID, authkittest.NewAuthenticator("localhost", staffOrigin))
	lookup := func(userHandle []byte) (webauthn.User, error) {
		var user webauthn.User
		var err error
		if txErr := w.d.InAuthTx(w.ctx, func(q db.Querier) error {
			user, err = authkit.PasskeyOwnerHandler(w.ctx, q, cred.ID, userHandle)
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

func TestPasskeyLoginRefusesABadSignature(t *testing.T) {
	w := newWorld(t, passkeys)
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	before := w.passkeyState(id)
	a.BadSignature = true
	res := w.passkeySignIn("staff", a)
	refusedNoSession(t, w, id, res)
	if after := w.passkeyState(id); after != before {
		t.Error("a refused sign-in changed the passkey row")
	}
	if n := w.count("SELECT count(*) FROM auth_events"); n != 1 {
		t.Errorf("%d events, want 1", n)
	}
	if n := w.count("SELECT count(*) FROM auth_events WHERE source = 'passkey_login' AND result = 'bad_passkey' AND principal_id = $1 AND session_id IS NULL AND audience = 'staff'", id); n != 1 {
		t.Errorf("no bad_passkey event for Ada on staff with no session")
	}
}

func TestPasskeyLoginWithAnUnknownCredentialRecordsNothing(t *testing.T) {
	w := newWorld(t, passkeys)
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	w.d.Exec(w.t, "DELETE FROM auth_passkeys WHERE principal_id = $1", id)
	refusedNoSession(t, w, id, w.passkeySignIn("staff", a))
	if n := w.count("SELECT count(*) FROM auth_events"); n != 0 {
		t.Errorf("%d events for an unknown credential, want 0", n)
	}
}

func TestPasskeyLoginRefusesABackwardsCounter(t *testing.T) {
	w := newWorld(t, passkeys)
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	a.SetCounter(5)
	if first := w.passkeySignIn("staff", a); first.Refusal != nil {
		t.Fatalf("first sign-in refused: %v", first.Refusal)
	}
	afterFirst := w.passkeyState(id)
	w.clock.Advance(time.Minute)
	a.SetCounter(3)
	if res := w.passkeySignIn("staff", a); !errors.Is(res.Refusal, authkit.ErrPasskeyRejected) {
		t.Errorf("backwards counter refusal = %v, want ErrPasskeyRejected", res.Refusal)
	}
	if after := w.passkeyState(id); after != afterFirst {
		t.Error("a backwards counter changed the passkey row")
	}
	if n := w.count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1 AND revoked_at IS NULL", id); n != 1 {
		t.Errorf("%d live sessions, want the first one only", n)
	}
	if got := w.loginEvents(id); !slices.Equal(got, []string{"signed_in", "bad_passkey"}) {
		t.Errorf("passkey_login events %v, want [signed_in bad_passkey]", got)
	}
}

func TestPasskeyLoginAcceptsZeroCounters(t *testing.T) {
	w := newWorld(t, passkeys)
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	for i := range 2 {
		a.SetCounter(0)
		if res := w.passkeySignIn("staff", a); res.Refusal != nil {
			t.Fatalf("sign-in %d refused: %v", i+1, res.Refusal)
		}
	}
	if n := w.count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", id); n != 2 {
		t.Errorf("%d sessions, want 2", n)
	}
	if n := w.count("SELECT count(*) FROM auth_passkeys WHERE principal_id = $1 AND COALESCE((data->'authenticator'->>'signCount')::int, 0) = 0", id); n != 1 {
		t.Errorf("the stored sign count is not 0")
	}
}

func TestPasskeyLoginAcceptsASyncedPasskey(t *testing.T) {
	w := newWorld(t, passkeys)
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	a.BackupEligible = true
	w.seedPasskey(id, a)
	if res := w.passkeySignIn("staff", a); res.Refusal != nil {
		t.Fatalf("synced passkey refused: %v", res.Refusal)
	}
	if n := w.count("SELECT count(*) FROM auth_passkeys WHERE principal_id = $1 AND data->'flags'->>'backupEligible' = 'true'", id); n != 1 {
		t.Errorf("the backup-eligible flag is not kept in the row")
	}
}

func TestPasskeyLoginGoesThroughAdmit(t *testing.T) {
	w := newWorld(t, passkeys)
	id := w.user("ada@example.invalid", "")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	before := w.passkeyState(id)
	w.p.Refuse(id, errDeactivated)
	res := w.passkeySignIn("staff", a)
	if !errors.Is(res.Refusal, errDeactivated) {
		t.Errorf("sign-in refusal = %v, want Admit's refusal", res.Refusal)
	}
	if errors.Is(res.Refusal, authkit.ErrPasskeyRejected) {
		t.Error("Admit's refusal came back as ErrPasskeyRejected")
	}
	if n := w.count("SELECT count(*) FROM auth_sessions WHERE principal_id = $1", id); n != 0 {
		t.Errorf("%d sessions opened for a refused principal, want 0", n)
	}
	if after := w.passkeyState(id); after != before {
		t.Error("a refused sign-in changed the passkey row")
	}
	if n := w.count("SELECT count(*) FROM auth_events WHERE source = 'passkey_login' AND result = 'no_membership' AND login = 'ada@example.invalid'"); n != 1 {
		t.Errorf("no passkey_login no_membership event for Ada")
	}
	if n := w.count("SELECT count(*) FROM auth_events"); n != 1 {
		t.Errorf("%d events, want 1", n)
	}
	if n := w.count("SELECT count(*) FROM auth_passkey_ceremonies WHERE used_at IS NOT NULL"); n != 1 {
		t.Errorf("the ceremony was not spent")
	}
}

func TestPasskeyLoginLeavesThePasswordThrottleAlone(t *testing.T) {
	w := newWorld(t, passkeys)
	const login = "ada@example.invalid"
	id := w.user(login, "the right password")
	a := authkittest.NewAuthenticator("localhost", staffOrigin)
	w.seedPasskey(id, a)
	for range 10 {
		w.login("staff", login, "wrong")
	}
	var locked authkit.ErrLocked
	if res := w.login("staff", login, "the right password"); !errors.As(res.Refusal, &locked) {
		t.Fatalf("password sign-in after 10 failures = %v, want ErrLocked", res.Refusal)
	}
	before := w.throttleRows()
	if res := w.passkeySignIn("staff", a); res.Refusal != nil {
		t.Fatalf("passkey sign-in on a locked login refused: %v", res.Refusal)
	}
	if after := w.throttleRows(); !slices.Equal(after, before) {
		t.Error("a passkey sign-in changed the password throttle")
	}
	if res := w.login("staff", login, "the right password"); !errors.As(res.Refusal, &locked) {
		t.Errorf("password sign-in after a passkey sign-in = %v, want ErrLocked", res.Refusal)
	}
}
