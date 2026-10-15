package tests

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/internal/kittest"
	"github.com/sylly-mika/authkit/passkey"
)

func withPasskeys(c *kittest.Rules) {
	c.Passkeys = passkey.Rules{RPID: "localhost", Origins: map[authkit.Audience][]string{"staff": {"http://localhost:3000"}, "client": {"http://localhost:3100"}}}
}

func (w *world) addStoredPasskey(owner uuid.UUID, label string, backedUp bool) uuid.UUID {
	w.T.Helper()
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		w.T.Fatal(err)
	}
	data, err := json.Marshal(webauthn.Credential{ID: credID, PublicKey: []byte{1}, Flags: webauthn.CredentialFlags{UserPresent: true, UserVerified: true, BackupEligible: backedUp, BackupState: backedUp}})
	if err != nil {
		w.T.Fatal(err)
	}
	id := uuid.New()
	w.D.Exec(w.T, "INSERT INTO auth_passkeys (id, principal_id, credential_id, label, data, created_at) VALUES ($1, $2, $3, $4, $5, $6)", id, owner, credID, label, string(data), w.Clock.Now())
	return id
}

func (w *world) listPasskeys(principal uuid.UUID) []authkit.Passkey {
	w.T.Helper()
	var out []authkit.Passkey
	if err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		var err error
		out, err = w.Svc.Passkeys.ListPasskeys(w.Ctx, q, principal)
		return err
	}); err != nil {
		w.T.Fatalf("ListPasskeys: %v", err)
	}
	return out
}

func (w *world) renamePasskey(c *authkit.Claims, id uuid.UUID, label string) (authkit.Result, error) {
	w.T.Helper()
	var res authkit.Result
	err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		var err error
		res, err = w.Svc.Passkeys.RenamePasskey(w.Ctx, q, c, id, label)
		return err
	})
	return res, err
}

func (w *world) deletePasskey(c *authkit.Claims, id uuid.UUID) (authkit.Result, error) {
	w.T.Helper()
	var res authkit.Result
	err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		var err error
		res, err = w.Svc.Passkeys.DeletePasskey(w.Ctx, q, c, id, authkit.Meta{IP: "192.0.2.7", UserAgent: "authkit-test"})
		return err
	})
	return res, err
}

func (w *world) sessionLive(id uuid.UUID) bool {
	w.T.Helper()
	return w.Count("SELECT count(*) FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL", id) == 1
}

func (w *world) storedLabel(id uuid.UUID) string {
	w.T.Helper()
	var label string
	if err := w.D.Row(w.T, "SELECT label FROM auth_passkeys WHERE id = $1", id).Scan(&label); err != nil {
		w.T.Fatal(err)
	}
	return label
}

func (w *world) passkeyRemovedEvents(principal uuid.UUID) int {
	w.T.Helper()
	return w.Count("SELECT count(*) FROM auth_events WHERE result = 'passkey_removed' AND principal_id = $1", principal)
}

func TestListPasskeysShowsOnlyTheCallersOwn(t *testing.T) {
	w := newWorld(t, withPasskeys)
	ada := w.User("ada@example.invalid", "the right password")
	bob := w.User("bob@example.invalid", "the right password")
	start := w.Clock.Now()
	x := w.addStoredPasskey(ada, "Laptop", false)
	w.Clock.Advance(time.Minute)
	y := w.addStoredPasskey(ada, "Phone", true)
	w.addStoredPasskey(bob, "Bob key", false)
	list := w.listPasskeys(ada)
	if len(list) != 2 {
		t.Fatalf("ada has %d passkeys, want 2", len(list))
	}
	if list[0].ID != x || list[0].Label != "Laptop" || !list[0].CreatedAt.Equal(start) || list[0].LastUsedAt != nil || list[0].BackedUp {
		t.Errorf("first passkey = %s %q, want %s Laptop created at the start, never used, not backed up", list[0].ID, list[0].Label, x)
	}
	if list[1].ID != y || list[1].Label != "Phone" || !list[1].CreatedAt.Equal(start.Add(time.Minute)) || !list[1].BackedUp {
		t.Errorf("second passkey = %s %q, want %s Phone created a minute later, backed up", list[1].ID, list[1].Label, y)
	}
	if got := w.listPasskeys(uuid.New()); len(got) != 0 {
		t.Errorf("an unknown principal has %d passkeys, want none", len(got))
	}
}

func TestListPasskeysShowsAPasskeyAsRegistrationReturnedIt(t *testing.T) {
	w := newWorld(t, withPasskeys)
	ada := w.User("ada@example.invalid", "the right password")
	c := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
	begin := regBegin(w, c)
	if begin.Refusal != nil || begin.Ceremony == nil {
		t.Fatalf("begin: refusal %v, ceremony given %v", begin.Refusal, begin.Ceremony != nil)
	}
	fin := regFinish(w, c, begin.Ceremony.ID, regCreate(t, regAuthn("http://localhost:3000"), begin.Ceremony), "Work laptop")
	if fin.Refusal != nil || fin.Passkey == nil {
		t.Fatalf("finish: refusal %v, passkey given %v", fin.Refusal, fin.Passkey != nil)
	}
	list := w.listPasskeys(ada)
	if len(list) != 1 {
		t.Fatalf("ada has %d passkeys, want 1", len(list))
	}
	got := list[0]
	if got.ID != fin.Passkey.ID || got.Label != "Work laptop" || !got.CreatedAt.Equal(fin.Passkey.CreatedAt) || got.LastUsedAt != nil || got.BackedUp != fin.Passkey.BackedUp {
		t.Errorf("listed %s %q backedUp=%v, registration returned %s %q backedUp=%v", got.ID, got.Label, got.BackedUp, fin.Passkey.ID, fin.Passkey.Label, fin.Passkey.BackedUp)
	}
}

func TestRenamePasskeyTrimsTheLabelAndKeepsTheRest(t *testing.T) {
	w := newWorld(t, withPasskeys)
	ada := w.User("ada@example.invalid", "the right password")
	c := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
	x := w.addStoredPasskey(ada, "Laptop", true)
	y := w.addStoredPasskey(ada, "Phone", false)
	var before string
	if err := w.D.Row(w.T, "SELECT data::text FROM auth_passkeys WHERE id = $1", x).Scan(&before); err != nil {
		t.Fatal(err)
	}
	events := w.Count("SELECT count(*) FROM auth_events WHERE principal_id = $1", ada)
	got, err := w.renamePasskey(c, x, "  Desk key \n")
	if err != nil || got.Refusal != nil {
		t.Fatalf("rename: refusal %v, err %v", got.Refusal, err)
	}
	if got.Passkey == nil || got.Passkey.ID != x || got.Passkey.Label != "Desk key" || !got.Passkey.BackedUp {
		t.Errorf("renamed passkey = %+v, want %s Desk key, backed up", got.Passkey, x)
	}
	if label := w.storedLabel(x); label != "Desk key" {
		t.Errorf("stored label of %s = %q, want %q", x, label, "Desk key")
	}
	var after string
	if err := w.D.Row(w.T, "SELECT data::text FROM auth_passkeys WHERE id = $1", x).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("rename changed the stored credential of %s", x)
	}
	if label := w.storedLabel(y); label != "Phone" {
		t.Errorf("the other passkey %s has label %q, want Phone", y, label)
	}
	if n := w.Count("SELECT count(*) FROM auth_events WHERE principal_id = $1", ada); n != events {
		t.Errorf("rename logged %d events, want none", n-events)
	}
}

func TestRenamePasskeyNeedsNoRecentSignIn(t *testing.T) {
	w := newWorld(t, withPasskeys)
	ada := w.User("ada@example.invalid", "the right password")
	c := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
	x := w.addStoredPasskey(ada, "Laptop", false)
	w.Clock.Advance(time.Hour)
	got, err := w.renamePasskey(c, x, "Old laptop")
	if err != nil || got.Refusal != nil {
		t.Fatalf("rename after an hour: refusal %v, err %v", got.Refusal, err)
	}
	if label := w.storedLabel(x); label != "Old laptop" {
		t.Errorf("stored label of %s = %q, want %q", x, label, "Old laptop")
	}
}

func TestRenamePasskeyRefusesABadLabel(t *testing.T) {
	w := newWorld(t, withPasskeys)
	ada := w.User("ada@example.invalid", "the right password")
	c := w.Claims(w.SignIn("ada@example.invalid", "the right password"))
	x := w.addStoredPasskey(ada, "Laptop", false)
	for _, bad := range []string{"", "   ", strings.Repeat("é", 65), "Bad\nlabel", "tab\tkey", "nul\x00"} {
		got, err := w.renamePasskey(c, x, bad)
		if err != nil || !errors.Is(got.Refusal, authkit.ErrPasskeyLabel) || got.Passkey != nil {
			t.Errorf("rename to %q: refusal %v, err %v, passkey given %v, want ErrPasskeyLabel", bad, got.Refusal, err, got.Passkey != nil)
		}
	}
	if label := w.storedLabel(x); label != "Laptop" {
		t.Errorf("refused renames changed the label of %s to %q", x, label)
	}
	full := strings.Repeat("é", 64)
	got, err := w.renamePasskey(c, x, full)
	if err != nil || got.Refusal != nil {
		t.Fatalf("rename to 64 runes: refusal %v, err %v", got.Refusal, err)
	}
	if label := w.storedLabel(x); label != full {
		t.Errorf("stored label of %s has %d runes, want the 64 given", x, len([]rune(label)))
	}
}

func TestRenameAndDeleteAnswerAForeignIdAsUnknown(t *testing.T) {
	w := newWorld(t, withPasskeys)
	ada := w.User("ada@example.invalid", "the right password")
	bob := w.User("bob@example.invalid", "the right password")
	a1 := w.SignIn("ada@example.invalid", "the right password")
	a2 := w.SignIn("ada@example.invalid", "the right password")
	c1 := w.Claims(a1)
	xa := w.addStoredPasskey(ada, "Laptop", false)
	xb := w.addStoredPasskey(bob, "Bob key", false)
	for _, id := range []uuid.UUID{xb, uuid.New()} {
		got, err := w.renamePasskey(c1, id, "Mine")
		if err != nil || !errors.Is(got.Refusal, authkit.ErrPasskeyNotFound) || got.Passkey != nil {
			t.Errorf("rename %s: refusal %v, err %v, want ErrPasskeyNotFound", id, got.Refusal, err)
		}
		got, err = w.deletePasskey(c1, id)
		if err != nil || !errors.Is(got.Refusal, authkit.ErrPasskeyNotFound) || got.Passkey != nil {
			t.Errorf("delete %s: refusal %v, err %v, want ErrPasskeyNotFound", id, got.Refusal, err)
		}
	}
	if label := w.storedLabel(xb); label != "Bob key" {
		t.Errorf("bob's passkey %s has label %q, want Bob key", xb, label)
	}
	if label := w.storedLabel(xa); label != "Laptop" {
		t.Errorf("ada's passkey %s has label %q, want Laptop", xa, label)
	}
	if !w.sessionLive(a2.Session.ID) {
		t.Error("a foreign delete revoked ada's other session")
	}
	if n := w.passkeyRemovedEvents(ada); n != 0 {
		t.Errorf("foreign deletes logged %d passkey_removed events, want none", n)
	}
}

func TestDeletePasskeyRevokesTheOtherSessions(t *testing.T) {
	rec := &captured{}
	w := newWorld(t, withPasskeys, func(c *kittest.Rules) { c.OnEvent = rec.onEvent })
	ada := w.User("ada@example.invalid", "the right password")
	w.User("bob@example.invalid", "the right password")
	a1 := w.SignIn("ada@example.invalid", "the right password")
	a2 := w.SignIn("ada@example.invalid", "the right password")
	b1 := w.SignIn("bob@example.invalid", "the right password")
	x := w.addStoredPasskey(ada, "Laptop", false)
	y := w.addStoredPasskey(ada, "Phone", false)
	rec.pairs = nil
	got, err := w.deletePasskey(w.Claims(a1), x)
	if err != nil || got.Refusal != nil {
		t.Fatalf("delete: refusal %v, err %v", got.Refusal, err)
	}
	if got.Passkey == nil || got.Passkey.ID != x || got.Passkey.Label != "Laptop" {
		t.Errorf("deleted passkey = %+v, want %s Laptop", got.Passkey, x)
	}
	if n := w.Count("SELECT count(*) FROM auth_passkeys WHERE id = $1", x); n != 0 {
		t.Errorf("passkey %s still stored", x)
	}
	if n := w.Count("SELECT count(*) FROM auth_passkeys WHERE id = $1", y); n != 1 {
		t.Errorf("passkey %s stored %d times, want 1", y, n)
	}
	if !w.sessionLive(a1.Session.ID) {
		t.Error("the caller's session was revoked")
	}
	if w.sessionLive(a2.Session.ID) {
		t.Error("the other session of ada is still live")
	}
	var at time.Time
	var reason string
	if err := w.D.Row(w.T, "SELECT revoked_at, revoke_reason FROM auth_sessions WHERE id = $1", a2.Session.ID).Scan(&at, &reason); err != nil {
		t.Fatal(err)
	}
	if !at.Equal(w.Clock.Now()) || reason != "passkey_removed" {
		t.Errorf("other session revoked at %v for %q, want now for passkey_removed", at, reason)
	}
	if !w.sessionLive(b1.Session.ID) {
		t.Error("bob's session was revoked")
	}
	if want := []string{"delete_passkey/passkey_removed"}; !slices.Equal(rec.pairs, want) {
		t.Errorf("events = %v, want %v", rec.pairs, want)
	}
	if n := w.Count("SELECT count(*) FROM auth_events WHERE result = 'passkey_removed' AND principal_id = $1 AND session_id = $2 AND ip = '192.0.2.7'", ada, a1.Session.ID); n != 1 {
		t.Errorf("passkey_removed events for the caller = %d, want 1", n)
	}
}

func TestDeletePasskeyNeedsARecentSignIn(t *testing.T) {
	w := newWorld(t, withPasskeys)
	ada := w.User("ada@example.invalid", "the right password")
	a1 := w.SignIn("ada@example.invalid", "the right password")
	a2 := w.SignIn("ada@example.invalid", "the right password")
	x := w.addStoredPasskey(ada, "Laptop", false)
	w.Clock.Advance(5*time.Minute + time.Second)
	got, err := w.deletePasskey(w.Claims(a1), x)
	if err != nil || !errors.Is(got.Refusal, authkit.ErrReauthRequired) || got.Passkey != nil {
		t.Errorf("delete after the re-auth window: refusal %v, err %v, passkey given %v, want ErrReauthRequired", got.Refusal, err, got.Passkey != nil)
	}
	if n := w.Count("SELECT count(*) FROM auth_passkeys WHERE id = $1", x); n != 1 {
		t.Errorf("passkey %s stored %d times after a refused delete, want 1", x, n)
	}
	if !w.sessionLive(a2.Session.ID) {
		t.Error("a refused delete revoked the other session")
	}
	if n := w.passkeyRemovedEvents(ada); n != 0 {
		t.Errorf("a refused delete logged %d passkey_removed events, want none", n)
	}
}

func TestDeletePasskeyCountsFromTheLastPasswordProof(t *testing.T) {
	w := newWorld(t, withPasskeys)
	ada := w.User("ada@example.invalid", "the right password")
	a1 := w.SignIn("ada@example.invalid", "the right password")
	x := w.addStoredPasskey(ada, "Laptop", false)
	w.Clock.Advance(10 * time.Minute)
	changed := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.Password.ChangePassword(w.Ctx, q, w.Claims(a1), "the right password", "another password", authkit.Meta{})
	})
	if changed.Refusal != nil {
		t.Fatalf("change password: refusal %v", changed.Refusal)
	}
	w.Clock.Advance(4 * time.Minute)
	got, err := w.deletePasskey(w.Claims(a1), x)
	if err != nil || got.Refusal != nil {
		t.Fatalf("delete four minutes after the password proof: refusal %v, err %v", got.Refusal, err)
	}
	if n := w.Count("SELECT count(*) FROM auth_passkeys WHERE id = $1", x); n != 0 {
		t.Errorf("passkey %s still stored", x)
	}
}

func TestDeletePasskeyFromASwitchedSessionKeepsItsSignInTime(t *testing.T) {
	w := newWorld(t, withPasskeys)
	ada := w.User("ada@example.invalid", "the right password")
	p := authkit.Principal{ID: ada, Login: "ada@example.invalid"}
	x := w.addStoredPasskey(ada, "Laptop", false)
	y := w.addStoredPasskey(ada, "Phone", false)

	s0 := w.SignIn("ada@example.invalid", "the right password")
	w.Clock.Advance(time.Minute)
	s1 := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.OpenSessionFrom(w.Ctx, q, s0.Session.ID, p, "staff", authkit.Meta{})
	})
	if s1.Refusal != nil {
		t.Fatalf("switch: refusal %v", s1.Refusal)
	}
	got, err := w.deletePasskey(w.Claims(s1), x)
	if err != nil || got.Refusal != nil {
		t.Fatalf("delete from a switched session: refusal %v, err %v", got.Refusal, err)
	}

	s2 := w.SignIn("ada@example.invalid", "the right password")
	w.Clock.Advance(5*time.Minute + time.Second)
	s3 := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.OpenSessionFrom(w.Ctx, q, s2.Session.ID, p, "staff", authkit.Meta{})
	})
	if s3.Refusal != nil {
		t.Fatalf("second switch: refusal %v", s3.Refusal)
	}
	got, err = w.deletePasskey(w.Claims(s3), y)
	if err != nil || !errors.Is(got.Refusal, authkit.ErrReauthRequired) {
		t.Errorf("delete from a switch of an old sign-in: refusal %v, err %v, want ErrReauthRequired", got.Refusal, err)
	}
	if n := w.Count("SELECT count(*) FROM auth_passkeys WHERE id = $1", y); n != 1 {
		t.Errorf("passkey %s stored %d times after a refused delete, want 1", y, n)
	}
}

func TestDeletePasskeyRefusesAnEndedSession(t *testing.T) {
	w := newWorld(t, withPasskeys)
	ada := w.User("ada@example.invalid", "the right password")
	a1 := w.SignIn("ada@example.invalid", "the right password")
	a2 := w.SignIn("ada@example.invalid", "the right password")
	x := w.addStoredPasskey(ada, "Laptop", false)
	w.D.Exec(w.T, "UPDATE auth_sessions SET revoked_at = $2, revoke_reason = 'logout' WHERE id = $1", a1.Session.ID, w.Clock.Now())
	got, err := w.deletePasskey(w.Claims(a1), x)
	if err != nil || !errors.Is(got.Refusal, authkit.ErrReauthRequired) {
		t.Errorf("delete from an ended session: refusal %v, err %v, want ErrReauthRequired", got.Refusal, err)
	}
	if n := w.Count("SELECT count(*) FROM auth_passkeys WHERE id = $1", x); n != 1 {
		t.Errorf("passkey %s stored %d times after a refused delete, want 1", x, n)
	}
	if !w.sessionLive(a2.Session.ID) {
		t.Error("a refused delete revoked the other session")
	}
	if n := w.passkeyRemovedEvents(ada); n != 0 {
		t.Errorf("a refused delete logged %d passkey_removed events, want none", n)
	}
}

func TestPasskeyManagementIsOffWithoutAnRPID(t *testing.T) {
	w := newWorld(t)
	ada := w.User("ada@example.invalid", "the right password")
	a1 := w.SignIn("ada@example.invalid", "the right password")
	a2 := w.SignIn("ada@example.invalid", "the right password")
	c1 := w.Claims(a1)
	x := w.addStoredPasskey(ada, "Laptop", false)
	err := w.D.InAuthTx(w.Ctx, func(q db.Querier) error {
		_, err := w.Svc.Passkeys.ListPasskeys(w.Ctx, q, ada)
		return err
	})
	if !errors.Is(err, authkit.ErrPasskeysOff) {
		t.Errorf("ListPasskeys = %v, want ErrPasskeysOff", err)
	}
	if _, err := w.renamePasskey(c1, x, "New"); !errors.Is(err, authkit.ErrPasskeysOff) {
		t.Errorf("RenamePasskey = %v, want ErrPasskeysOff", err)
	}
	if _, err := w.deletePasskey(c1, x); !errors.Is(err, authkit.ErrPasskeysOff) {
		t.Errorf("DeletePasskey = %v, want ErrPasskeysOff", err)
	}
	if label := w.storedLabel(x); label != "Laptop" {
		t.Errorf("passkey %s has label %q, want Laptop", x, label)
	}
	if !w.sessionLive(a2.Session.ID) {
		t.Error("a passkey method with passkeys off revoked the other session")
	}
	if n := w.passkeyRemovedEvents(ada); n != 0 {
		t.Errorf("passkeys off logged %d passkey_removed events, want none", n)
	}
}

func TestDeletePasskeyWaitsForTheCredentialLock(t *testing.T) {
	w := newWorld(t, withPasskeys)
	ada := w.User("ada@example.invalid", "the right password")
	a1 := w.SignIn("ada@example.invalid", "the right password")
	c := w.Claims(a1)
	x := w.addStoredPasskey(ada, "Laptop", false)
	holder, err := w.D.Owner.BeginTx(w.Ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(w.Ctx, "SELECT 1 FROM auth_credentials WHERE principal_id = $1 FOR UPDATE", ada); err != nil {
		t.Fatal(err)
	}
	conn := w.Pinned(ada)
	type outcome struct {
		res authkit.Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		var res authkit.Result
		err := authkittest.InConnTx(w.Ctx, conn, func(q db.Querier) error {
			var err error
			res, err = w.Svc.Passkeys.DeletePasskey(w.Ctx, q, c, x, authkit.Meta{})
			return err
		})
		done <- outcome{res, err}
	}()
	w.D.WaitForLockWaiters(w.T, 1)
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	o := <-done
	if o.err != nil || o.res.Refusal != nil {
		t.Fatalf("delete after the lock: refusal %v, err %v", o.res.Refusal, o.err)
	}
	if n := w.Count("SELECT count(*) FROM auth_passkeys WHERE id = $1", x); n != 0 {
		t.Errorf("passkey %s still stored", x)
	}
}
