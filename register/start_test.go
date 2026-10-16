package register_test

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/authkittest"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/sqldb"
	"github.com/sylly-mika/authkit/password"
	"github.com/sylly-mika/authkit/register"
)

func newService(t *testing.T) (*authkit.Service, *password.Module) {
	t.Helper()
	svc, err := authkit.New(authkit.Config{Issuer: "test", Secret: []byte("a-test-secret-of-at-least-32-bytes!")}, authkittest.NewPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	pw, err := password.New(svc, password.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return svc, pw
}

func TestNewRefuses(t *testing.T) {
	svc, pw := newService(t)
	ok := register.Rules{Create: stub}
	refused := []struct {
		name string
		pw   *password.Module
		r    register.Rules
		want string
	}{
		{"Create nil", pw, register.Rules{}, "register: Rules.Create is nil"},
		{"password nil", nil, ok, "register: the password module is nil"},
		{"TTL negative", pw, register.Rules{Create: stub, TTL: -1}, "register: Rules.TTL is negative"},
		{"MailCap negative", pw, register.Rules{Create: stub, MailCap: -1}, "register: Rules.MailCap is negative"},
		{"MailWindow negative", pw, register.Rules{Create: stub, MailWindow: -1}, "register: Rules.MailWindow is negative"},
		{"Floor negative", pw, register.Rules{Create: stub, Floor: -1}, "register: Rules.Floor is negative"},
		{"MailWindow over 24h", pw, register.Rules{Create: stub, MailWindow: 24*time.Hour + time.Nanosecond}, "register: Rules.MailWindow is longer than 24h"},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			m, err := register.New(svc, c.pw, c.r)
			if m != nil {
				t.Fatal("New returned a module for a refused rule set")
			}
			if err == nil || err.Error() != c.want {
				t.Fatalf("New error = %v; want %q", err, c.want)
			}
		})
	}

	m, err := register.New(svc, pw, ok)
	if err != nil {
		t.Fatalf("New after the refusals: %v", err)
	}
	if got := m.Floor(); got != 500*time.Millisecond {
		t.Fatalf("Floor() = %v; want 500ms", got)
	}
	if _, err := register.New(svc, pw, ok); !errors.Is(err, authkit.ErrAttached) {
		t.Fatalf("second New error = %v; want authkit.ErrAttached", err)
	}

	svc2, pw2 := newService(t)
	if _, err := register.New(svc2, pw2, register.Rules{Create: stub, MailWindow: 24 * time.Hour}); err != nil {
		t.Fatalf("New with a 24h window: %v", err)
	}
}

func TestStartNew(t *testing.T) {
	f := newFixture(t)
	T0 := f.Clock.Now()
	before := f.Count("SELECT count(*) FROM users")
	st := f.start("staff", "  Ada@Example.INVALID ", pAda)
	if st.TokenID == nil || st.Holder != nil || st.RetryAfter != 0 {
		t.Fatalf("Start decided %+v; want a new link only", st)
	}
	if n := f.Count("SELECT count(*) FROM auth_registrations WHERE email = $1 AND audience = 'staff' AND payload->>'given_name' = 'Ada' AND created_at = $2 AND expires_at = $3", addr, T0, T0.Add(48*time.Hour)); n != 1 {
		t.Fatalf("registration rows = %d; want 1", n)
	}
	if n := f.Count("SELECT count(*) FROM auth_tokens WHERE id = $1 AND purpose = 'register' AND owner_id = $2 AND token_hash IS NULL AND used_at IS NULL AND revoked_at IS NULL", *st.TokenID, f.regID("staff", addr)); n != 1 {
		t.Fatalf("link rows = %d; want 1", n)
	}
	if n := f.Count("SELECT count(*) FROM users"); n != before {
		t.Fatalf("users = %d; want %d", n, before)
	}
	for _, table := range []string{"auth_credentials", "auth_events"} {
		if n := f.Count("SELECT count(*) FROM " + table); n != 0 {
			t.Fatalf("%s rows = %d; want 0", table, n)
		}
	}
}

func TestStartHeld(t *testing.T) {
	f := newFixture(t)
	id := f.User(addr, "")
	st := f.start("staff", " ADA@example.invalid", "{}")
	if st.Holder == nil || st.Holder.ID != id || st.TokenID != nil || st.RetryAfter != 0 {
		t.Fatalf("Start decided %+v; want the holder only", st)
	}
	for _, table := range []string{"auth_registrations", "auth_tokens", "auth_events"} {
		if n := f.Count("SELECT count(*) FROM " + table); n != 0 {
			t.Fatalf("%s rows = %d; want 0", table, n)
		}
	}
	if n := f.Count("SELECT count(*) FROM auth_mail_counts WHERE audience = 'staff' AND sent = 1"); n != 1 {
		t.Fatalf("mail count rows = %d; want 1", n)
	}
}

func TestStartNeedsTx(t *testing.T) {
	f := newFixture(t)
	id := f.User("x@example.invalid", "")
	var n int
	q := counted{Querier: sqldb.Conn(f.Pinned(id)), n: &n}
	calls := []struct {
		name string
		call func() error
	}{
		{"Start", func() error { _, err := f.Reg.Start(f.Ctx, q, "staff", addr, nil); return err }},
		{"CountMail", func() error { _, err := f.Reg.CountMail(f.Ctx, q, "staff", addr); return err }},
		{"Mint", func() error { _, err := f.Reg.Mint(f.Ctx, q, uuid.New()); return err }},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			n = 0
			if err := c.call(); !errors.Is(err, db.ErrTxRequired) || n != 0 {
				t.Fatalf("%s on a bare connection: err = %v, statements = %d; want db.ErrTxRequired and 0", c.name, err, n)
			}
		})
	}
	for _, table := range []string{"auth_mail_counts", "auth_registrations", "auth_tokens"} {
		if got := f.Count("SELECT count(*) FROM " + table); got != 0 {
			t.Fatalf("%s rows = %d; want 0", table, got)
		}
	}
}

func TestCountMailCommitted(t *testing.T) {
	f := newFixture(t)
	for i := 1; i <= 3; i++ {
		if st := f.start("staff", addr, "{}"); st.TokenID == nil {
			t.Fatalf("start %d decided %+v; want a link", i, st)
		}
	}
	st4 := f.start("staff", addr, "{}")
	if st4.TokenID != nil || st4.Holder != nil || st4.RetryAfter != time.Hour {
		t.Fatalf("start 4 decided %+v; want RetryAfter 1h only", st4)
	}
	if n := f.Count("SELECT sent FROM auth_mail_counts WHERE audience = 'staff'"); n != 4 {
		t.Fatalf("sent after start 4 = %d; want 4", n)
	}
	if n := f.Count("SELECT count(*) FROM auth_tokens t JOIN auth_registrations r ON r.id = t.owner_id WHERE r.audience = 'staff'"); n != 3 {
		t.Fatalf("links after start 4 = %d; want 3", n)
	}
	f.Clock.Advance(30 * time.Minute)
	st5 := f.start("staff", addr, "{}")
	if st5.TokenID != nil || st5.RetryAfter != 30*time.Minute {
		t.Fatalf("start 5 decided %+v; want RetryAfter 30m only", st5)
	}
	if n := f.Count("SELECT sent FROM auth_mail_counts WHERE audience = 'staff'"); n != 5 {
		t.Fatalf("sent after start 5 = %d; want 5", n)
	}
	if c := f.start("client", addr, "{}"); c.TokenID == nil {
		t.Fatalf("a different audience decided %+v; want a link", c)
	}
	if n := f.Count("SELECT count(*) FROM auth_mail_counts"); n != 2 {
		t.Fatalf("mail count rows = %d; want 2", n)
	}
}

func TestCountMailWindowReopens(t *testing.T) {
	f := newFixture(t)
	T0 := f.Clock.Now()
	for i := 1; i <= 3; i++ {
		if d := f.count("staff", addr); d != 0 {
			t.Fatalf("call %d waits %v; want 0", i, d)
		}
	}
	if d := f.count("staff", addr); d != time.Hour {
		t.Fatalf("call 4 waits %v; want 1h", d)
	}
	f.Clock.Advance(59 * time.Minute)
	if d := f.count("staff", addr); d != time.Minute {
		t.Fatalf("call at T0+59m waits %v; want 1m", d)
	}
	f.Clock.Advance(time.Minute)
	if d := f.count("staff", addr); d != 0 {
		t.Fatalf("call at T0+1h waits %v; want 0", d)
	}
	if n := f.Count("SELECT count(*) FROM auth_mail_counts WHERE sent = 1 AND window_started_at = $1", T0.Add(time.Hour)); n != 1 {
		t.Fatalf("reopened window rows = %d; want 1", n)
	}
}

func TestCountTableHoldsNoAddress(t *testing.T) {
	const a32 = "ada.lovelace1234@example.invalid"
	f := newFixture(t)
	f.start("staff", " Ada.Lovelace1234@EXAMPLE.invalid ", "{}")
	key := sha256.Sum256([]byte(a32))
	if n := f.Count("SELECT count(*) FROM auth_mail_counts WHERE email_key = $1", key[:]); n != 1 {
		t.Fatalf("rows under the address digest = %d; want 1", n)
	}
	if n := f.Count("SELECT count(*) FROM auth_mail_counts WHERE position(convert_to($1, 'UTF8') IN email_key) > 0 OR audience = $1", a32); n != 0 {
		t.Fatalf("rows holding the address = %d; want 0", n)
	}
}

func TestStartResendSupersedes(t *testing.T) {
	f := newFixture(t)
	T0 := f.Clock.Now()
	st1 := f.start("staff", addr, pAda)
	id1 := f.regID("staff", addr)
	m1, err := f.mint(*st1.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	f.Clock.Advance(time.Hour)
	st2 := f.start("staff", " ADA@example.invalid", pAugusta)
	if *st2.TokenID == *st1.TokenID {
		t.Fatal("the resend kept the first link")
	}
	_, errOld := f.mint(*st1.TokenID)
	m2, errNew := f.mint(*st2.TokenID)
	_, spentOld := f.spend(m1.Raw)
	tok, spentNew := f.spend(m2.Raw)
	if n := f.Count("SELECT count(*) FROM auth_registrations"); n != 1 {
		t.Fatalf("registration rows = %d; want 1", n)
	}
	if f.regID("staff", addr) != id1 {
		t.Fatal("the resend changed the registration id")
	}
	if n := f.Count("SELECT count(*) FROM auth_registrations WHERE id = $1 AND payload->>'given_name' = 'Augusta' AND created_at = $2 AND expires_at = $3", id1, T0.Add(time.Hour), T0.Add(49*time.Hour)); n != 1 {
		t.Fatalf("the resent row does not hold the latest payload and expiry")
	}
	if !errors.Is(errOld, register.ErrNothingToSend) {
		t.Fatalf("minting the superseded link = %v; want ErrNothingToSend", errOld)
	}
	if errNew != nil {
		t.Fatalf("minting the live link: %v", errNew)
	}
	var p struct {
		GivenName string `json:"given_name"`
	}
	if err := json.Unmarshal(m2.Payload, &p); err != nil || p.GivenName != "Augusta" {
		t.Fatal("the mail payload is not the latest registration's")
	}
	if !errors.Is(spentOld, authkit.ErrTokenUnknown) {
		t.Fatalf("spending the superseded link = %v; want ErrTokenUnknown", spentOld)
	}
	if spentNew != nil || tok.Owner != id1 {
		t.Fatalf("spending the live link = %v, owner %v; want the registration", spentNew, tok.Owner)
	}
}

func TestMintGone(t *testing.T) {
	cases := []struct {
		name     string
		unminted bool
		setup    func(t *testing.T, f *fixture) uuid.UUID
	}{
		{"unknown", false, func(*testing.T, *fixture) uuid.UUID { return uuid.New() }},
		{"expired", true, func(_ *testing.T, f *fixture) uuid.UUID {
			st := f.start("staff", addr, pAda)
			f.Clock.Advance(48 * time.Hour)
			return *st.TokenID
		}},
		{"deleted", true, func(t *testing.T, f *fixture) uuid.UUID {
			st := f.start("staff", addr, pAda)
			f.D.Exec(t, "DELETE FROM auth_registrations")
			return *st.TokenID
		}},
		{"superseded", true, func(_ *testing.T, f *fixture) uuid.UUID {
			first := f.start("staff", addr, pAda)
			f.start("staff", addr, pAugusta)
			return *first.TokenID
		}},
		{"spent", false, func(t *testing.T, f *fixture) uuid.UUID {
			st := f.start("staff", addr, pAda)
			m, err := f.mint(*st.TokenID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.spend(m.Raw); err != nil {
				t.Fatal(err)
			}
			return *st.TokenID
		}},
		{"purpose", true, func(t *testing.T, f *fixture) uuid.UUID {
			f.start("staff", addr, pAda)
			var rid uuid.UUID
			if err := f.D.InAuthTx(f.Ctx, func(q db.Querier) error {
				var err error
				rid, err = f.Svc.OneTime().Create(f.Ctx, q, authkit.PurposeReset, f.regID("staff", addr), time.Hour)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return rid
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			id := c.setup(t, f)
			mail, err := f.mint(id)
			if !errors.Is(err, register.ErrNothingToSend) || mail.To != "" || mail.Raw != "" || len(mail.Payload) != 0 || !mail.ExpiresAt.IsZero() {
				t.Fatalf("Mint = %+v, %v; want ErrNothingToSend and no mail", mail.ExpiresAt, err)
			}
			if c.unminted {
				if n := f.Count("SELECT count(*) FROM auth_tokens WHERE id = $1 AND token_hash IS NULL", id); n != 1 {
					t.Fatalf("link rows without a hash = %d; want 1", n)
				}
			}
		})
	}
}

func TestMintExpiresAt(t *testing.T) {
	t.Run("registration first", func(t *testing.T) {
		f := newFixture(t)
		T0 := f.Clock.Now()
		st := f.start("staff", addr, pAda)
		f.Clock.Advance(2 * time.Hour)
		mail, err := f.mint(*st.TokenID)
		if err != nil {
			t.Fatal(err)
		}
		if !mail.ExpiresAt.Equal(T0.Add(48 * time.Hour)) {
			t.Fatalf("ExpiresAt = %v; want the registration's %v", mail.ExpiresAt, T0.Add(48*time.Hour))
		}
		if mail.To != addr {
			t.Fatal("the mail is addressed to another address")
		}
		var p struct {
			GivenName string `json:"given_name"`
		}
		if err := json.Unmarshal(mail.Payload, &p); err != nil || p.GivenName != "Ada" {
			t.Fatal("the mail payload is not the registration's")
		}
		tok, err := f.spend(mail.Raw)
		if err != nil || tok.Owner != f.regID("staff", addr) {
			t.Fatalf("spending the minted link = %v; want the registration as owner", err)
		}
		if n := f.Count("SELECT count(*) FROM auth_tokens WHERE id = $1 AND expires_at = $2", *st.TokenID, T0.Add(50*time.Hour)); n != 1 {
			t.Fatalf("the link's own expiry changed: rows = %d; want 1", n)
		}
	})
	t.Run("token first", func(t *testing.T) {
		f := newFixture(t)
		T0 := f.Clock.Now()
		st := f.start("staff", addr, pAda)
		f.D.Exec(t, "UPDATE auth_registrations SET expires_at = expires_at + interval '4 hours'")
		f.Clock.Advance(2 * time.Hour)
		mail, err := f.mint(*st.TokenID)
		if err != nil {
			t.Fatal(err)
		}
		if !mail.ExpiresAt.Equal(T0.Add(50 * time.Hour)) {
			t.Fatalf("ExpiresAt = %v; want the link's %v", mail.ExpiresAt, T0.Add(50*time.Hour))
		}
	})
}
