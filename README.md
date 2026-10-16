# authkit

authkit is a Go library for password authentication on PostgreSQL. It covers
password sign-in, sessions with token-reuse detection, password reset,
registration with an emailed activation link, sign-in with Google and Apple
(OpenID Connect), one-time links, a sign-in log, a per-login throttle,
passkeys and second factors (TOTP, emailed codes, recovery codes), invites,
erasure of a person's authkit rows, re-verification before sensitive changes
and verified email change. Passwords are hashed with argon2id. authkit owns
its `auth_*` tables; your app owns its users ("principals") table and its own
data.

The core package `authkit` owns sessions, the login throttle, `Admit`, the
second-factor gate, the sign-in log, `Forget` and `RequireRecent`. Password
sign-in, passkeys, second factors, registration, OIDC sign-in, invites and
email change are modules (`password`, `passkey`, `secondfactor`, `register`,
`oidc`, `invite`, `emailchange`); an app links only the modules it imports.

What it does not do:

- It never opens a transaction and never sets a row-level security (RLS)
  setting. Your app passes a transaction to every call.
- It does not send email. It gives you an ID to enqueue; your mail worker
  turns the ID into a code or link and sends it.
- It does not map refusals to HTTP status codes. Your app renders them.
- It reads no environment variables.

The API may change between minor versions until 1.0.

## Install

```sh
go get github.com/sylly-mika/authkit@v0.6.0
```

Requirements:

- Go 1.26 or later (`go.mod` says `go 1.26.0`).
- PostgreSQL. The tests and CI run PostgreSQL 17.
- A table of principals whose `id` column is a `uuid`.
- Optional: `github.com/labstack/echo/v5` if you use the `echov5`
  middleware, and `github.com/jackc/pgx/v5` if you use the `db/pgxdb` adapter.
  `db/sqldb` adapts `database/sql` instead.

Packages you will use:

| Package | Use |
|---|---|
| `authkit` | the core: `Config`, `New`, `Service` (sessions, `Admit`, the second-factor gate, the sign-in log); `Core` for module authors |
| `password` | `password.New`, `*password.Module`: password sign-in, reset and changes; the argon2id hasher |
| `passkey` | `passkey.New`, `*passkey.Module`: passkey sign-in and management (links `go-webauthn`) |
| `secondfactor` | `secondfactor.New`, `*secondfactor.Module`: TOTP, emailed codes, recovery codes (links `pquerna/otp`) |
| `oidc` | `oidc.New`, `*oidc.Module`: sign-in, sign-up and linking with Google, Apple or another OpenID Connect provider (links `go-oidc`, `go-jose`, `oauth2`) |
| `register` | `register.New`, `*register.Module`: sign-up with an emailed activation link; the password is set at activation |
| `db` | `db.Querier`, the SQL interface every method runs on |
| `db/pgxdb`, `db/sqldb` | wrap a pgx or `database/sql` transaction as a `db.Querier` |
| `echov5` | echo v5 middleware |
| `transport/cookie` | the session cookie (Session mode) |
| `cmd/authkit-gen` | copies authkit's migrations into your migration directory |
| `authkittest` | Postgres test harness, fake principals, software passkey authenticator |
| `authkittest/oidcfake` | a local Google or Apple over `httptest` TLS, for tests of your OIDC routes (links `go-oidc`) |

## Minimal example

This app signs users in with a password and keeps them signed in with a
session cookie. It uses echo v5 and pgx. Before it runs, generate and apply
the migrations (see "Add the database tables").

```go
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"
	"golang.org/x/time/rate"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
	"github.com/sylly-mika/authkit/db/pgxdb"
	"github.com/sylly-mika/authkit/echov5"
	"github.com/sylly-mika/authkit/password"
	"github.com/sylly-mika/authkit/transport/cookie"
)

// users is the app side of authkit: it finds principals and admits sessions.
type users struct{}

func (users) Lookup(ctx context.Context, q db.Querier, login string, aud authkit.Audience) (authkit.Principal, error) {
	// login arrives normalised (authkit.Normalize: trimmed, NFC, lower case).
	var p authkit.Principal
	err := q.QueryRow(ctx, `SELECT id, email FROM users WHERE email = $1`, login).Scan(&p.ID, &p.Login)
	if errors.Is(err, db.ErrNoRows) {
		return p, authkit.ErrUnknownLogin
	}
	return p, err
}

func (users) ByID(ctx context.Context, q db.Querier, id uuid.UUID, aud authkit.Audience) (authkit.Principal, error) {
	var p authkit.Principal
	err := q.QueryRow(ctx, `SELECT id, email FROM users WHERE id = $1`, id).Scan(&p.ID, &p.Login)
	if errors.Is(err, db.ErrNoRows) {
		return p, authkit.ErrUnknownLogin
	}
	return p, err
}

func (users) Admit(ctx context.Context, q db.Querier, p authkit.Proposal) (authkit.Admission, error) {
	return authkit.Admission{}, nil // everyone with a valid password may sign in
}

const aud authkit.Audience = "web"

func main() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, "postgres://app@localhost/app")
	if err != nil {
		log.Fatal(err)
	}
	inTx := func(ctx context.Context, fn func(q db.Querier) error) error {
		return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error { return fn(pgxdb.Tx(tx)) })
	}

	kit, err := authkit.New(authkit.Config{Transport: authkit.TransportSession}, users{})
	if err != nil {
		log.Fatal(err)
	}
	passwords, err := password.New(kit, password.Config{})
	if err != nil {
		log.Fatal(err)
	}
	// Refuse to start on a database older than the library.
	if err := inTx(ctx, func(q db.Querier) error { return authkit.CheckSchema(ctx, q) }); err != nil {
		log.Fatal(err)
	}

	opts := cookie.Options{Name: "session"} // sets __Host-session
	e := echo.New()
	g := e.Group("",
		echov5.SessionCookie(kit, aud, opts, inTx),
		echov5.RequireOrigin([]string{"https://app.example.com"}),
	)
	g.POST("/login", login(passwords, inTx, opts), echov5.RateLimit(rate.Limit(1), 5), echov5.HashSlot(passwords))
	g.GET("/me", me, echov5.RequireSession(opts, false))
	log.Fatal(http.ListenAndServe(":8080", e))
}

func login(passwords *password.Module, inTx func(context.Context, func(db.Querier) error) error, opts cookie.Options) echo.HandlerFunc {
	return func(c *echo.Context) error {
		ctx := c.Request().Context() // carries the hash slot HashSlot took
		m := authkit.Meta{IP: c.RealIP(), UserAgent: c.Request().UserAgent()}
		var res authkit.Result
		err := inTx(ctx, func(q db.Querier) error {
			var err error
			res, err = passwords.Login(ctx, q, aud, c.FormValue("login"), c.FormValue("password"), m)
			return err // a refusal is not an error: the transaction commits the throttle count
		})
		var locked authkit.ErrLocked
		switch {
		case err != nil:
			return err
		case errors.As(res.Refusal, &locked):
			c.Response().Header().Set("Retry-After", strconv.Itoa(int(locked.RetryAfter.Seconds())))
			return c.NoContent(http.StatusTooManyRequests)
		case errors.Is(res.Refusal, authkit.ErrBusy):
			return c.NoContent(http.StatusServiceUnavailable)
		case res.Refusal != nil:
			return c.NoContent(http.StatusUnauthorized)
		}
		opts.Set(c.Response(), res.SessionToken, res.Session.AbsoluteExpiresAt)
		return c.NoContent(http.StatusNoContent)
	}
}

func me(c *echo.Context) error {
	res, _ := echov5.Session(c) // RequireSession has already refused requests without one
	return c.JSON(http.StatusOK, map[string]any{"id": res.Principal.ID})
}
```

What the pieces do:

- `SessionCookie` reads the cookie, checks the session in its own transaction
  (`AuthenticateSession`), sets the rotated cookie when the token is swapped,
  and stores the `Result` for `echov5.Session`. A request with no cookie opens
  no transaction. A refused session is committed and the request continues
  with no stored session.
- `RequireSession` returns `authkit.ErrSessionEnded` when there is no stored
  session and clears the cookie (unless `keepCookie` is true).
- `RequireOrigin` refuses a non-GET/HEAD/OPTIONS request whose `Origin` header
  is absent or not in the list (`cookie.ErrForeignOrigin`). There is no
  `Referer` fallback, and a `*` entry is ignored.
- `HashSlot` takes one argon2id slot before the handler opens its transaction
  and returns `authkit.ErrBusy` when none frees up within `HashWait`.
- `RateLimit(r, burst)` is a per-IP limiter for the auth routes.

Each middleware returns its refusal as the handler error. Map them in your
echo error handler; the codes in "Errors and refusals" are the ones the
package documentation suggests.

## Common tasks

### Wire modules

`authkit.New` builds the core. Each module's `New` takes that
`*authkit.Service` and the module's own rules, and attaches once per
`Service`: a second `New` of the same module returns `authkit.ErrAttached`.
An app links only the modules it imports: without `passkey` the binary has no
`go-webauthn`, without `secondfactor` no `pquerna/otp`, without `oidc` no
`go-oidc`, `go-jose` or `oauth2`. Bundle them in one
struct; the examples below call it `kit`:

```go
type Kit struct {
	*authkit.Service
	Password *password.Module
	Passkeys *passkey.Module
	Factors  *secondfactor.Module
}

func NewKit(cfg authkit.Config, principals authkit.Principals) (*Kit, error) {
	core, err := authkit.New(cfg, principals)
	if err != nil {
		return nil, err
	}
	k := &Kit{Service: core}
	if k.Password, err = password.New(core, password.Config{}); err != nil {
		return nil, err
	}
	if k.Passkeys, err = passkey.New(core, passkey.Rules{}); err != nil {
		return nil, err
	}
	k.Factors, err = secondfactor.New(core, secondfactor.Rules{})
	return k, err
}
```

Core methods (`Authenticate`, `Refresh`, `OpenSession`, `VerifySecondStep`,
`SendSecondStepEmail`, `Prune` and the rest) stay on `kit`; module methods are
on `kit.Password`, `kit.Passkeys` and `kit.Factors`. A module given empty
rules is attached but off: `passkey` without `RPID` answers
`ErrPasskeysOff`; `secondfactor` without `Key` answers `ErrSecondFactorsOff`,
and so does a sign-in by a principal with a confirmed factor. Leaving
`secondfactor` out has the same effect. `oidc`, `register`, `invite` and
`emailchange` attach the same way; add `OIDC *oidc.Module`,
`Register *register.Module`, `Invite *invite.Module` and
`EmailChange *emailchange.Module` to `Kit` (see "Add Google and Apple
sign-in", "Add registration", "Invite people" and "Change a sign-in email").

### Add the database tables

The migrations are embedded in the module. `authkit-gen` copies them into
your migration directory, numbered after your own migrations, with your
principals table filled in:

```sh
go run github.com/sylly-mika/authkit/cmd/authkit-gen -principals users -out migrations
go run github.com/sylly-mika/authkit/cmd/authkit-gen -principals users -out migrations -format goose
```

| Flag | Default | Meaning |
|---|---|---|
| `-principals` | required | your principals table |
| `-schema` | none | put the tables in this PostgreSQL schema (see "Run two installs in one database") |
| `-out` | `migrations` | your migration directory |
| `-lock` | `authkit.lock` (`authkit.<schema>.lock` with `-schema`) | records what was written, so a later run adds only new migrations |
| `-format` | `golang-migrate` | `golang-migrate` writes `NNNNNN_authkit_<name>.up.sql` and `.down.sql`; `goose` writes one `NNNNN_authkit_<name>.sql` with `-- +goose Up` and `-- +goose Down` |

With `goose`, numbering follows the highest `N_*.sql` or `N_*.go` file in
`-out` and keeps its digit width (5 when there is none). A statement
containing `$$` is wrapped in `-- +goose StatementBegin`/`StatementEnd`. Once
the lock lists migrations, a run with a different `-format` is refused
before anything is written.

The migrations create these tables: `auth_schema`, `auth_credentials`,
`auth_sessions`, `auth_tokens`, `auth_events`, `auth_throttle`,
`auth_passkeys`, `auth_passkey_ceremonies`, `auth_second_factors`,
`auth_recovery_codes`, `auth_second_step_challenges`, `auth_email_codes`,
`auth_ceremonies`, `auth_identities`, `auth_registrations`, `auth_mail_counts`.

Your app must:

- Apply the migrations with its own migration tool, before deploying code
  that needs them.
- Call `authkit.CheckSchema(ctx, q)` once at startup. It returns
  `authkit.ErrSchemaBehind` when `auth_schema.version` is older than the
  library's migrations.
- Write its own RLS policies if it uses RLS. The migrations contain none.
  `authkittest/policies.sql` shows the policies authkit's own tests use; for
  example, `auth_passkeys` and `auth_passkey_ceremonies` get the same policies
  as `auth_credentials`, and so do the four tables v0.6.0 adds.

### Run two installs in one database

`Config.Schema` puts an install's tables in their own PostgreSQL schema, so one
database can hold two installs, for example staff on `administrators` and
shoppers on `customers`. Each install is its own `authkit.New` with its own
`Schema` and its own modules; they share no rows. An empty `Schema` (the
default) uses the unqualified `auth_*` names. A `Schema` must match
`^[a-z_][a-z0-9_]{0,62}$` and must not be `public`, `information_schema` or
start with `pg_`; `New` refuses any other.

Generate the install's migrations with the same name:

```sh
go run github.com/sylly-mika/authkit/cmd/authkit-gen -principals customers -schema customer_auth -out migrations
```

With `-schema`, files are named `NNNNN_authkit_<schema>_<name>`, the first one
creates the schema (`CREATE SCHEMA IF NOT EXISTS`; no down migration drops it),
every `auth_*` table is created in it, and the lock defaults to
`authkit.<schema>.lock`. A lock written with one `-schema` refuses another.

Grant your app's role the schema and its tables, as authkit's tests do:

```sql
GRANT USAGE ON SCHEMA customer_auth TO app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA customer_auth TO app;
```

Write your RLS policies on `customer_auth.auth_*` as you would on `auth_*`.
At startup, call `kit.CheckSchema(ctx, q)` on each install; it reads that
install's `<schema>.auth_schema` (the package func `authkit.CheckSchema`
reads only the search path). `kit.OneTime()` keeps its links in the
install's schema; a store you build yourself takes the schema through
`onetime.NewIn(schema, now, rand)`. In tests,
`authkittest.NewDB(t, authkittest.Schema("customer_auth"))` builds a database
whose tables live in that schema.

### Pass a transaction

Every `Service` and module method takes a `db.Querier` as its second argument. Methods
that write or lock refuse to run outside a transaction with
`db.ErrTxRequired`. Wrap your transaction:

- pgx: `pgxdb.Tx(tx)` over a `pgx.Tx`, `pgxdb.Conn(conn)` over a pinned
  `*pgxpool.Conn`. `pgxdb.Unwrap(q)` returns `(pgx.Tx, bool)`, so your own pgx
  code (in `Principals`, in `OnEvent`) can run on the same transaction.
- `database/sql`: `sqldb.Tx(tx)` over a `*sql.Tx`, `sqldb.Conn(conn)` over a
  `*sql.Conn`, and `sqldb.Unwrap(q)`.

Set any RLS settings your policies need on the transaction before you pass it
in; authkit never sets them.

### Implement `Principals`

`authkit.New(cfg, principals)` refuses a nil `Principals`. The interface has
three methods:

| Method | Must return |
|---|---|
| `Lookup(ctx, q, login string, aud Audience) (Principal, error)` | the principal for a normalised login, or `authkit.ErrUnknownLogin` |
| `ByID(ctx, q, id uuid.UUID, aud Audience) (Principal, error)` | the principal for an id, or `authkit.ErrUnknownLogin` |
| `Admit(ctx, q, p Proposal) (Admission, error)` | whether this principal may hold this session now |

`Admit` is called when a session is created, refreshed or used.
`Proposal` carries the `Principal`, the `Audience`, a `ScopeID` (nil when the
session is being created) and `SecondFactor` (how the session was signed in:
`""`, `totp`, `email`, `recovery`, `passkey` or `oidc`). To allow, return an
`Admission` (optional `ScopeID`, extra token `Claims`, and a `Context` value
for your handlers). To refuse, return `authkit.Refuse(result, err)`: `result`
is the sign-in event to log and `err` is what the caller gets in
`Result.Refusal`. `err` must not be nil.

An `Audience` is a sign-in surface you name, such as `"web"` or `"admin"`.

### Read a `Result`

Every method returns `(Result, error)`. `error` is only for infrastructure
failures: roll back and answer 500. A refusal (wrong password, locked login,
expired link) is `Result.Refusal`, with a nil `error`. Commit the transaction
on a refusal: authkit has recorded the attempt and the throttle count in it.

`Result.Claims()` returns the session as the account methods take it
(`Logout`, `ListSessions`, `RevokeSession`, `ChangePassword`, and the passkey
and second-factor methods). It is nil when the `Result` has no session.

### Choose a transport

`Config.Transport` sets how sessions travel.

**Session mode** (`authkit.TransportSession`): one opaque token in an
`HttpOnly` cookie, checked against the database on every request by
`AuthenticateSession`. A token older than `Session.RotateEvery` is swapped for
a new one, and reuse of a swapped-out token is detected. The minimal example
uses this mode. `Login`, `OpenSession`, `CompleteReset` and `ChangePassword`
(under `RevokeAll`) return the token in `Result.SessionToken`; set it with
`opts.Set(w, res.SessionToken, res.Session.AbsoluteExpiresAt)`.

`cookie.Options{Name: "session"}` sets `__Host-session` with `Secure`,
`HttpOnly`, `Path=/`, no `Domain`, `SameSite=Strict` (set `SameSite` to
change it) and `Max-Age` running to the absolute expiry. `Insecure: true`
drops the `__Host-` prefix and `Secure`; use it only for plain-HTTP
development.

If a rotated cookie never reaches the browser, the old token counts as reuse
after `ReuseGrace` and the session ends.

**Bearer mode** (`authkit.TransportBearer`, the default): a short-lived HS256
access JWT plus a rotating refresh token. Set `Issuer` and a `Secret` of at
least 32 bytes. `Login` returns `Result.Tokens` (`AccessToken`,
`RefreshToken`, `ExpiresAt` of the access token). `Refresh(ctx, q, aud, raw,
m)` rotates a refresh token; a refusal leaves the token valid.
`Authenticate(ctx, q, claims)` checks one request. `Refresh` and
`Authenticate` work in Bearer mode only.

With echo, mount `echov5.ParseBearer(kit, aud)` (checks the token, reads no
database) before your connection middleware and `echov5.Guard(kit, querier)`
after it, where `querier` returns the request's `db.Querier`. `Guard` refuses
with `authkit.ErrSessionEnded` or `authkit.ErrStale` (the session's access
changed; the client should refresh). Read the claims with `echov5.Claims(c)`
and the `Admission` with `echov5.Admission(c)`.

### Handle sign-in

`kit.Password.Login(ctx, q, aud, login, pw, m)` counts the attempt on the login's throttle
row, then verifies the password. After `Throttle.Failures` failures within
`Throttle.Window`, the next attempt is refused with `authkit.ErrLocked`
without a password check until `Throttle.Lockout` passes. A success clears the
counter. A wrong password and an unknown login both give
`authkit.ErrInvalidCredentials`.

argon2id runs on at most `HashConcurrency` slots. When no slot frees up
within `HashWait`, the method refuses with `authkit.ErrBusy` and counts
nothing. To hold a slot before opening the transaction (what
`echov5.HashSlot` does):

```go
ctx2, release, res, err := kit.Password.AcquireHashSlot(ctx)
defer release() // never nil
if err != nil { return err }               // only ctx's error
if res.Refusal != nil { /* ErrBusy: answer 503 */ }
// Open the transaction, then pass ctx2 to Login, VerifyPassword,
// ChangePassword, CompleteReset or SetPassword: it carries the slot.
res, err = kit.Password.Login(ctx2, q, aud, login, password, m)
```

When the principal has a confirmed second factor, `Login` opens no session
and returns `Result.SecondStep` instead (see "Add second factors").

`OpenSession(ctx, q, p, aud, m)` signs in a principal your app has
authenticated itself, such as an accepted invitation.
`OpenSessionFrom(ctx, q, from, p, aud, m)` opens a session that keeps the
sign-in time of session `from` (same principal and audience, which may be
revoked or expired), for a workspace switch.

### Add password reset

1. `kit.Password.RequestReset(ctx, q, aud, login)` creates a reset link and returns its id
   in `Result.TokenID`. Enqueue the email with that id in the same
   transaction. An unknown login, or one without a password (unless
   `Reset.MayCreateCredential`), writes nothing and has no `TokenID`. Answer
   the same way in both cases, and after the transaction commits call
   `authkit.PadSince(start, kit.Password.ResetFloor())` so both take the same time.
2. Your mail worker, in its own transaction, calls
   `kit.OneTime().Mint(ctx, q, id)`. The returned `Minted.Raw` goes into the
   email and nowhere else.
3. The link handler calls `kit.Password.CompleteReset(ctx, q, aud, raw, newPassword, m)`.
   It checks the password policy, spends the link, sets the password and
   revokes every session of the principal. It also deletes the principal's
   passkeys (`Result.PasskeysRemoved`). With a second factor on, it returns
   `Result.SecondStep` instead of a session.

`kit.OneTime()` is also available for your own one-time links (invitations).

### Change or set a password

- `kit.Password.ChangePassword(ctx, q, claims, current, next, m)` replaces the caller's
  password. `RevokeOnPasswordChange` decides the caller's own session:
  `RevokeOthers` (default) keeps it, `RevokeAll` replaces it with a new one in
  `Result.Tokens` or `Result.SessionToken`. Passkeys are kept.
- `kit.Password.SetPassword(ctx, q, p, aud, pw, m)` gives a principal without a password
  its first one. It revokes nothing.
- `kit.Password.VerifyPassword(ctx, q, p, aud, pw, m)` checks a password inside your own
  flow. A mismatch is `ErrInvalidCredentials`; it does not touch the throttle.
- `kit.Password.HasCredential(ctx, q, principal)` reports whether a principal has a
  password. `kit.Password.CheckPassword(pw)` applies the policy alone.

### Manage sessions

- `Logout(ctx, q, claims, m)` ends the session. Repeating it succeeds. In
  Session mode, also clear the cookie with `opts.Clear(w)`.
- `ListSessions(ctx, q, claims, limit, offset)` returns the caller's open
  sessions, newest first, the current one marked `Current`, and their count.
- `RevokeSession(ctx, q, claims, id, m)` revokes one of the caller's sessions.
- `RevokeAllSessions(ctx, q, principal, reason, m)` revokes every session of
  a principal; `reason` is one of the `authkit.Reason*` constants, such as
  `authkit.ReasonAdmin`.

### Use the sign-in log

Every sign-in attempt and account change writes an `auth_events` row.
`ListEvents(ctx, q, principal, exclude, limit, offset)` returns them newest
first, without the results in `exclude`, and their count. `Event.Source`
names the method that wrote the row (`authkit.SourceLogin`,
`authkit.SourceChangePassword`, and so on); rows written before v0.3.0 have
`""`.

`Config.OnEvent(ctx, q, e)` runs right after each event is written, on the
same querier and so in the same transaction. If it returns an error, the
method fails.

### Clean up old rows

Call `kit.Prune(ctx, q)` on a schedule. It deletes throttle counters whose
window has passed and that are not locked, sessions and one-time links dead
for 30 days, passkey ceremonies and second-step challenges an hour past
expiry, OIDC ceremonies and sign-up tickets an hour after they expire or are
used, registrations past their expiry, mail counts 48 hours after their window
began, invites 30 days after they expired, were accepted or were revoked,
email changes past their expiry, and events older than `EventRetention`
(none when it is negative).

### Add passkeys

Passkeys are off until `passkey.Rules.RPID` is set; until then every
passkey method refuses with `authkit.ErrPasskeysOff`. `RPID` is your domain
with no scheme, port or path. `Rules.Origins` lists the allowed origins
per audience: `https`, or `http` only when `RPID` is `localhost`, each host
equal to `RPID` or ending in `.` + `RPID`. A ceremony begun on one audience
cannot be finished on another.

```go
kit.Passkeys, err = passkey.New(kit.Service, passkey.Rules{
	RPID:    "example.com",
	Origins: map[authkit.Audience][]string{"web": {"https://app.example.com"}},
})
```

Sign-in:

1. `kit.Passkeys.BeginPasskeyLogin(ctx, q, aud, m)` stores a ceremony and returns it in
   `Result.Ceremony` (`ID`, `Options` for the browser, `ExpiresAt`). It takes
   no login.
2. `kit.Passkeys.FinishPasskeyLogin(ctx, q, aud, ceremonyID, response, m)` takes the
   browser's JSON response, calls `Admit` and opens a session as `Login`
   does. Every refusal is `authkit.ErrPasskeyRejected`, except a refusal from
   your `Admit`. The password throttle is not used.

Registration needs a principal with a password (`ErrNoPassword`), a sign-in
within `Rules.Reauth` (`ErrReauthRequired`) and fewer than `Rules.Max`
passkeys (`ErrPasskeyLimit`): `kit.Passkeys.BeginPasskeyRegistration(ctx, q, claims, m)`,
then `kit.Passkeys.FinishPasskeyRegistration(ctx, q, claims, ceremonyID, response, label,
m)`.

Management: `kit.Passkeys.ListPasskeys(ctx, q, principal)`; `kit.Passkeys.RenamePasskey(ctx, q, claims,
id, label)` (label 1 to 64 characters, `ErrPasskeyLabel`; no recent sign-in
needed); `kit.Passkeys.DeletePasskey(ctx, q, claims, id, m)` (needs a sign-in within
`Reauth`, revokes the principal's other sessions). Another principal's
passkey is `ErrPasskeyNotFound`, like an unknown one.

### Add second factors

Second factors are off until `secondfactor.New` runs with a 32-byte `Rules.Key`.
The key seals the TOTP secrets. Until it is set, every second-factor method
refuses with `authkit.ErrSecondFactorsOff`, and so does `kit.Password.Login` for a
principal that has a confirmed factor.

Setting a factor up needs a sign-in within `Rules.Reauth`
(`ErrReauthRequired`):

- TOTP: `kit.Factors.BeginTOTPSetup(ctx, q, claims, m)` returns `Result.TOTPSetup` (`URI`,
  `Secret`, `QRPNG` a 256x256 PNG, `ExpiresAt`); `kit.Factors.ConfirmTOTP(ctx, q, claims,
  code, m)` turns it on.
- Email: `kit.Factors.BeginEmailCodeSetup(ctx, q, claims, m)` returns `Result.EmailCode`
  for your mail worker; `kit.Factors.ConfirmEmailCode(ctx, q, claims, code, m)` turns it
  on.
- The first confirmed factor returns 10 recovery codes in
  `Result.RecoveryCodes`. Show them once.
- `kit.Factors.SecondFactorStatus(ctx, q, claims)` returns a `FactorStatus` (`TOTP`,
  `Email`, `RecoveryCodesLeft`). `kit.Factors.RegenerateRecoveryCodes(ctx, q, claims, m)`
  replaces the codes. `kit.Factors.DisableSecondFactor(ctx, q, claims, kind, proof, m)`
  turns one factor off, with a `FactorProof{Method, Code}` from any factor or
  a recovery code; `kit.Factors.RequestEmailProof(ctx, q, claims, m)` mails a code to use
  as that proof. Turning off the last factor deletes the recovery codes. No
  session ends.

Sign-in with a second factor:

1. `Login` (or `CompleteReset`) returns `Result.SecondStep` (`Token`,
   `ExpiresAt`, `Methods`) and no session.
2. For the email method, `SendSecondStepEmail(ctx, q, aud, token, m)` returns
   `Result.EmailCode`.
3. `VerifySecondStep(ctx, q, aud, token, method, code, m)` with method
   `authkit.FactorTOTP`, `FactorEmail` or `FactorRecovery` opens the session.
   A wrong code counts on the challenge and on the login's throttle; a locked
   login is refused with `ErrLocked` before any code is checked.

Emailed codes: enqueue `Result.EmailCode.ID` in the same transaction. The
mail worker calls `kit.Factors.MintEmailCode(ctx, q, id)` and mails the 6-digit
`EmailCodeMail.Code`. `ErrCodeEnded` means the code was replaced, expired or
used up.

### Add Google and Apple sign-in

`oidc.New(core, oidc.Rules{Providers: …})` signs principals in through
OpenID Connect providers. Endpoints are fixed in the code: nothing is
discovered at startup, and the providers' signing keys are fetched on first
use.

```go
google := oidc.Google(googleID, googleSecret, "https://api.example.com/auth/oidc/google/callback")
apple, err := oidc.Apple(teamID, keyID, servicesID, applePEM, "https://api.example.com/auth/oidc/apple/callback")
if err != nil {
	return nil, err
}
k.OIDC, err = oidc.New(core, oidc.Rules{Providers: []oidc.Provider{google, apple}})
```

- Google: a web OAuth client in Google Cloud, with the callback URL as an
  authorized redirect URI.
- Apple: a Services ID (the client id) with the callback URL as its return
  URL, your Team ID, and a Sign in with Apple key: `applePEM` is the `.p8`
  file and `keyID` its Key ID. `Apple` refuses anything but a P-256 PKCS #8
  key. It signs a new ES256 client secret, valid 5 minutes, for each token
  request.
- `Google` and `Apple` set `SkipSecondFactor`: their sign-in opens a session
  without the second step, as a passkey does. A `Provider` you build with
  `SkipSecondFactor` false goes through the second-factor gate.

Each provider needs two routes:

1. Start: `r, err := kit.OIDC.Begin(ctx, q, provider, aud, m)`
   (`oidc.ErrUnknownProvider` for a name not configured; answer 404).
   Commit, set the binding cookie to `r.Binding`, and answer 303 to `r.URL`.
2. Callback, `GET` for Google, `POST` for Apple (Apple answers with
   `response_mode=form_post`): call `cb, err := oidc.ParseCallback(req)`
   before anything else reads the body (`oidc.ErrBadCallback`), then
   `res, signUp, err := kit.OIDC.Finish(ctx, q, cb, binding, m)` with the
   binding cookie's value. Clear the cookie on every outcome. A non-nil `err`
   means roll back. Commit on anything else, a refusal included: the ceremony
   is spent and cannot be replayed.

The binding cookie ties the callback to the browser that started it. Make it
`HttpOnly` and `Secure`, with `Path` the callback path (so its name takes the
`__Secure-` prefix: `__Host-` needs `Path=/`), `Max-Age` the
`Rules.CeremonyTTL` (10 minutes by default) and `SameSite` from
`r.SameSite`: `Lax` for Google, `None` for Apple, whose callback is a
cross-site POST. Keep the Apple callback out of `echov5.RequireOrigin` and any
CSRF middleware; the state, the binding cookie and the ID token's nonce
protect it.

| `Finish` gives | What to do |
|---|---|
| a session (or `SecondStep`, for a provider without `SkipSecondFactor`) | as after `Login` |
| `Result.Principal` with no session and no refusal | a `Link` finished; back to the account page |
| `Refusal: oidc.ErrIdentityUnknown` and a non-nil `signUp` | redirect to your sign-up page with `signUp.Ticket` in the URL fragment |
| `Refusal: oidc.ErrSignInToLink` | a principal holds this verified email: ask the user to sign in (or reset the password), then link. authkit never links by email |
| `Refusal: oidc.ErrCancelled`, `oidc.ErrEmailUnverified` | cancelled at the provider; the provider sent no verified email |
| `Refusal: oidc.ErrIdentityTaken` | a link whose identity another principal holds |
| `Refusal: authkit.ErrInvalidCredentials` | any failed check of the callback or ID token, logged as `bad_identity` |
| your `Admit` refusal | as after `Login` |

Sign-up: the sign-up page calls `kit.OIDC.Ticket(ctx, q, ticket)` to prefill
the email and names; it does not spend the ticket, which lives
`CeremonyTTL`. The submit handler, in one transaction, creates your principal
from the form and calls `kit.OIDC.SignUp(ctx, q, ticket, principalID, aud, m)`.
That spends the ticket, stores the identity and signs the principal in. Any
error from it, `oidc.ErrTicketUnknown` and `oidc.ErrIdentityTaken` included,
means roll back, so no principal is left with no way to sign in. On an
`Admit` refusal, roll back the principal too. Apple sends the user's name only
on the first authorization; `SignUp.GivenName` and `FamilyName` carry it, and
the email always comes from the signed ID token. `SignUp.PrivateEmail` is
true for an Apple relay address ("Hide My Email"); say so on the form. A
relay sign-up is a new principal: a user with a password account signs in
first and links.

Linked accounts:

- `kit.OIDC.Link(ctx, q, claims, provider, m)` needs a sign-in within
  `Rules.Reauth` (`authkit.ErrReauthRequired`). It returns a `Redirect`
  handled as `Begin`'s; the provider's callback route finishes it.
- `kit.OIDC.Unlink(ctx, q, claims, provider, m)` removes the identity and
  ends the caller's other sessions. It returns `authkit.ErrReauthRequired`,
  `oidc.ErrNotLinked`, or `oidc.ErrLastCredential` when no password, passkey
  or other identity would be left.
- `kit.OIDC.Identities(ctx, q, principal)` lists `Identity{Provider, Email,
  CreatedAt, LastUsedAt}`, oldest first; `kit.OIDC.Providers()` lists the
  configured names.
- `CompleteReset` removes every identity of the principal, as it removes
  passkeys.

### Add registration

`register.New(core, k.Password, register.Rules{Create: createPrincipal})`
adds sign-up with an emailed link. A pending registration is an authkit row,
not a principal. It holds the address (`authkit.Normalize`d), your form's
fields as an opaque JSON `payload`, and no password: the password is typed on
the activation page, so whoever reads the mail chooses it.

1. Register handler, one transaction: validate the form (address, names,
   consent), then `st, err := kit.Register.Start(ctx, q, aud, email, payload)`.
   Exactly one field of `Started` is set:
   - `TokenID`: enqueue the activation mail with it. A second `Start` for a
     pending address is the resend: a new link replaces the old one, and the
     latest payload is kept.
   - `Holder`: a principal holds the address; enqueue your "you already have
     an account" mail, if you send one.
   - `RetryAfter`: the address had `MailCap` mails within `MailWindow`; send
     nothing.

   Commit in every case (the mail count must stay counted) and answer the
   same way, then call `authkit.PadSince(start, kit.Register.Floor())`.
2. Mail worker, own transaction: `mail, err := kit.Register.Mint(ctx, q, id)`.
   `register.ErrNothingToSend` means the registration or link is gone: drop
   the job. `mail.Raw` goes into the link and nowhere else; `To`, `Payload`
   and `ExpiresAt` fill the email. `kit.Register.CountMail(ctx, q, aud, email)`
   counts your other mails to the address (the account-exists notice) against
   the same cap, and returns the wait when over it.
3. Activation page, one transaction:
   `res, err := kit.Register.Activate(ctx, q, raw, password, m)`. It checks the
   password against `password.Config.Password`, spends the link, calls
   `Rules.Create` with the `Pending` (`ID`, `Audience`, `Email`, `Payload`,
   `CreatedAt`) so you insert your principal, stores the password and signs the
   principal in. Refusals come with a nil `err`; commit them: `PolicyError`
   and `ErrBusy` leave the link unspent, `authkit.ErrTokenUnknown` is an
   unknown, used, replaced or expired link, `register.ErrAddressHeld` means a
   principal took the address meanwhile (the registration is deleted), or your
   `Admit` refusal. When `Create` hits your unique index, return an error
   wrapping `register.ErrAddressHeld`: `Activate` returns it as `err`, and you
   roll back and answer as for the refusal.

An OIDC sign-up for a pending address creates the principal; the pending
registration then ends with `register.ErrAddressHeld`.

### Invite people

`invite.New(core, k.Password, invite.Rules{Create: createPrincipal, Join: joinPrincipal})`
adds invitations by an admin. Your app checks that the caller may invite
before it calls `Invite`, `Resend`, `Revoke` or `List`; authkit stores
`InvitedBy` as data and never decides who may invite. Write your audit row in
the same transaction.

1. Invite handler, one transaction: `inv, err := kit.Invite.Invite(ctx, q,
   invite.Request{Audience: aud, Email: email, ScopeID: scope, InvitedBy:
   &admin.ID, Payload: payload})`. Enqueue the mail with `inv.TokenID`.
   `inv.Holder` is set when a principal already holds the address; without
   `Rules.Join` that is `invite.ErrAddressHeld` instead.
   `invite.ErrInvitePending` means an open invite to the address exists.
   `Resend(ctx, q, id)` replaces the link and restarts the expiry,
   `Revoke(ctx, q, id)` closes the invite, and both return
   `invite.ErrInviteClosed` for an accepted or revoked one.
   `List(ctx, q, aud, scope, limit, offset)` pages the invites with their
   `State` (`pending`, `expired`, `accepted`, `revoked`) and the total.
2. Mail worker, own transaction: `mail, err := kit.Invite.Mint(ctx, q,
   tokenID)`. `invite.ErrNothingToSend` means the invite or link is gone, or
   `Rules.Check` voided it: drop the job. `mail.Held` says the address has an
   account: word the mail "sign in to accept".
3. Invite page: `op, err := kit.Invite.Open(ctx, q, raw)` shows the invite and
   spends nothing; it returns `authkit.ErrTokenUnknown` or
   `authkit.ErrTokenGone`. Send `Referrer-Policy: no-referrer` on this page,
   because its URL carries the token.
4. Accept, one transaction, in one of three ways. Refusals come in
   `Result.Refusal` with a nil `err`; commit them.
   - `kit.Invite.Accept(ctx, q, raw, password, input, m)` creates the
     principal with `Rules.Create`, stores the password and signs it in.
     `invite.ErrSignInToAccept` means the address has an account: the link
     stays live, and the person signs in and accepts as below. When `Create`
     hits your unique index, return the error and roll back; a retry gets
     `invite.ErrSignInToAccept`.
   - `kit.Invite.AcceptSignedIn(ctx, q, claims, raw, m)` lets the signed-in
     principal whose login is the invited address join through `Rules.Join`
     (`ResultInviteAccepted`, no new session, no recent sign-in needed).
     Another principal gets `invite.ErrOtherAccount` and the link stays live.
   - `kit.Invite.AcceptOIDC(ctx, q, raw, ticket, input, m)`, with
     `Rules.OIDC: k.OIDC`. The page's "Continue with Google" or "Continue with
     Apple" POST carries the raw invite token in its body. Call `Open`, then
     `kit.OIDC.Begin`, and set two cookies: the binding and the raw invite
     token, both `HttpOnly` and `Secure`, with `Redirect.SameSite` and
     `Max-Age` equal to `CeremonyTTL` (10 minutes). The token goes into no URL
     the provider sees. Your callback calls `Finish` as for any sign-in. A
     sign-up ticket (`oidc.ErrIdentityUnknown`) goes back to the invite page
     in the URL fragment; the page POSTs `{ticket, input}`, and the server
     reads the invite token from the cookie, calls `AcceptOIDC` and clears
     the cookie. A sign-in of an already linked subject may go on to
     `AcceptSignedIn`. Refusals: `invite.ErrEmailMismatch`,
     `invite.ErrPrivateEmail` (an Apple private relay address, even one equal
     to the invite) and `invite.ErrSignInToAccept`; the link stays live.
     Errors, roll back: `invite.ErrNoOIDC`, `oidc.ErrTicketUnknown`,
     `oidc.ErrIdentityTaken`, an error from `Create`, and your `Admit`
     refusal.

### Erase a person

`f, err := kit.Forget(ctx, q, p)` deletes every authkit row of `p` in every
audience: sessions, password, passkeys, second factors, OIDC identities, reset
links, invites to its address, its pending registration and email change, and
its throttle counters. Run it in one transaction:

1. Lock your principal row `FOR UPDATE`.
2. Call `kit.Forget`.
3. Delete or anonymise your row.
4. Commit.

If you keep the row as a tombstone, your `Admit` must refuse it: a sign-in
that raced step 2 is then refused on its first use. `Forgotten` counts
`Sessions`, `Passkeys` and `Identities` and names the `Providers` for your
receipt; authkit stores no provider token, so revoking the app at Google or
Apple is up to you. The sign-in log keeps the person's rows, unlinked from
the principal and session, until `Prune` removes them at `EventRetention`
(90 days by default), to investigate account takeover and abuse. With a
negative `EventRetention`, `Forget` deletes them. Gate the route with
`RequireRecent`.

### Require a recent sign-in

`res, err := kit.RequireRecent(ctx, q, claims, 0)` refuses with
`authkit.ErrReauthRequired` unless the session signed in or re-verified within
`Config.Recent` (5 minutes, at most 10), and with `authkit.ErrSessionEnded`
when it is not open. A zero window means `Config.Recent`, and so does a
module's zero `Reauth`. Use it before account deletion, role changes or API
keys. On `ErrReauthRequired`, ask for one factor of the account:

- `kit.Password.Reverify(ctx, q, claims, password, m)`; it counts on the login
  throttle (`ErrLocked`).
- `kit.Factors.Reverify(ctx, q, claims, code, m)`: TOTP only; an emailed or
  recovery code is not accepted.
- `kit.Passkeys.BeginReverify(ctx, q, claims)`, then
  `FinishReverify(ctx, q, claims, ceremonyID, response, m)`.
- `kit.OIDC.BeginReverify(ctx, q, claims, provider)` sends `prompt=login`
  and `max_age=0`; `FinishReverify(ctx, q, claims, cb, binding, m)` needs a
  subject linked to the caller.

Each records `reverified` and marks the session as just authenticated in
place. The session token is not rotated, so your cookie stays. ASVS 7.2.4 asks
for a new token on re-authentication; authkit deviates because a rotation
would make the app swap its cookie in the middle of a flow, while the refresh
token already rotates on every refresh. ASVS 7.1.1 asks for such a deviation
to be documented; the package doc records it. `ChangePassword` needs no recent
sign-in: the current password is the proof.

### Change a sign-in email

`emailchange.New(core, emailchange.Rules{Change: setLogin})` changes a login
only after the new mailbox confirms a link.

1. Settings handler, one transaction: `st, err :=
   kit.EmailChange.Start(ctx, q, claims, newEmail)`. `st.Refusal` is
   `authkit.ErrReauthRequired` (re-verify first) or
   `emailchange.ErrSameAddress`. `st.RetryAfter` set means 3 starts this hour:
   send nothing. `st.AddressHeld` means another principal holds the address
   and nothing was written: answer exactly as on success (you may mail that
   address a notice). Otherwise enqueue the confirmation mail with
   `st.TokenID` and a notice to `st.Old`. A new `Start` replaces the pending
   change. `StartFor(ctx, q, p, aud, newEmail)` is the admin path, with no
   recent check: your app authorises.
2. Mail worker: `mail, err := kit.EmailChange.Mint(ctx, q, tokenID)` gives
   `To`, `Raw`, `Old` and `ExpiresAt`; `emailchange.ErrNothingToSend`: drop
   the job.
3. Confirm page, one transaction: `ch, err := kit.EmailChange.Confirm(ctx, q,
   raw, m)`. It spends the link, calls `Rules.Change`, moves the login
   throttle to the new address and ends the principal's other sessions (all
   of them with `Rules.RevokeAll` or after `StartFor`). Refusals in
   `ch.Refusal`, commit them: `authkit.ErrTokenUnknown`,
   `authkit.ErrTokenGone`, `emailchange.ErrStale` (the login changed since
   `Start`) and `emailchange.ErrAddressHeld`. An error from `Change` is
   returned: roll back. Mail `ch.Old` that the address changed. The link alone
   confirms, since the new mailbox may be on another device.

`Pending(ctx, q, p)` reads the pending change (nil when none) and
`Cancel(ctx, q, p)` drops it. OIDC identities stay linked by subject; passkey
and TOTP labels keep the old login.

### Write a module

A module is a package whose `New(core *authkit.Service, rules)` checks its
rules, calls `core.Attach("<name>")` once and keeps the returned
`*authkit.Core`. The `Core` is the module's only way to the core's rules:

- `Begin` (or `BeginVerified`, for a sign-in with no login) starts an
  `Attempt`: it normalises the login and checks the throttle.
  `Attempt.Refuse` records a refusal and counts it once; `SignIn` runs
  `Admit` and the second-factor gate, then opens the session.
  `Attempt.SkipSecondFactor` lets a `FactorOIDC` sign-in skip the second step,
  as a passkey sign-in does.
- `Fresh`, `LockSession`, `RevokeAll`, `RevokeOthers` and `Reopen` act on
  sessions; `Record` writes to the sign-in log in your transaction.
- Run every statement on `core.Q(q)`, so the module's SQL reaches the
  install's schema.

The `Core` API is unstable until 1.0: any minor version may change it.

### Test your integration

`authkittest` is a Postgres test harness: `NewDB(t)`, `(*DB).InAuthTx(ctx,
fn)`, `(*DB).NewPrincipal(t, login)`, `NewPrincipals()` (a `Principals` you
can set to refuse or allow), `NewClock()` (starts 2040-01-01 12:00 UTC),
`Rand(seed)`, and `NewAuthenticator(rpID, origin)`, a software passkey
authenticator whose `Create` and `Get` answer the options JSON.
`authkittest/oidcfake.New(t, oidcfake.Google)` (or `oidcfake.Apple`) is a local
provider over `httptest` TLS: put `Server.Provider(redirectURL)` in
`oidc.Rules.Providers` and `Server.Client` in `oidc.Rules.HTTPClient`, and
`Server.Authorize(t, redirect, oidcfake.User{…})` plays the browser and returns
the callback.
`Config.Clock` and `Config.Rand` take the clock and random source.

## Configuration reference

`authkit.New(cfg, principals)` takes a `Config`; each module's `New` takes its
own rules. A zero field takes its default. A negative `Session.AbsoluteTTL`,
`Session.RotateEvery` or `EventRetention` turns that limit off.

`authkit.Config`:

| Field | Default | Meaning |
|---|---|---|
| `Transport` | `TransportBearer` | `TransportBearer` or `TransportSession` |
| `Issuer`, `Secret` | none | Bearer mode: required; `Secret` at least 32 bytes. Ignored in Session mode |
| `AccessTTL` | 15 min | Bearer mode: access token lifetime. Ignored in Session mode |
| `Session.IdleTTL` | 30 min | sign-in ends after this long without activity |
| `Session.AbsoluteTTL` | 12 h | cap from sign-in; negative: no cap |
| `Session.RotateEvery` | 15 min | Session mode: token age that triggers a swap; negative: never rotate |
| `RefreshTTLFor` | none | `map[Audience]time.Duration`: `IdleTTL` per audience |
| `RefreshTTL` | unset | deprecated name of `Session.IdleTTL`; wins when set |
| `ReuseGrace` | 30 s | how long a swapped-out token is accepted before it counts as reuse |
| `Throttle.Failures` | 5 | failures within `Window` before a lockout |
| `Throttle.Window` | 15 min | counting window |
| `Throttle.Lockout` | 15 min | lockout length |
| `Throttle.CountAfterVerify` | false | false: count before verifying; true: v0.1's order |
| `Throttle.PlainLoginKey` | false | false: key `auth_throttle` on hex(sha256(normalised login)); true: the plain login |
| `Events.ChangeLogsReset` | false | true: `ChangePassword` logs `password_reset` instead of `password_changed` |
| `EventRetention` | 90 days | `Prune` deletes older events; negative: keep forever |
| `Recent` | 5 min | how recent a sign-in or re-verify must be for a sensitive change; at most 10 min |
| `OnEvent` | nil | `func(ctx, q db.Querier, e Event) error`, run after each event |
| `Clock` | system clock | source of every timestamp |
| `Rand` | `crypto/rand.Reader` | random source |
| `Schema` | empty | PostgreSQL schema of the install's tables; empty: the unqualified `auth_*` names |

`password.Config` (`password.New`):

| Field | Default | Meaning |
|---|---|---|
| `Password` | 10 to 256 runes | `password.Policy{MinRunes, MaxRunes}` |
| `Hashing` | argon2id 19 MiB, t=2, p=1 | `password.Params` |
| `HashConcurrency` | 4 | argon2id slots |
| `HashWait` | 2 s | wait for a slot before `ErrBusy` |
| `RevokeOnPasswordChange` | `RevokeOthers` | `RevokeAll` also replaces the caller's session |
| `ResetTTL` | 1 h | reset link lifetime |
| `ResetFloor` | 500 ms | minimum time for a reset request (`PadSince`) |
| `Reset.MayCreateCredential` | false | true: a reset can set a first password for a principal without one |

`passkey.Rules` (`passkey.New`):

| Field | Default | Meaning |
|---|---|---|
| `RPID` | empty (off) | relying party domain; set to turn passkeys on |
| `RPName` | `authkit` | relying party name |
| `Origins` | none | `map[Audience][]string` of allowed origins |
| `CeremonyTTL` | 2 min | ceremony lifetime, at most 10 min |
| `Reauth` | `Config.Recent` | how recent a sign-in must be to add or delete a passkey |
| `Max` | 10 | passkeys per principal |

`secondfactor.Rules` (`secondfactor.New`):

| Field | Default | Meaning |
|---|---|---|
| `Key` | empty (off) | 32 bytes; set to turn second factors on |
| `Issuer` | `authkit` | issuer shown in authenticator apps |
| `ChallengeTTL` | 10 min | second-step challenge lifetime |
| `EmailCodeTTL` | 10 min | emailed code lifetime |
| `SetupTTL` | 15 min | factor setup lifetime |
| `ResendEvery` | 60 s | minimum gap between emailed codes |
| `MaxSends` | 5 | emailed codes per setup or challenge |
| `MaxTries` | 5 | wrong tries per code |
| `Reauth` | `Config.Recent` | how recent a sign-in must be to manage factors |
| `RecoveryCodes` | 10 | recovery codes issued |

`oidc.Rules` (`oidc.New`):

| Field | Default | Meaning |
|---|---|---|
| `Providers` | none (required) | `[]oidc.Provider`, built by `oidc.Google`, `oidc.Apple` or by hand |
| `CeremonyTTL` | 10 min | how long a `Begin` or `Link` can be finished, and a sign-up ticket lives |
| `Skew` | 5 min | how far ahead of the clock an ID token's `iat` may be |
| `Reauth` | `Config.Recent` | how recent a sign-in must be to link or unlink |
| `HTTPClient` | a client with a 10 s timeout | carries token requests and key fetches |

`oidc.Provider` (for a provider other than Google and Apple):

| Field | Meaning |
|---|---|
| `Name` | the provider's name in your routes and stored identities |
| `Issuers` | accepted `iss` values |
| `AuthURL`, `TokenURL`, `JWKSURL` | the provider's endpoints |
| `ClientID`, `ClientSecret` | your client at the provider; `Secret`, when set, makes the secret for each token request instead |
| `RedirectURL` | your callback URL as registered |
| `Scopes` | requested scopes |
| `SkipSecondFactor` | its sign-in skips the second step |
| `AuthStyle` | `oauth2.AuthStyleInParams` or `AuthStyleInHeader` |
| `FormPost` | ask for `response_mode=form_post` (a POST callback) |
| `SameSite` | the binding cookie's `SameSite` |

`register.Rules` (`register.New`):

| Field | Default | Meaning |
|---|---|---|
| `Create` | none (required) | `func(ctx, q, register.Pending) (authkit.Principal, error)`: inserts your principal at activation |
| `TTL` | 48 h | registration and link lifetime |
| `MailCap` | 3 | activation mails per address per `MailWindow` |
| `MailWindow` | 1 h | the window the cap counts over; at most 24 h |
| `Floor` | 500 ms | minimum time of your register handler (`PadSince`) |

`invite.Rules` (`invite.New`):

| Field | Default | Meaning |
|---|---|---|
| `Create` | none (required) | ``func(ctx, q, invite.Pending, input json.RawMessage) (authkit.Principal, error)``: inserts your principal at `Accept` and `AcceptOIDC` |
| `Join` | nil | ``func(ctx, q, invite.Pending, holder authkit.Principal) error``: adds a holder at `AcceptSignedIn`; nil refuses held addresses with `invite.ErrAddressHeld` |
| `Check` | nil | ``func(ctx, q, invite.Pending) error``: an error voids the invite |
| `OIDC` | nil | an `invite.Tickets` (your `*oidc.Module`); nil: `AcceptOIDC` returns `invite.ErrNoOIDC` |
| `TTL` | 72 h | invite and link lifetime |

`emailchange.Rules` (`emailchange.New`):

| Field | Default | Meaning |
|---|---|---|
| `Change` | none (required) | ``func(ctx, q, authkit.Principal, newLogin string) error``: sets your principal's login at `Confirm` |
| `TTL` | 24 h | change and link lifetime |
| `RevokeAll` | false | true: `Confirm` ends every session, the starter's too |

`authkit.New` refuses:

- Bearer mode without `Issuer`, with a `Secret` under 32 bytes, or with a
  negative `AccessTTL`.
- `Session.IdleTTL` (or a `RefreshTTLFor` entry) above `AbsoluteTTL` when
  there is a cap.
- In Session mode, `RotateEvery` at or above `IdleTTL` (or an entry).
- A negative `RefreshTTL`, `Session.IdleTTL` or `ReuseGrace`, a throttle
  that cannot work, and a `Schema` that is not a valid schema name.
- A negative `Recent`, or one over 10 minutes.

`password.New` refuses a policy that cannot work, an unknown
`RevokeOnPasswordChange`, and a negative `ResetTTL`, `ResetFloor`,
`HashWait` or `HashConcurrency`. `passkey.New` refuses invalid `RPID`,
`Origins`, `CeremonyTTL` and `Max`. `secondfactor.New` refuses a `Key` that
is neither empty nor 32 bytes, an `Issuer` with a colon, and limits out of
range. Each module's `New` returns `authkit.ErrAttached` when that module is
already attached to the `Service`.

`oidc.New` refuses no provider, a `Name` not matching
`^[a-z][a-z0-9_-]{0,31}$` or used twice, an empty `ClientID` or `Issuers`, an
`AuthURL`, `TokenURL` or `JWKSURL` that is not `https://`, a `RedirectURL`
that is not `https://` (except on `http://localhost` and
`http://127.0.0.1`), a provider with neither `ClientSecret` nor `Secret`, a
zero `AuthStyle` or `SameSite`, and negative durations. `register.New`
refuses a nil `Create` or password module, negative values and a
`MailWindow` over 24 h.

`invite.New` refuses a nil `Create` or password module and a negative `TTL`;
`emailchange.New` refuses a nil `Change` and a negative `TTL`.

Switching `PlainLoginKey` off on a running app orphans the existing throttle
counters; nothing migrates them.

## Errors and refusals

Refusals arrive in `Result.Refusal` with a nil `error`, except where the
"From" column names middleware, which returns them as the handler error.
Compare with `errors.Is`, or `errors.As` for the struct types. Status codes
are the ones echov5's documentation suggests; elsewhere they are your choice.

| Error | From | Meaning |
|---|---|---|
| `ErrInvalidCredentials` | `Login`, `VerifyPassword`, `oidc` `Finish` | wrong password or unknown login; for `Finish`, any failed check of the callback or ID token |
| `ErrLocked{RetryAfter}` | `Login`, `VerifySecondStep`, `SendSecondStepEmail`, `DisableSecondFactor` | throttle locked; retry after `RetryAfter` |
| `ErrBusy` | hashing methods; `echov5.HashSlot` (503) | no argon2id slot within `HashWait` |
| `ErrSessionEnded` | `Authenticate`, `RevokeSession`; `echov5.RequireSession`, `echov5.Guard` (401) | session missing, revoked or expired |
| `ErrStale` | `Authenticate`, `echov5.Guard` | the session's access changed; refresh |
| `ErrMissingToken`, `ErrInvalidToken`, `ErrWrongAudience` | `echov5.ParseBearer` | bad or absent access token |
| `cookie.ErrForeignOrigin` | `echov5.RequireOrigin` (403) | `Origin` absent or not allowed |
| `ErrCurrentPasswordWrong` | `ChangePassword` | the current password is wrong |
| `PolicyError` | `ChangePassword`, `SetPassword`, `CompleteReset` | the password fails the policy (`MinRunes`, `MaxRunes`) |
| `ErrTokenUnknown`, `ErrTokenGone{State}` | `CompleteReset`; `ErrTokenGone` also from `OneTime()` | link unknown; link exists but can no longer be spent |
| `ErrPasskeysOff` | passkey methods | `passkey.Rules.RPID` not set |
| `ErrPasskeyRejected` | `BeginPasskeyLogin`, `FinishPasskeyLogin` | passkey sign-in failed |
| `ErrNoPassword`, `ErrReauthRequired`, `ErrPasskeyLimit` | passkey registration; `ErrReauthRequired` also from `DeletePasskey` and second-factor methods | no password, sign-in too old, too many passkeys |
| `ErrPasskeyExists`, `ErrPasskeyInvalid` | passkey registration | already registered; no relying party for the audience or the ceremony cannot be spent |
| `ErrPasskeyNotFound` | `RenamePasskey`, `DeletePasskey` | not the caller's passkey |
| `ErrPasskeyLabel` | `RenamePasskey`, `FinishPasskeyRegistration` | bad label |
| `ErrSecondFactorsOff` | second-factor methods, `Login` | no `secondfactor` module, or its `Rules.Key` is empty |
| `ErrBadCode`, `ErrChallengeEnded`, `ErrCodeEnded`, `ErrSetupExpired` | second-factor methods | wrong code; challenge, code or setup no longer valid |
| `ErrFactorExists`, `ErrFactorNotFound` | second-factor methods | factor already on; factor not on |
| `ErrResendTooSoon{RetryAfter}` | emailed-code methods | a new code asked for too soon |
| `oidc.ErrCancelled`, `oidc.ErrEmailUnverified`, `oidc.ErrSignInToLink`, `oidc.ErrIdentityUnknown`, `oidc.ErrIdentityTaken` | `oidc` `Finish` | cancelled at the provider; no verified email; a principal holds the email (sign in, then link); no principal holds the identity (with a `SignUp`); a link to an identity another principal holds |
| `oidc.ErrTicketUnknown`, `oidc.ErrIdentityTaken` (errors) | `oidc` `Ticket`, `SignUp` | the ticket is unknown, spent or expired; the identity was linked meanwhile. Roll back |
| `oidc.ErrUnknownProvider`, `ErrReauthRequired` (errors) | `oidc` `Begin`, `Link`, `Unlink` | no such provider; sign-in too old |
| `oidc.ErrNotLinked`, `oidc.ErrLastCredential` (errors) | `oidc` `Unlink` | not linked; it is the principal's last way to sign in |
| `oidc.ErrBadCallback` (an error) | `oidc.ParseCallback` | the callback cannot be read |
| `PolicyError`, `ErrBusy`, `ErrTokenUnknown`, `register.ErrAddressHeld` | `register` `Activate` | bad password (link unspent); no hashing slot (link unspent); link unknown, used, replaced or expired; a principal holds the address |
| `register.ErrNothingToSend` (an error) | `register` `Mint` | the registration or link is gone: drop the mail job |
| `ErrReauthRequired`, `ErrSessionEnded` | `RequireRecent`, `emailchange` `Start`; `ErrSessionEnded` also from the `Reverify` methods | sign-in too old: re-verify; session not open |
| `invite.ErrSignInToAccept`, `invite.ErrOtherAccount`, `invite.ErrEmailMismatch`, `invite.ErrPrivateEmail`, `ErrTokenUnknown`, `ErrTokenGone` | `invite` accepts | the address has an account: sign in, then `AcceptSignedIn`; the signed-in principal is not the invited address; the provider's address is another; an Apple private relay address; link unknown; link or invite closed |
| `invite.ErrInvitePending`, `invite.ErrInviteClosed`, `invite.ErrAddressHeld` (errors) | `invite` `Invite`, `Resend`, `Revoke` | an open invite exists; the invite is accepted or revoked; a principal holds the address and `Rules.Join` is nil |
| `invite.ErrNothingToSend`, `emailchange.ErrNothingToSend` (errors) | `Mint` | drop the mail job |
| `invite.ErrNoOIDC` (an error) | `invite` `AcceptOIDC` | `Rules.OIDC` is nil |
| `emailchange.ErrSameAddress` | `emailchange` `Start`, `StartFor` | the new address is the current one |
| `emailchange.ErrStale`, `emailchange.ErrAddressHeld`, `ErrTokenUnknown`, `ErrTokenGone` | `emailchange` `Confirm` | the login changed since the start; another principal took the address; link unknown; link spent or expired |
| your `Refuse(result, err)` error | any method that calls `Admit` | your app refused the session |
| `db.ErrTxRequired` (an `error`, not a refusal) | methods that write or lock | called outside a transaction |
| `ErrSchemaBehind` (an `error`) | `CheckSchema` | run the migrations |
| `ErrAttached` (an `error`) | `Attach`, a module's `New` | that module is already attached to this `Service` |

## Upgrading

Each release may add migrations. After every upgrade, rerun `authkit-gen`
with the same flags and lock file, and apply the new migrations before
deploying; otherwise `CheckSchema` refuses to start with `ErrSchemaBehind`.
See `CHANGELOG.md` for the full list of changes.

**v0.7.0.** New modules: `invite` and `emailchange`; new core methods `Forget`
and `RequireRecent`, and re-verify methods on `password`, `secondfactor`,
`passkey` and `oidc`. No existing signature changes; with `Config.Recent` and
every module `Reauth` left at zero the windows stay 5 minutes. Migration 0007
(`auth_invites`, `auth_email_changes`, the `reverify` ceremony kinds, the
`email_changed` revoke reason) is required: `CheckSchema` refuses a database
below version 7, even for an app that uses none of the new parts. Run
`go get github.com/sylly-mika/authkit@v0.7.0` and `go mod tidy`, rerun
`authkit-gen` with the same flags and lock, and apply the migration. If you
use RLS, give the two new tables policies, as `authkittest/policies.sql`
shows.

**v0.6.0.** New modules: `oidc` (Google and Apple sign-in) and `register`.
No existing signature changes. Migrations 0005 (`auth_ceremonies`,
`auth_identities`, the `oidc` second factor, the `identity_removed` revoke
reason) and 0006 (`auth_registrations`, `auth_mail_counts`) are required:
`CheckSchema` refuses a database below version 6, even for an app that uses
neither module. Run `go get github.com/sylly-mika/authkit@v0.6.0` and
`go mod tidy`, rerun `authkit-gen` with the same flags and lock, and apply
the migrations. If you use RLS, give the four new tables policies, as
`authkittest/policies.sql` does. `Proposal.SecondFactor` and the sign-in log
can now say `oidc`, and `CompleteReset` also removes the principal's OIDC
identities.

**v0.5.0.** authkit is now a core plus modules. There is no new migration,
and behaviour is unchanged except that `Proposal.Source` names the path that
asks `Admit`. Signatures are unchanged; the names moved:

| v0.4 | v0.5 |
|---|---|
| `kit.Login`, `ChangePassword`, `SetPassword`, `VerifyPassword`, `CheckPassword`, `HasCredential`, `AcquireHashSlot`, `RequestReset`, `CompleteReset`, `ResetFloor` | `kit.Password.<same>` (`*password.Module`) |
| `kit.BeginPasskeyLogin`, `FinishPasskeyLogin`, `ListPasskeys`, `RenamePasskey`, `DeletePasskey`, `BeginPasskeyRegistration`, `FinishPasskeyRegistration` | `kit.Passkeys.<same>` (`*passkey.Module`) |
| `kit.BeginTOTPSetup`, `ConfirmTOTP`, `BeginEmailCodeSetup`, `ConfirmEmailCode`, `RequestEmailProof`, `MintEmailCode`, `SecondFactorStatus`, `RegenerateRecoveryCodes`, `DisableSecondFactor` | `kit.Factors.<same>` (`*secondfactor.Module`) |
| `Config.Password`, `Hashing`, `HashConcurrency`, `HashWait`, `RevokeOnPasswordChange`, `ResetTTL`, `ResetFloor`, `Reset` | `password.Config`, same field names |
| `Config.Passkeys` (`authkit.PasskeyRules`) | `passkey.New(core, passkey.Rules{…})`, same fields |
| `Config.SecondFactors` (`authkit.SecondFactorRules`) | `secondfactor.New(core, secondfactor.Rules{…})`, same fields |
| `echov5.HashSlot(kit)` | `echov5.HashSlot(kit.Password)` (the `HashSlots` interface is unchanged) |

The moved `Config` fields are gone, so code that still sets one does not
compile. To upgrade:

1. `go get github.com/sylly-mika/authkit@v0.5.0`, then `go mod tidy`.
2. Add a `Kit` struct with the modules you use (see "Wire modules") and move
   the `Config` fields as the table says.
3. Rewrite the call sites one module at a time, for example
   `sed -i -E 's/\b(kit|a\.kit|s\.kit)\.(Login|ChangePassword|SetPassword|VerifyPassword|CheckPassword|HasCredential|AcquireHashSlot|RequestReset|CompleteReset|ResetFloor)\(/\1.Password.\2(/g'`
   over your Go files, with the receivers that
   `grep -rn '\.Login(' --include=*.go .` shows.
4. Split your own interfaces and fakes that list moved methods the same way;
   the compiler names each one.
5. Change `echov5.HashSlot(x)` to `echov5.HashSlot(x.Password)`.
6. Rerun `authkit-gen` with the same flags: it writes no migration and adds
   `"schema": ""` to the lock. Then run `go build ./... && go vet ./... &&
   go test ./...`.

**From v0.1.** A zero `Config` now means a 30-minute idle timeout and a
12-hour cap, 5 failures before a lockout, counting before verifying, hashed
throttle keys, `password_changed` from `ChangePassword`, no reset link for a
principal without a password, and 90 days of events. Migration 0002
(`absolute_expiry`) is required. `RefreshTTL` still works as a deprecated
name of `Session.IdleTTL` and wins when set. To keep v0.1 behaviour:

```go
cfg := authkit.Config{
	// Issuer, Secret, AccessTTL as before
	Session:        authkit.SessionRules{IdleTTL: 7 * 24 * time.Hour, AbsoluteTTL: -1}, // IdleTTL = your refresh TTL
	Throttle:       authkit.Throttle{Failures: 10, CountAfterVerify: true, PlainLoginKey: true},
	Events:         authkit.EventRules{ChangeLogsReset: true},
	EventRetention: -1,
}
kit, err := authkit.New(cfg, principals)
passwords, err := password.New(kit, password.Config{Reset: authkit.ResetRules{MayCreateCredential: true}})
```

**v0.3.0.** Migration 0003 adds `auth_passkeys`, `auth_passkey_ceremonies`
and the `auth_events.source` column (`Event.Source`; older rows read `""`).
If you use RLS, give the two new tables the same policies as
`auth_credentials`.

## Development

You need Docker and a local `gofmt`. Vet, tests and fuzzing run in the
`golang:1.27.1` image against a throwaway PostgreSQL 17.

| Command | What it does |
|---|---|
| `make start-db` | starts PostgreSQL on `localhost:5446` |
| `make stop` / `make clean` | stops it / also deletes its data |
| `make hooks` | points git at `.githooks`, whose pre-push runs `make verify` |
| `make roundtrip` | runs `authkit-gen`'s output through goose and golang-migrate |
| `make test-ns` | the tests again with every table in the `kit_ns` schema (`AUTHKIT_TEST_SCHEMA=kit_ns`) |
| `make verify` | gofmt, `go vet`, `go test -race` (plain and in `kit_ns`), the round trip and the fuzz targets |

Tests live in `tests/`, in `password/`, `passkey/`, `secondfactor/`, `oidc/`,
`register/` and `authkittest/oidcfake/`, and in
the root `*_test.go` files. `TestModuleDeps` runs `go list` and skips when
`go` is not on `PATH`.

## License

MIT, see [LICENSE](LICENSE).
