# authkit

authkit is a Go library for password authentication on PostgreSQL. It covers
password sign-in, sessions with token-reuse detection, password reset,
one-time links, a sign-in log, a per-login throttle, passkeys and second
factors (TOTP, emailed codes, recovery codes). Passwords are hashed with
argon2id. authkit owns its `auth_*` tables; your app owns its users
("principals") table and its own data.

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
go get github.com/sylly-mika/authkit@v0.4.2
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
| `authkit` | `Config`, `New`, `Service` and its methods |
| `db` | `db.Querier`, the SQL interface every method runs on |
| `db/pgxdb`, `db/sqldb` | wrap a pgx or `database/sql` transaction as a `db.Querier` |
| `echov5` | echo v5 middleware |
| `transport/cookie` | the session cookie (Session mode) |
| `cmd/authkit-gen` | copies authkit's migrations into your migration directory |
| `authkittest` | Postgres test harness, fake principals, software passkey authenticator |

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
	g.POST("/login", login(kit, inTx, opts), echov5.RateLimit(rate.Limit(1), 5), echov5.HashSlot(kit))
	g.GET("/me", me, echov5.RequireSession(opts, false))
	log.Fatal(http.ListenAndServe(":8080", e))
}

func login(kit *authkit.Service, inTx func(context.Context, func(db.Querier) error) error, opts cookie.Options) echo.HandlerFunc {
	return func(c *echo.Context) error {
		ctx := c.Request().Context() // carries the hash slot HashSlot took
		m := authkit.Meta{IP: c.RealIP(), UserAgent: c.Request().UserAgent()}
		var res authkit.Result
		err := inTx(ctx, func(q db.Querier) error {
			var err error
			res, err = kit.Login(ctx, q, aud, c.FormValue("login"), c.FormValue("password"), m)
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
| `-out` | `migrations` | your migration directory |
| `-lock` | `authkit.lock` | records what was written, so a later run adds only new migrations |
| `-format` | `golang-migrate` | `golang-migrate` writes `NNNNNN_authkit_<name>.up.sql` and `.down.sql`; `goose` writes one `NNNNN_authkit_<name>.sql` with `-- +goose Up` and `-- +goose Down` |

With `goose`, numbering follows the highest `N_*.sql` or `N_*.go` file in
`-out` and keeps its digit width (5 when there is none). A statement
containing `$$` is wrapped in `-- +goose StatementBegin`/`StatementEnd`. Once
the lock lists migrations, a run with a different `-format` is refused
before anything is written.

The migrations create these tables: `auth_schema`, `auth_credentials`,
`auth_sessions`, `auth_tokens`, `auth_events`, `auth_throttle`,
`auth_passkeys`, `auth_passkey_ceremonies`, `auth_second_factors`,
`auth_recovery_codes`, `auth_second_step_challenges`, `auth_email_codes`.

Your app must:

- Apply the migrations with its own migration tool, before deploying code
  that needs them.
- Call `authkit.CheckSchema(ctx, q)` once at startup. It returns
  `authkit.ErrSchemaBehind` when `auth_schema.version` is older than the
  library's migrations.
- Write its own RLS policies if it uses RLS. The migrations contain none.
  `authkittest/policies.sql` shows the policies authkit's own tests use; for
  example, `auth_passkeys` and `auth_passkey_ceremonies` get the same policies
  as `auth_credentials`.

### Pass a transaction

Every `Service` method takes a `db.Querier` as its second argument. Methods
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
`""`, `totp`, `email`, `recovery` or `passkey`). To allow, return an
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

`Login(ctx, q, aud, login, pw, m)` counts the attempt on the login's throttle
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
ctx2, release, res, err := kit.AcquireHashSlot(ctx)
defer release() // never nil
if err != nil { return err }               // only ctx's error
if res.Refusal != nil { /* ErrBusy: answer 503 */ }
// Open the transaction, then pass ctx2 to Login, VerifyPassword,
// ChangePassword, CompleteReset or SetPassword: it carries the slot.
res, err = kit.Login(ctx2, q, aud, login, password, m)
```

When the principal has a confirmed second factor, `Login` opens no session
and returns `Result.SecondStep` instead (see "Add second factors").

`OpenSession(ctx, q, p, aud, m)` signs in a principal your app has
authenticated itself, such as an accepted invitation.
`OpenSessionFrom(ctx, q, from, p, aud, m)` opens a session that keeps the
sign-in time of session `from` (same principal and audience, which may be
revoked or expired), for a workspace switch.

### Add password reset

1. `RequestReset(ctx, q, aud, login)` creates a reset link and returns its id
   in `Result.TokenID`. Enqueue the email with that id in the same
   transaction. An unknown login, or one without a password (unless
   `Reset.MayCreateCredential`), writes nothing and has no `TokenID`. Answer
   the same way in both cases, and after the transaction commits call
   `authkit.PadSince(start, kit.ResetFloor())` so both take the same time.
2. Your mail worker, in its own transaction, calls
   `kit.OneTime().Mint(ctx, q, id)`. The returned `Minted.Raw` goes into the
   email and nowhere else.
3. The link handler calls `CompleteReset(ctx, q, aud, raw, newPassword, m)`.
   It checks the password policy, spends the link, sets the password and
   revokes every session of the principal. It also deletes the principal's
   passkeys (`Result.PasskeysRemoved`). With a second factor on, it returns
   `Result.SecondStep` instead of a session.

`kit.OneTime()` is also available for your own one-time links (invitations).

### Change or set a password

- `ChangePassword(ctx, q, claims, current, next, m)` replaces the caller's
  password. `RevokeOnPasswordChange` decides the caller's own session:
  `RevokeOthers` (default) keeps it, `RevokeAll` replaces it with a new one in
  `Result.Tokens` or `Result.SessionToken`. Passkeys are kept.
- `SetPassword(ctx, q, p, aud, pw, m)` gives a principal without a password
  its first one. It revokes nothing.
- `VerifyPassword(ctx, q, p, aud, pw, m)` checks a password inside your own
  flow. A mismatch is `ErrInvalidCredentials`; it does not touch the throttle.
- `HasCredential(ctx, q, principal)` reports whether a principal has a
  password. `kit.CheckPassword(pw)` applies the policy alone.

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
for 30 days, passkey ceremonies and
second-step challenges an hour past expiry, and events older than
`EventRetention` (none when it is negative).

### Add passkeys

Passkeys are off until `Config.Passkeys.RPID` is set; until then every
passkey method refuses with `authkit.ErrPasskeysOff`. `RPID` is your domain
with no scheme, port or path. `Passkeys.Origins` lists the allowed origins
per audience: `https`, or `http` only when `RPID` is `localhost`, each host
equal to `RPID` or ending in `.` + `RPID`. A ceremony begun on one audience
cannot be finished on another.

```go
cfg.Passkeys = authkit.PasskeyRules{
	RPID:    "example.com",
	Origins: map[authkit.Audience][]string{"web": {"https://app.example.com"}},
}
```

Sign-in:

1. `BeginPasskeyLogin(ctx, q, aud, m)` stores a ceremony and returns it in
   `Result.Ceremony` (`ID`, `Options` for the browser, `ExpiresAt`). It takes
   no login.
2. `FinishPasskeyLogin(ctx, q, aud, ceremonyID, response, m)` takes the
   browser's JSON response, calls `Admit` and opens a session as `Login`
   does. Every refusal is `authkit.ErrPasskeyRejected`, except a refusal from
   your `Admit`. The password throttle is not used.

Registration needs a principal with a password (`ErrNoPassword`), a sign-in
within `Passkeys.Reauth` (`ErrReauthRequired`) and fewer than `Passkeys.Max`
passkeys (`ErrPasskeyLimit`): `BeginPasskeyRegistration(ctx, q, claims, m)`,
then `FinishPasskeyRegistration(ctx, q, claims, ceremonyID, response, label,
m)`.

Management: `ListPasskeys(ctx, q, principal)`; `RenamePasskey(ctx, q, claims,
id, label)` (label 1 to 64 characters, `ErrPasskeyLabel`; no recent sign-in
needed); `DeletePasskey(ctx, q, claims, id, m)` (needs a sign-in within
`Reauth`, revokes the principal's other sessions). Another principal's
passkey is `ErrPasskeyNotFound`, like an unknown one.

### Add second factors

Second factors are off until `Config.SecondFactors.Key` is set to 32 bytes.
The key seals the TOTP secrets. Until it is set, every second-factor method
refuses with `authkit.ErrSecondFactorsOff`, and so does `Login` for a
principal that has a confirmed factor.

Setting a factor up needs a sign-in within `SecondFactors.Reauth`
(`ErrReauthRequired`):

- TOTP: `BeginTOTPSetup(ctx, q, claims, m)` returns `Result.TOTPSetup` (`URI`,
  `Secret`, `QRPNG` a 256x256 PNG, `ExpiresAt`); `ConfirmTOTP(ctx, q, claims,
  code, m)` turns it on.
- Email: `BeginEmailCodeSetup(ctx, q, claims, m)` returns `Result.EmailCode`
  for your mail worker; `ConfirmEmailCode(ctx, q, claims, code, m)` turns it
  on.
- The first confirmed factor returns 10 recovery codes in
  `Result.RecoveryCodes`. Show them once.
- `SecondFactorStatus(ctx, q, claims)` returns a `FactorStatus` (`TOTP`,
  `Email`, `RecoveryCodesLeft`). `RegenerateRecoveryCodes(ctx, q, claims, m)`
  replaces the codes. `DisableSecondFactor(ctx, q, claims, kind, proof, m)`
  turns one factor off, with a `FactorProof{Method, Code}` from any factor or
  a recovery code; `RequestEmailProof(ctx, q, claims, m)` mails a code to use
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
mail worker calls `kit.MintEmailCode(ctx, q, id)` and mails the 6-digit
`EmailCodeMail.Code`. `ErrCodeEnded` means the code was replaced, expired or
used up.

### Test your integration

`authkittest` is a Postgres test harness: `NewDB(t)`, `(*DB).InAuthTx(ctx,
fn)`, `(*DB).NewPrincipal(t, login)`, `NewPrincipals()` (a `Principals` you
can set to refuse or allow), `NewClock()` (starts 2040-01-01 12:00 UTC),
`Rand(seed)`, and `NewAuthenticator(rpID, origin)`, a software passkey
authenticator whose `Create` and `Get` answer the options JSON.
`Config.Clock` and `Config.Rand` take the clock and random source.

## Configuration reference

`authkit.New(cfg, principals)` takes a `Config`. A zero field takes its
default. A negative `Session.AbsoluteTTL`, `Session.RotateEvery` or
`EventRetention` turns that limit off.

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
| `ResetTTL` | 1 h | reset link lifetime |
| `ResetFloor` | 500 ms | minimum time for a reset request (`PadSince`) |
| `Reset.MayCreateCredential` | false | true: a reset can set a first password for a principal without one |
| `Password` | 10 to 256 runes | `password.Policy{MinRunes, MaxRunes}` |
| `Hashing` | argon2id 19 MiB, t=2, p=1 | `password.Params` |
| `HashConcurrency` | 4 | argon2id slots |
| `HashWait` | 2 s | wait for a slot before `ErrBusy` |
| `Throttle.Failures` | 5 | failures within `Window` before a lockout |
| `Throttle.Window` | 15 min | counting window |
| `Throttle.Lockout` | 15 min | lockout length |
| `Throttle.CountAfterVerify` | false | false: count before verifying; true: v0.1's order |
| `Throttle.PlainLoginKey` | false | false: key `auth_throttle` on hex(sha256(normalised login)); true: the plain login |
| `RevokeOnPasswordChange` | `RevokeOthers` | `RevokeAll` also replaces the caller's session |
| `Events.ChangeLogsReset` | false | true: `ChangePassword` logs `password_reset` instead of `password_changed` |
| `EventRetention` | 90 days | `Prune` deletes older events; negative: keep forever |
| `OnEvent` | nil | `func(ctx, q db.Querier, e Event) error`, run after each event |
| `Clock` | system clock | source of every timestamp |
| `Rand` | `crypto/rand.Reader` | random source |
| `Passkeys.RPID` | empty (off) | relying party domain; set to turn passkeys on |
| `Passkeys.RPName` | `authkit` | relying party name |
| `Passkeys.Origins` | none | `map[Audience][]string` of allowed origins |
| `Passkeys.CeremonyTTL` | 2 min | ceremony lifetime, at most 10 min |
| `Passkeys.Reauth` | 5 min | how recent a sign-in must be to add or delete a passkey |
| `Passkeys.Max` | 10 | passkeys per principal |
| `SecondFactors.Key` | empty (off) | 32 bytes; set to turn second factors on |
| `SecondFactors.Issuer` | `authkit` | issuer shown in authenticator apps |
| `SecondFactors.ChallengeTTL` | 10 min | second-step challenge lifetime |
| `SecondFactors.EmailCodeTTL` | 10 min | emailed code lifetime |
| `SecondFactors.SetupTTL` | 15 min | factor setup lifetime |
| `SecondFactors.ResendEvery` | 60 s | minimum gap between emailed codes |
| `SecondFactors.MaxSends` | 5 | emailed codes per setup or challenge |
| `SecondFactors.MaxTries` | 5 | wrong tries per code |
| `SecondFactors.Reauth` | 5 min | how recent a sign-in must be to manage factors |
| `SecondFactors.RecoveryCodes` | 10 | recovery codes issued |

`New` refuses:

- Bearer mode without `Issuer`, with a `Secret` under 32 bytes, or with a
  negative `AccessTTL`.
- `Session.IdleTTL` (or a `RefreshTTLFor` entry) above `AbsoluteTTL` when
  there is a cap.
- In Session mode, `RotateEvery` at or above `IdleTTL` (or an entry).
- A negative `RefreshTTL`, `Session.IdleTTL`, `ResetTTL`, `ResetFloor`,
  `HashWait` or `ReuseGrace`, and a negative `HashConcurrency`.
- A throttle or password policy that cannot work, a `SecondFactors.Key` that
  is neither empty nor 32 bytes, and invalid passkey settings (`RPID`,
  `Origins`, `CeremonyTTL`).

Switching `PlainLoginKey` off on a running app orphans the existing throttle
counters; nothing migrates them.

## Errors and refusals

Refusals arrive in `Result.Refusal` with a nil `error`, except where the
"From" column names middleware, which returns them as the handler error.
Compare with `errors.Is`, or `errors.As` for the struct types. Status codes
are the ones echov5's documentation suggests; elsewhere they are your choice.

| Error | From | Meaning |
|---|---|---|
| `ErrInvalidCredentials` | `Login`, `VerifyPassword` | wrong password or unknown login |
| `ErrLocked{RetryAfter}` | `Login`, `VerifySecondStep`, `SendSecondStepEmail`, `DisableSecondFactor` | throttle locked; retry after `RetryAfter` |
| `ErrBusy` | hashing methods; `echov5.HashSlot` (503) | no argon2id slot within `HashWait` |
| `ErrSessionEnded` | `Authenticate`, `RevokeSession`; `echov5.RequireSession`, `echov5.Guard` (401) | session missing, revoked or expired |
| `ErrStale` | `Authenticate`, `echov5.Guard` | the session's access changed; refresh |
| `ErrMissingToken`, `ErrInvalidToken`, `ErrWrongAudience` | `echov5.ParseBearer` | bad or absent access token |
| `cookie.ErrForeignOrigin` | `echov5.RequireOrigin` (403) | `Origin` absent or not allowed |
| `ErrCurrentPasswordWrong` | `ChangePassword` | the current password is wrong |
| `PolicyError` | `ChangePassword`, `SetPassword`, `CompleteReset` | the password fails the policy (`MinRunes`, `MaxRunes`) |
| `ErrTokenUnknown`, `ErrTokenGone{State}` | `CompleteReset`; `ErrTokenGone` also from `OneTime()` | link unknown; link exists but can no longer be spent |
| `ErrPasskeysOff` | passkey methods | `Passkeys.RPID` not set |
| `ErrPasskeyRejected` | `BeginPasskeyLogin`, `FinishPasskeyLogin` | passkey sign-in failed |
| `ErrNoPassword`, `ErrReauthRequired`, `ErrPasskeyLimit` | passkey registration; `ErrReauthRequired` also from `DeletePasskey` and second-factor methods | no password, sign-in too old, too many passkeys |
| `ErrPasskeyExists`, `ErrPasskeyInvalid` | passkey registration | already registered; no relying party for the audience or the ceremony cannot be spent |
| `ErrPasskeyNotFound` | `RenamePasskey`, `DeletePasskey` | not the caller's passkey |
| `ErrPasskeyLabel` | `RenamePasskey`, `FinishPasskeyRegistration` | bad label |
| `ErrSecondFactorsOff` | second-factor methods, `Login` | `SecondFactors.Key` not set |
| `ErrBadCode`, `ErrChallengeEnded`, `ErrCodeEnded`, `ErrSetupExpired` | second-factor methods | wrong code; challenge, code or setup no longer valid |
| `ErrFactorExists`, `ErrFactorNotFound` | second-factor methods | factor already on; factor not on |
| `ErrResendTooSoon{RetryAfter}` | emailed-code methods | a new code asked for too soon |
| your `Refuse(result, err)` error | any method that calls `Admit` | your app refused the session |
| `db.ErrTxRequired` (an `error`, not a refusal) | methods that write or lock | called outside a transaction |
| `ErrSchemaBehind` (an `error`) | `CheckSchema` | run the migrations |

## Upgrading

Each release may add migrations. After every upgrade, rerun `authkit-gen`
with the same flags and lock file, and apply the new migrations before
deploying; otherwise `CheckSchema` refuses to start with `ErrSchemaBehind`.
See `CHANGELOG.md` for the full list of changes.

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
	Reset:          authkit.ResetRules{MayCreateCredential: true},
	EventRetention: -1,
}
kit, err := authkit.New(cfg, principals)
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
| `make verify` | gofmt, `go vet`, `go test -race`, the round trip and the fuzz targets |

Tests live in `tests/` and in the root `*_test.go` files.

## License

MIT, see [LICENSE](LICENSE).
