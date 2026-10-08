# authkit

Password authentication for Go services on PostgreSQL: password sign-in,
sessions with reuse detection, password reset, one-time links, a sign-in log
and a per-login throttle, over tables the library owns and keys by the app's
principal uuid. Passwords are hashed with argon2id (`password`).

Sessions travel one of two ways (`Config.Transport`):

- **Bearer** (`TransportBearer`, the default): HS256 access JWTs
  (`transport/bearer`) plus rotating refresh tokens, as in v0.1.
- **Session** (`TransportSession`): one opaque token in an `HttpOnly` cookie
  (`transport/cookie`), checked against the database on every request
  (`AuthenticateSession`). It rotates on activity, with reuse detection.

`echov5` mounts either on echo v5. `db/sqldb` adapts `database/sql`, and
`db/pgxdb` adapts pgx v5.

## Status

Pre-1.0: the API may change between minor versions.

## Install

```sh
go get github.com/sylly-mika/authkit@v0.2.0
```

## Database

PostgreSQL 17. The library owns the `auth_*` tables (`auth_schema`,
`auth_credentials`, `auth_sessions`, `auth_tokens`, `auth_events`,
`auth_throttle`); the app owns its principals table, whose `id` is a uuid.

The caller owns transactions and RLS: authkit never opens a transaction and
never binds an RLS setting. Every `Service` method runs on the `db.Querier` the
caller passes (a transaction or a pinned connection, never a pool), and the
methods that write or lock refuse to run outside a transaction
(`db.ErrTxRequired`).

- `db/sqldb` adapts `database/sql`.
- `db/pgxdb` adapts pgx v5: `pgxdb.Tx(tx)` over a `pgx.Tx`, `pgxdb.Conn(conn)`
  over a pinned `*pgxpool.Conn`, and `pgxdb.Pool` for the reads of an app
  without RLS settings. `pgxdb.Unwrap(q)` returns the `pgx.Tx` behind a `Tx`
  querier, so the app's own pgx code can run on the same transaction (in
  `Principals`, in `OnEvent`). Apps that don't import it don't pull in pgx.

The migrations are embedded in the module. `authkit-gen` copies them into the
app's migration directory, numbered after the app's own, with the principals
table filled in:

```sh
go run github.com/sylly-mika/authkit/cmd/authkit-gen -principals users -out migrations
go run github.com/sylly-mika/authkit/cmd/authkit-gen -principals users -out migrations -format goose
```

- `-principals` is required; `-out` defaults to `migrations` and `-lock` to
  `authkit.lock`, which records what was written so a later run adds only the
  migrations a newer library brings.
- `-format golang-migrate` (the default) writes `NNNNNN_authkit_<name>.up.sql`
  and `.down.sql` pairs.
- `-format goose` writes one `NNNNN_authkit_<name>.sql` per migration, with
  `-- +goose Up` and `-- +goose Down`. It is numbered after the highest
  `N_*.sql` or `N_*.go` in `-out` and keeps that file's digit width (5 when
  there is none). A statement containing `$$` is wrapped in
  `-- +goose StatementBegin`/`StatementEnd`.
- The lock records the format. A run whose `-format` differs from a lock that
  already lists migrations is refused before anything is written.

At startup the app calls `authkit.CheckSchema` to refuse a database older than
the library (`ErrSchemaBehind`).

## Configuration

`authkit.New(cfg, principals)` takes a `Config`. The zero value means the
default. A negative `Session.AbsoluteTTL`, `Session.RotateEvery` or
`EventRetention` turns that limit off; `New` refuses a negative value
anywhere else.

| Option | Zero value | Other values |
|---|---|---|
| `Transport` | `TransportBearer` | `TransportSession` |
| `Issuer`, `Secret` | required in Bearer mode (`Secret` at least 32 bytes) | ignored in Session mode |
| `AccessTTL` | 15 min (Bearer only) | |
| `Session.IdleTTL` | 30 min | `RefreshTTLFor` sets it per audience |
| `Session.AbsoluteTTL` | 12 h from sign-in | `< 0`: no cap |
| `Session.RotateEvery` | 15 min (Session mode) | `< 0`: never rotate |
| `RefreshTTL` | unset | deprecated alias of `Session.IdleTTL`; wins when set |
| `ResetTTL` / `ResetFloor` | 1 h / 500 ms | |
| `Throttle.Failures` / `Window` / `Lockout` | 5 / 15 min / 15 min | |
| `Throttle.CountAfterVerify` | false: count before verify | true: v0.1's order |
| `Throttle.PlainLoginKey` | false: key `auth_throttle` on hex(sha256(normalised login)) | true: the plain login, as v0.1 |
| `RevokeOnPasswordChange` | `RevokeOthers` | `RevokeAll`: also opens the caller a new session |
| `Events.ChangeLogsReset` | false: `ChangePassword` logs `password_changed` | true: logs `password_reset`, as v0.1 |
| `Reset.MayCreateCredential` | false: reset links only for a principal that has a password | true: a reset can set a first password |
| `EventRetention` | 90 days: `Prune` deletes older `auth_events` | `< 0`: keep forever |
| `Hashing` | argon2id 19 MiB, t=2, p=1 | |
| `Password` | 10 to 256 runes | |
| `HashConcurrency` / `HashWait` | 4 / 2 s | |
| `ReuseGrace` | 30 s | |
| `OnEvent` | nil | see Events |

The session defaults follow NIST SP 800-63B (rev 3) at AAL2: sign in again
after 30 minutes of inactivity and at least every 12 hours.

`New` refuses:

- Bearer mode without an `Issuer` or with a `Secret` under 32 bytes;
- `Session.IdleTTL` (or a `RefreshTTLFor` entry) above `AbsoluteTTL` when
  there is a cap;
- in Session mode, `RotateEvery` at or above `IdleTTL` (or an entry);
- a negative `RefreshTTL`, `IdleTTL`, `ResetTTL`, `ResetFloor`, `HashWait` or
  `ReuseGrace`, and a throttle or password policy that cannot work.

Switching `PlainLoginKey` off on a running app: existing counters stop
matching and lapse within `Lockout`. Nothing migrates.

## Sign-in order and the hash slot

`Login` counts before it verifies. It takes a hash slot, then locks and counts
the login's throttle row. `Failures` attempts within `Window` are judged; the
next is refused `ErrLocked` without a verify until `Lockout` passes. Success
clears the counter. The `locked` event names the principal when the login
resolves.

argon2id runs on at most `HashConcurrency` slots. When none frees up within
`HashWait`, the method refuses `ErrBusy`. Busy is a refusal and is never
counted.

To keep a waiting request from holding a database connection, take the slot
before opening the transaction: `ctx2, release, res, err :=
kit.AcquireHashSlot(ctx)`. `release` is never nil; call it when the request
ends. `res.Refusal` is `ErrBusy`; `err` is only `ctx`'s. Under `ctx2`,
`Login`, `VerifyPassword`, `ChangePassword`, `CompleteReset` and `SetPassword`
use that slot and take no other. Without it, each method takes a slot itself.

## Session mode with echo v5

- `echov5.SessionCookie(kit, aud, opts, inTx)` on the route group. It reads
  the cookie and runs `AuthenticateSession` in the app's `inTx` hook (begin,
  run `fn`, commit when it returns nil). On success it stores the `Result`
  (`echov5.Session`, `Claims`, `Admission`) and sets a rotated cookie. A
  refusal is committed and the request continues with no session.
- `echov5.RequireSession(opts, keepCookie)` per route: with no session it
  returns `ErrSessionEnded` and clears the cookie the request carried, unless
  `keepCookie`.
- `echov5.RequireOrigin(allow)` on cookie-authenticated mutations: every method
  but GET, HEAD and OPTIONS needs an `Origin` equal to an entry. An absent
  `Origin` is refused, `*` entries are dropped, and there is no Referer
  fallback.
- `echov5.HashSlot(kit)` on the routes that hash, before the app's
  transaction middleware.
- `echov5.RateLimit(r, burst)`, unchanged.

`cookie.Options{Name: "session"}` sets `__Host-session`: `Secure`, `HttpOnly`,
`Path=/`, no `Domain`, `SameSite=Strict` by default, with `Max-Age` running to
the absolute expiry. `Insecure: true` drops the prefix and `Secure` together,
for plain-HTTP development only.

| Sentinel | From | Status |
|---|---|---|
| `authkit.ErrSessionEnded` | `RequireSession`; `RevokeSession` refusals (`Logout` never refuses) | 401 (`RevokeSession`: 404) |
| `authkit.ErrBusy` | `HashSlot`; the hashing methods' `Result.Refusal` | 503 |
| `cookie.ErrForeignOrigin` | `RequireOrigin` | 403 |
| `authkit.ErrLocked` | `Login` | 429 with `Retry-After` |

```go
inTx := func(ctx context.Context, fn func(q db.Querier) error) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error { return fn(pgxdb.Tx(tx)) })
}
opts := cookie.Options{Name: "session"} // __Host-session
g := e.Group("/api",
	echov5.SessionCookie(kit, "staff", opts, inTx),
	echov5.RequireOrigin([]string{"https://app.example.invalid"}),
)
g.POST("/login", login, echov5.RateLimit(rate.Limit(1), 5), echov5.HashSlot(kit))
g.GET("/me", me, echov5.RequireSession(opts, false))

// in login, under the request's ctx (it carries the slot):
//   res, err = kit.Login(ctx, q, "staff", login, pw, m)   inside inTx
//   on success: opts.Set(c.Response(), res.SessionToken, res.Session.AbsoluteExpiresAt)
```

`Login`, `OpenSession`, `CompleteReset` and `ChangePassword` under `RevokeAll`
return `Result.SessionToken` in Session mode; `Result.Claims()` feeds the
account methods. `Refresh` and `Authenticate` are Bearer only.

Accepted risk: if a rotation's `Set-Cookie` never reaches the browser, the old
token turns into reuse after `ReuseGrace` and the session ends.

## Events

`Event.Source` names the method that recorded an event (`authkit.SourceLogin`,
`SourceChangePassword`, ...). It is set on the value `OnEvent` receives and is
not stored. `Config.OnEvent(ctx, q, e)` runs straight after authkit records an
event, on the same querier, so in the same transaction; its error fails the
method. `ChangePassword` logs the new result `password_changed`
(`ResultPasswordChanged`). `Prune` also deletes events older than
`EventRetention`.

## Upgrading from v0.1

v0.1 code compiles unchanged. With a zero `Config`, these change: a 30-minute
idle timeout and a 12-hour cap, 5 failures before a lockout, count-before-verify,
hashed throttle keys, `password_changed`, no reset link for a principal without
a password, and 90 days of events.

To keep v0.1 behaviour:

```go
cfg := authkit.Config{
	// Issuer, Secret, AccessTTL as before
	Session:        authkit.SessionRules{IdleTTL: 7 * 24 * time.Hour, AbsoluteTTL: -1}, // IdleTTL = your refresh TTL
	Throttle:       authkit.Throttle{Failures: 10, CountAfterVerify: true, PlainLoginKey: true},
	Events:         authkit.EventRules{ChangeLogsReset: true},
	Reset:          authkit.ResetRules{MayCreateCredential: true},
	EventRetention: -1,
}
```

`RefreshTTL` still works as a deprecated alias of `Session.IdleTTL` and wins
when set. Rerun `authkit-gen` to add core migration 0002
(`absolute_expiry`), and apply it before deploying, or `CheckSchema` refuses
to start.

## Development

Needs Docker and a local `gofmt`: vet, tests and fuzzing run in the
`golang:1.27.1` image against a throwaway PostgreSQL 17.

- `make start-db` starts it on `localhost:5446`; `make stop` stops it and
  `make clean` deletes its data.
- `make hooks` points git at `.githooks`, whose pre-push runs `make verify`.
- `make roundtrip` runs `authkit-gen`'s output through goose and
  golang-migrate against the database.
- `make verify` runs gofmt, `go vet`, `go test -race`, the round trip and the
  fuzz targets.

## License

MIT, see [LICENSE](LICENSE).
