# authkit

Password authentication for Go services on PostgreSQL: password sign-in,
sessions with rotating refresh tokens and reuse detection, password reset,
one-time links, a sign-in log and a per-login throttle, over tables the library
owns and keys by the app's principal uuid. Access tokens are HS256 JWTs
(`transport/bearer`), passwords are hashed with argon2id (`password`), and
`echov5` mounts the service on echo v5 (`ParseBearer`, `Guard`, `RateLimit`).

## Status

Pre-1.0: the API may change between minor versions.

## Install

```sh
go get github.com/sylly-mika/authkit@v0.1.0
```

## Database

PostgreSQL 17. The library owns the `auth_*` tables (`auth_schema`,
`auth_credentials`, `auth_sessions`, `auth_tokens`, `auth_events`,
`auth_throttle`); the app owns its principals table, whose `id` is a uuid.

The caller owns transactions and RLS: authkit never opens a transaction and
never binds an RLS setting. Every `Service` method runs on the `db.Querier` the
caller passes (a transaction or a pinned connection, never a pool), and the
methods that write or lock refuse to run outside a transaction
(`db.ErrTxRequired`). `db/sqldb` adapts `database/sql`.

The migrations are embedded in the module. `authkit-gen` copies them into the
app's golang-migrate directory, numbered after the app's own, with the
principals table filled in:

```sh
go run github.com/sylly-mika/authkit/cmd/authkit-gen -principals users -out migrations
```

`-principals` is required; `-out` defaults to `migrations` and `-lock` to
`authkit.lock`, which records what was written so a later run adds only the
migrations a newer library brings. At startup the app calls
`authkit.CheckSchema` to refuse a database older than the library.

## Development

Needs Docker and a local `gofmt`: vet, tests and fuzzing run in the
`golang:1.27.1` image against a throwaway PostgreSQL 17.

- `make start-db` starts it on `localhost:5446`; `make stop` stops it and
  `make clean` deletes its data.
- `make hooks` points git at `.githooks`, whose pre-push runs `make verify`.
- `make verify` runs gofmt, `go vet`, `go test -race` and the fuzz targets.

## License

MIT, see [LICENSE](LICENSE).
