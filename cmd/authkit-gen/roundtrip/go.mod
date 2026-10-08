module github.com/sylly-mika/authkit/cmd/authkit-gen/roundtrip

go 1.26.0

require (
	github.com/golang-migrate/migrate/v4 v4.19.1
	github.com/pressly/goose/v3 v3.27.0
	github.com/sylly-mika/authkit v0.0.0-00010101000000-000000000000
)

require (
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/lib/pq v1.12.0 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/sethvargo/go-retry v0.3.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

replace github.com/sylly-mika/authkit => ../../..
