# Changelog

## v0.5.0

Breaking: authkit is a core plus modules. The core (`authkit`) keeps sessions, the login throttle, `Admit`, the second-factor gate, the sign-in log and every type, error and constant. Password sign-in, reset and changes move to `password.Module` (`password.New(core, password.Config)`), passkeys to `passkey.Module` (`passkey.New(core, passkey.Rules)`) and second factors to `secondfactor.Module` (`secondfactor.New(core, secondfactor.Rules)`); method signatures are unchanged. `Config.Password`, `Hashing`, `HashConcurrency`, `HashWait`, `RevokeOnPasswordChange`, `ResetTTL`, `ResetFloor` and `Reset` move to `password.Config`. `Config.Passkeys` and `Config.SecondFactors` are gone; `PasskeyRules` and `SecondFactorRules` become `passkey.Rules` and `secondfactor.Rules` with the same fields. `echov5.HashSlot` takes the `*password.Module`. An app links only the modules it imports: the core and `password` link neither `go-webauthn` nor `pquerna/otp`. The README's "Upgrading" section lists every move.

Without `secondfactor.New`, or with an empty `secondfactor.Rules.Key`, a sign-in by a principal with a confirmed factor fails closed with `ErrSecondFactorsOff`, as an empty `Config.SecondFactors.Key` did.

`Proposal.Source` names the path that asks `Admit` (`SourceLogin`, `SourcePasskeyLogin`, `SourceCompleteReset` and the rest, and the new `SourceAuthenticate` for `Authenticate`). It is the only behaviour change.

Modules: `Service.Attach(name)` returns a `*Core`, the handle a module uses for the throttle (`Begin`, `BeginVerified`, `Attempt`, `LoginThrottle`), `SignIn`, `Reopen`, sessions, `Record` and `SetVerifier` (`SecondStepVerifier`); a taken name is `ErrAttached`. `FactorPassword` names a password first factor, and `Meta.Clean` cleans request metadata. The `Core` API is unstable until v1.0.0.

Namespace: `Config.Schema` puts an install's tables in a PostgreSQL schema, so one database can hold several installs; `""` keeps the unqualified names. `authkit-gen -schema <name>` writes `NNNNN_authkit_<schema>_<name>` files, the first of which creates the schema, and records `"schema"` in the lock (`authkit.<schema>.lock` by default); a lock without the field reads as no schema. `authkittest.Schema(name)` builds a test database in a schema. `Service.CheckSchema` checks the tables in the install's schema (the package `CheckSchema` keeps reading the search path), and `onetime.NewIn(schema, now, rand)` builds a one-time store whose tables are in a schema; `Service.OneTime()` already uses the install's schema. No new migration: 0001 to 0004 are unchanged.

## v0.4.2

Tests: the black-box tests live in `tests/` and share their setup through `internal/kittest`; the hook tests stay in `hooks_test.go`. No API change.

## v0.4.1

Fix: the Service compares times at the database's microsecond precision; with a real clock, the first email code of a fresh row was refused as sent too soon about half the time.

## v0.4.0

Migration `0004_second_factors` adds the `auth_second_factors`, `auth_recovery_codes`, `auth_second_step_challenges` and `auth_email_codes` tables, and a `second_factor` column on `auth_sessions` and `auth_events`. The column is `''` until a session opens with a second factor. Apps regenerate their migrations with `authkit-gen`, and `CheckSchema` refuses a database below version 4. Each new table needs the app's RLS policies, as `auth_passkeys` does; the challenge and email-code tables are read only by the sign-in path and the mail worker.

Second factors: TOTP (`FactorTOTP`), email codes (`FactorEmail`) and recovery codes (`FactorRecovery`). `Config.SecondFactors` (type `SecondFactorRules`) turns them on; an empty `Key` leaves them off, and every second-factor method then returns `ErrSecondFactorsOff`. `SecondFactorStatus` reports which factors the caller has on and how many recovery codes remain. Setup is `BeginTOTPSetup` and `ConfirmTOTP` for an authenticator app, or `BeginEmailCodeSetup` and `ConfirmEmailCode` for email codes. `RequestEmailProof` stores an emailed code that the caller gives to `DisableSecondFactor` as proof, which turns a factor off. `RegenerateRecoveryCodes` issues a new set of recovery codes. A sign-in with a confirmed factor returns `Result.SecondStep` (type `SecondStep`) from `Login` and `CompleteReset`, and the app finishes it with `VerifySecondStep`, or sends the emailed code with `SendSecondStepEmail`. `MintEmailCode` returns the code for the mail worker. `Result` gains `SecondStep`, `TOTPSetup`, `EmailCode` (type `EmailCodeRequest`), `RecoveryCodes` and `RecoveryCodesLeft`, and `Proposal.SecondFactor` names the factor a sign-in completed. A refused second-factor step returns the refusal in `Result.Refusal`: `ErrBadCode`, `ErrChallengeEnded`, `ErrCodeEnded`, `ErrFactorExists`, `ErrFactorNotFound`, `ErrSetupExpired`, `ErrNoRecoveryCodes`, `ErrResendTooSoon` (type `ErrResendTooSoon`) and `ErrSecondFactorsOff`. The second-factor work adds the results `second_step_required`, `bad_code`, `factor_added`, `factor_removed` and `recovery_codes_regenerated`, and the sources `second_step` and `second_factor`.

## v0.3.0

Passkeys. `Config.Passkeys` (type `PasskeyRules`) turns them on; an empty RP ID leaves them off, and every passkey method then returns `ErrPasskeysOff`. Sign-in with a passkey is `BeginPasskeyLogin` and `FinishPasskeyLogin`. Adding one is `BeginPasskeyRegistration` and `FinishPasskeyRegistration`. `ListPasskeys`, `RenamePasskey` and `DeletePasskey` manage them. `OpenSessionFrom` is `OpenSession` for a workspace switch: the new session keeps the authenticated time of the session it came from. A refused passkey step returns the refusal in `Result.Refusal`: `ErrPasskeyRejected`, `ErrReauthRequired`, `ErrPasskeyLimit`, `ErrPasskeyExists`, `ErrPasskeyInvalid`, `ErrPasskeyNotFound`, `ErrPasskeyLabel` and `ErrNoPassword`. `Result.Ceremony` carries a passkey begin's answer, `Result.Passkey` the passkey a registration or rename wrote, and `Result.PasskeysRemoved` the count a completed reset deleted. `Event.Source` names the Service method that recorded the event, and the passkey work adds the results `bad_passkey`, `passkey_added`, `passkey_removed` and `passkeys_reset`.

Migration `0003_passkeys` adds the `auth_passkeys` and `auth_passkey_ceremonies` tables, the `auth_events.source` column, and the `passkey_removed` revoke reason for sessions.

`CompleteReset` removes every passkey the principal holds and reports the count in `Result.PasskeysRemoved`.

`authkittest.Authenticator` is a software authenticator for tests of passkey flows.

The passkey support depends on `github.com/go-webauthn/webauthn` v0.18.2.

## v0.2.0

Session mode, the cookie transport, pgx, goose; see the README's Upgrading from v0.1.
