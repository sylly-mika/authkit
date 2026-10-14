# Changelog

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
