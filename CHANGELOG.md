# Changelog

## v0.3.0

Passkeys. `Config.Passkeys` (type `PasskeyRules`) turns them on; an empty RP ID leaves them off, and every passkey method then returns `ErrPasskeysOff`. Sign-in with a passkey is `BeginPasskeyLogin` and `FinishPasskeyLogin`. Adding one is `BeginPasskeyRegistration` and `FinishPasskeyRegistration`. `ListPasskeys`, `RenamePasskey` and `DeletePasskey` manage them. `OpenSessionFrom` is `OpenSession` for a workspace switch: the new session keeps the authenticated time of the session it came from. A refused passkey step returns the refusal in `Result.Refusal`: `ErrPasskeyRejected`, `ErrReauthRequired`, `ErrPasskeyLimit`, `ErrPasskeyExists`, `ErrPasskeyInvalid`, `ErrPasskeyNotFound`, `ErrPasskeyLabel` and `ErrNoPassword`. `Result.Ceremony` carries a passkey begin's answer, `Result.Passkey` the passkey a registration or rename wrote, and `Result.PasskeysRemoved` the count a completed reset deleted. `Event.Source` names the Service method that recorded the event, and the passkey work adds the results `bad_passkey`, `passkey_added`, `passkey_removed` and `passkeys_reset`.

Migration `0003_passkeys` adds the `auth_passkeys` and `auth_passkey_ceremonies` tables, the `auth_events.source` column, and the `passkey_removed` revoke reason for sessions.

`CompleteReset` removes every passkey the principal holds and reports the count in `Result.PasskeysRemoved`.

`authkittest.Authenticator` is a software authenticator for tests of passkey flows.

The passkey support depends on `github.com/go-webauthn/webauthn` v0.18.2.

## v0.2.0

Session mode, the cookie transport, pgx, goose; see the README's Upgrading from v0.1.
