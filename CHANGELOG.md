# Changelog

## v0.8.0

Android app passkeys and a relying party ID per audience. No existing signature, default or error text changes, and there is no new migration: `CheckSchema` still wants version 7.

`passkey`: `passkey.Rules.Origins` also takes an Android app's origin, `android:apk-key-hash:` and the unpadded base64url SHA-256 of its signing certificate; it is matched byte for byte and only for the audience that lists it. An audience with only app origins also accepts `https://` and its RP ID, which go-webauthn needs. `passkey.Rules.RPIDs` (`map[authkit.Audience]string`) gives an audience its own RP ID in place of `RPID`; each key must be in `Origins`, and that audience's web origins must sit under it. `RPID` still switches passkeys on.

## v0.7.1

Moving an app with its own sign-in onto authkit: a legacy password verifier, sessions of another principal, and an absolute lifetime per audience. No existing signature or default changes, and there is no new migration: `CheckSchema` still wants version 7.

`password`: `password.Legacy` verifies a hash format that is not argon2id (`Owns`, `Verify`); `password.Config.Legacy` lists them, tried in order, and nil keeps today's behaviour, where such a hash is `password.ErrMalformed`. `password.Bcrypt()` owns `$2a$`, `$2b$` and `$2y$` hashes; a cost above 14 is `ErrMalformed` and a password over 72 bytes does not match. After a legacy hash verifies, `Login` stores an argon2id hash in its place. `Login` still does not apply the length policy, so a copied password shorter than `MinRunes` keeps working. `Module.SetPassword` is now documented to replace an existing password: it logs `password_reset` for a principal that had one (`password_set` otherwise) and revokes nothing, so call `RevokeAllSessions` after it. Its code is unchanged.

Core: `Service.ListSessionsOf` and `Service.RevokeSessionOf` list and end the sessions of a principal you name, for an admin acting on another login; your app checks that the caller may. `RevokeSessionOf` takes a revoke reason, writes the same row and `revoked` event as `RevokeSession`, and answers `ErrSessionEnded` for an id that is not that principal's open session. `SessionRules.AbsoluteTTLFor` (`map[Audience]time.Duration`) sets the absolute lifetime per audience; `-1` means no cap, and an audience without an entry keeps `Session.AbsoluteTTL`. `New` checks each audience's idle lifetime against that audience's absolute lifetime.

Docs: the README shows how to move users from another system: bcrypt hashes as they are, and open sessions whose refresh tokens were stored as a hex SHA-256.

No new dependency: `golang.org/x/crypto/bcrypt` is part of `golang.org/x/crypto`, already required.

## v0.7.0

Account management: invites, erasure (`Forget`), recent sign-in with re-verify, and verified email change. No existing signature changes, and with `Config.Recent` and every module `Reauth` left at zero the windows stay 5 minutes. Migration `0007_account` is required: `CheckSchema` refuses a database below version 7, even for an app that uses none of the new parts.

`invite` (new): `invite.New(core, pw, invite.Rules)` returns an `*invite.Module` attached as `"invite"`. `invite.Rules` holds `TTL` (72 h), `Create` (required), `Join`, `Check` and `OIDC` (an `invite.Tickets`, which `*oidc.Module` satisfies). `Invite` takes an `invite.Request` and returns an `invite.Invited` (`ID`, `TokenID`, `Holder`); `Resend` replaces the link and restarts the expiry; `Revoke` closes the invite; `List` pages `invite.Invite` rows with their `invite.State` (`pending`, `expired`, `accepted`, `revoked`). `Mint` returns the `invite.Mail` for a `TokenID` (the link expires with the invite at the latest), and `Open` returns an `invite.Opened` without spending the link; `invite.Pending` is the invite your `Create`, `Join` and `Check` see. Three accepts: `Accept` (a password; creates the principal and signs in), `AcceptSignedIn` (the signed-in holder of the address joins; `ResultInviteAccepted`, no new session) and `AcceptOIDC` (a Google or Apple sign-up ticket; an Apple private relay address is refused). Errors: `invite.ErrInvitePending`, `invite.ErrInviteClosed`, `invite.ErrSignInToAccept`, `invite.ErrOtherAccount`, `invite.ErrAddressHeld`, `invite.ErrNothingToSend`, `invite.ErrEmailMismatch`, `invite.ErrPrivateEmail` and `invite.ErrNoOIDC`.

`emailchange` (new): `emailchange.New(core, emailchange.Rules)` returns an `*emailchange.Module` attached as `"emailchange"`. `emailchange.Rules` holds `TTL` (24 h), `Change` (required) and `RevokeAll`. `Start` (needs a recent sign-in) and `StartFor` (an admin's change) return an `emailchange.Started` (`TokenID`, `Old`, `AddressHeld`, `RetryAfter`); starts are capped at 3 an hour. `Mint` returns the `emailchange.Mail`. `Confirm` spends the link, calls `Change`, moves the login throttle, ends the other sessions (`ReasonEmailChanged`) and returns an `emailchange.Changed` (`Old`, `New`). `Pending` returns the `emailchange.Pending` change and `Cancel` drops it. Errors: `emailchange.ErrSameAddress`, `emailchange.ErrAddressHeld`, `emailchange.ErrStale` and `emailchange.ErrNothingToSend`.

Core: `Config.Recent` (5 min, at most 10 min, negative refused) is how recent a sign-in must be for a sensitive change; a module's zero `Reauth` now means `Config.Recent`. `Service.RequireRecent` refuses with `ErrReauthRequired` or `ErrSessionEnded`. `Service.Forget` deletes a principal's authkit rows in every audience inside the caller's transaction and returns a `Forgotten` (`Sessions`, `Passkeys`, `Identities`, `Providers`); sign-in log rows are unlinked and kept until `EventRetention`, or deleted when it is negative. `LoginThrottle.MoveTo` carries a login's failed attempts to another login. New constants: the results `ResultInviteAccepted`, `ResultReverified` and `ResultEmailChanged`; the sources `SourceInvite`, `SourceReverify` and `SourceEmailChange`; the revoke reason `ReasonEmailChanged`; the link purposes `PurposeInvite` and `PurposeEmailChange`. `Prune` also deletes invites 30 days after they expire, are accepted or are revoked, and email changes past their expiry.

Re-verify: `password.Module.Reverify`, `secondfactor.Module.Reverify` (TOTP only), `passkey.Module.BeginReverify` and `FinishReverify`, and `oidc.Module.BeginReverify` (`prompt=login`, `max_age=0`) and `FinishReverify` mark the caller's session as just authenticated and record `reverified`. The session token is not rotated; the package doc says why (ASVS 7.2.4). `oidc.Module.TicketEmail` reads a sign-up ticket's email without spending it, and `Finish` refuses a re-verify ceremony.

Migrations: `0007_account` adds `auth_invites` and `auth_email_changes`, the `reverify` ceremony kind on `auth_passkey_ceremonies` and `auth_ceremonies`, and the `email_changed` revoke reason. Regenerate with `authkit-gen`. If you use RLS, give the two tables policies; `authkittest/policies.sql` shows them.

Tests: `oidcfake.User.AuthTime` sets the `auth_time` claim, and `Server.LastAuthorize` returns the query of the last authorize request.

Internal, no API: `internal/pending` (`Owner`, `Mint`) is shared by `register`, `invite` and `emailchange`; `throttle.Move` backs `MoveTo`; `internal/kittest` gains `Rules.Invite`, `Rules.EmailChange`, `Kit.Invite` and `Kit.EmailChange`. No new dependency.

## v0.6.0

Sign-in with Google and Apple (OpenID Connect), and a registration module. No existing signature changes. Migrations `0005_oidc` and `0006_register` are required: `CheckSchema` refuses a database below version 6, even for an app that uses neither module.

`oidc` (new): `oidc.New(core, oidc.Rules)` returns a `*oidc.Module` attached as `"oidc"`. `oidc.Rules` holds `Providers`, `CeremonyTTL` (10 min), `Skew` (5 min), `Reauth` (5 min) and `HTTPClient` (default: a 10 s timeout). An `oidc.Provider` has static endpoints, so nothing is discovered at startup. `oidc.Google(clientID, secret, redirectURL)` and `oidc.Apple(teamID, keyID, servicesID, p8, redirectURL)` build one; Apple's client secret is an ES256 JWT signed for each token request. `Begin` returns an `oidc.Redirect` (`URL`, `Binding`, `SameSite`). `oidc.ParseCallback` reads an `oidc.Callback` from a GET or a form POST of at most 64 KiB (`oidc.ErrBadCallback`). `Finish` spends the ceremony once, exchanges the code with PKCE and checks the ID token (RS256 signature, `iss`, `aud`, `azp`, nonce, `iat`, `exp`). A known identity signs in. `Google` and `Apple` set `Provider.SkipSecondFactor`, so their sign-ins skip the second step, as a passkey does. An unknown identity returns an `oidc.SignUp` (`Ticket`, `Provider`, `Email`, `Name`, `GivenName`, `FamilyName`, `PrivateEmail`): `Ticket` reads it, and the `SignUp` method spends it into an identity and a session. An email that matches a principal is never linked: `oidc.ErrSignInToLink`. `Link` and `Unlink` take the caller's `*authkit.Claims`, `Identities` lists `oidc.Identity` values and `Providers` lists the configured names. The errors are `oidc.ErrCancelled`, `oidc.ErrEmailUnverified`, `oidc.ErrSignInToLink`, `oidc.ErrIdentityUnknown`, `oidc.ErrIdentityTaken`, `oidc.ErrLastCredential`, `oidc.ErrNotLinked`, `oidc.ErrTicketUnknown` and `oidc.ErrUnknownProvider`.

`register` (new): `register.New(core, pw, register.Rules)` returns a `*register.Module` attached as `"register"`. `register.Rules` holds `Create` (required), `TTL` (48 h), `MailCap` (3), `MailWindow` (1 h, at most 24 h) and `Floor` (500 ms). `Start` records a `register.Pending` registration with the app's payload and answers a `register.Started` (`TokenID`, `Holder` or `RetryAfter`); a second `Start` replaces the link. `Mint` returns the `register.Mail` for a `TokenID`, or `register.ErrNothingToSend`. `CountMail` counts one mail against the cap. `Floor` is the register handler's minimum time. `Activate` checks the password with the `password` module, spends the link, calls `Create`, stores the password and signs in. It answers `register.ErrAddressHeld` when a principal holds the address.

`password`: `Module.Hash` returns a `password.Hash` that has passed the policy and the hasher. `Module.SetHash` stores one as a principal's first password (`password.ErrCredentialExists`, `password.ErrNoHash`).

Core: `FactorOIDC`; the results `ResultBadIdentity`, `ResultIdentityLinked`, `ResultIdentityUnlinked` and `ResultRegistered`; the sources `SourceOIDC` and `SourceRegister`; the revoke reason `ReasonIdentityRemoved`; the link purpose `PurposeRegister`; `Attempt.SkipSecondFactor`. `Prune` also deletes OIDC ceremonies an hour after they expire or are used, expired registrations, and mail counts 48 hours after their window began. `Core.ResetCredentials`, and so `CompleteReset`, also deletes the principal's OIDC identities.

Migrations: `0005_oidc` adds `auth_ceremonies` and `auth_identities`, the `oidc` value of `second_factor` on `auth_sessions` and `auth_events`, and the `identity_removed` revoke reason. `0006_register` adds `auth_registrations` and `auth_mail_counts`. Regenerate with `authkit-gen`. If you use RLS, give the four tables policies; `authkittest/policies.sql` shows them.

Tests: `authkittest/oidcfake` is a local Google or Apple over `httptest` TLS. `oidcfake.New(t, oidcfake.Google)` (or `oidcfake.Apple`, of type `oidcfake.Kind`) returns an `*oidcfake.Server` (`URL`, `Client`, `ClientID`, `Now`). Its methods are `Provider`, `Authorize` (for an `oidcfake.User`), `Tamper`, `SignNextWith` and `Exchanges`. `authkittest` itself links neither go-oidc nor go-jose.

Dependencies: `github.com/coreos/go-oidc/v3` v3.21.0, `github.com/go-jose/go-jose/v4` v4.1.6 and `golang.org/x/oauth2` v0.37.0. Only `oidc` and `authkittest/oidcfake` link them.

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
