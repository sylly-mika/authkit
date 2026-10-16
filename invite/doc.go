// Package invite is invitations by an admin: a pending row and a one-time link per invited address, the link minted at send time, and three ways to accept.
//
// Accept creates the invited principal with a password and signs it in. AcceptSignedIn lets a principal that already holds the address join, after it signed in. AcceptOIDC creates the principal from a Google or Apple sign-up ticket. A held address is never attached without a sign-in: Accept and AcceptOIDC refuse it with ErrSignInToAccept and leave the link live.
//
// Every write needs the caller's transaction and locks the invite row before it spends the link. The admin methods return errors; the accepts return refusals in Result.Refusal, and AcceptOIDC returns an error whenever the caller must roll back.
package invite
