// Package emailchange changes a principal's login to a new address only after the new mailbox confirms a one-time link.
//
// Start needs a recent sign-in and writes nothing for an address another principal holds, so the app can answer as for a free one; StartFor is the admin path. Confirm spends the link, calls Rules.Change, moves the login throttle to the new address and ends the principal's other sessions. One change per principal is pending; a new Start replaces it.
package emailchange
