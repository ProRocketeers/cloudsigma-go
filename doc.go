// Package cloudsigma is a dependency-free client for the T-Mobile T-Cloud
// CloudSigma 2.0 API.
//
// Accounts that enforce 2FA reject HTTP Basic, so Login performs the browser
// handshake (login, verify_otp) and returns an *http.Client riding the
// resulting session cookie. Login caches the session per credential set, which
// suits short-lived callers such as the muxed Terraform provider. TOTP
// generates the RFC 6238 code for verify_otp, and Endpoint derives the API host
// and path from a base URL or CloudSigma location.
//
// New(ctx, cfg) performs the same handshake for a single long-running caller and
// returns a *Client with Get/Post/Put/Delete helpers. It does not cache, so each
// caller owns its session.
//
// Both Login and New attach a transport that detects a 401, a login redirect,
// and the measured impersonation-closed 403 when impersonation is configured.
// Recovery authenticates into a fresh cookie jar, publishes it after the full
// handshake, and replays once. A single-flight refresher and failure cooldown
// bound login attempts. Other failures are returned without authentication
// replay.
//
// Errors are typed: AuthError reports stage, kind, wrapped cause, and retry
// timing without printing server bodies; APIError remains available through
// errors.As. Config.OnAuthEvent reports bounded authentication events. Optional
// Config.SessionCacheDir enables private local session reuse for short-lived
// processes; it is disabled by default. A response body larger than the read
// cap yields ErrResponseTooLarge instead of a truncated payload.
//
// The package uses only the Go standard library.
package cloudsigma
