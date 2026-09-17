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
// Both Login and New attach a transport that detects session loss (a 401, or the
// login-page redirect the API returns for an unauthenticated session),
// re-authenticates once through a single-flight refresher, and replays the
// original request. Only session loss is retried; other failures are returned
// untouched. A refresh cycle that fails is not started again until a cooldown
// elapses, so repeated 401s cannot drive repeated handshake cycles.
//
// Errors are typed: APIError carries StatusCode, Body, Method and URL for
// callers that branch on the HTTP status, and a response body larger than the
// read cap yields ErrResponseTooLarge instead of a truncated payload.
//
// The package uses only the Go standard library.
package cloudsigma
