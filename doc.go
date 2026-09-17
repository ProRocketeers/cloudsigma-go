// Package cloudsigma provides the T-Cloud / T-Mobile CloudSigma 2.0
// authentication flow and base-URL helper used by the ProRocketeers
// terraform-provider-cloudsigma fork.
//
// Accounts that enforce 2FA reject HTTP Basic, so Login performs the browser
// handshake (login, verify_otp) and returns an *http.Client that rides the
// resulting session cookie. TOTP generates the RFC 6238 code for the
// verify_otp step, and Endpoint derives the API host and path from a base URL
// or CloudSigma location.
//
// The module is SDK-free and depends only on the Go standard library.
package cloudsigma
