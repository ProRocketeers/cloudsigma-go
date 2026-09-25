# cloudsigma-go

Standalone, dependency-free Go package for the authentication leg of the
T-Mobile **T-Cloud** CloudSigma 2.0 API.

It implements the browser flow required by CloudSigma accounts that enforce
2FA (where HTTP Basic is rejected):

- `Login(ctx, baseURL, username, password, otpSecret, impersonate, userAgent)` —
  performs `login` + `verify_otp` and returns an `*http.Client` that carries the
  verified session cookie (and CSRF header).
- `New(ctx, Config)` — performs the same handshake under `ctx` and returns a
  `*Client` with typed JSON helpers (`Get`/`Post`/`Put`/`Delete`). Unlike
  `Login` it does **not** cache, so a long-running controller (CSI driver) gets
  its own session.
- `TOTP(secret, t)` — RFC 6238 TOTP codes for the `verify_otp` step.
- `Endpoint(baseURL, location)` — resolves the API host and path (no scheme),
  falling back to the `<location>.cloudsigma.com` endpoint.

The module uses only the Go standard library — there are no `require` entries.

## Install

```sh
go get github.com/ProRocketeers/cloudsigma-go
```

## Session refresh

Both `Login` and `New` attach a `RoundTripper` that detects a `401`, a login
redirect, and (when impersonating) the measured `403` response
`impersonation session has been closed`. On session loss it authenticates into
a fresh cookie jar, publishes the complete session only after OTP verification
and impersonation succeed, then replays the request at most once:

- The handshake is **single-flight**: N goroutines that hit a `401` at the same
  time trigger exactly one login; the rest wait and then retry.
- Request bodies are buffered, so a retried write sends byte-identical content.
- Only session loss is retried. A `5xx` is returned untouched so the caller can
  decide (the CSI driver maps it to `UNAVAILABLE` and lets the CO retry).
- Rate limits honor valid `Retry-After` seconds or HTTP dates. Without one,
  retries use bounded exponential backoff with jitter. A cycle makes at most
  four handshakes; credentials rejected at login are not retried. An OTP
  rejection can wait for one new TOTP window, because rejection alone does not
  establish whether the code was replayed or the clocks differ.
- A refresh cycle that ends in error is remembered for a 30s cooldown: further
  session-loss responses at the same generation fail fast with the remembered
  error instead of starting another full handshake cycle. A refresh that sees a
  newer generation (another goroutine already succeeded) still returns
  immediately.
- If session loss persists after replay, the SDK records an ineffective
  recovery cooldown. It returns an `*AuthError` with stage `session_recovery`
  and kind `persistent_session_loss`, wrapping the real `*APIError` for
  `errors.As` callers. Ordinary permission 403s, 5xx responses, transport
  timeouts, and ambiguous writes are not replayed by authentication code.
- Response bodies are capped at 8 MiB. An oversized body fails with
  `ErrResponseTooLarge` (test with `errors.Is`) rather than being silently
  truncated and mis-reported as a JSON error.
- The handshake runs on a bare client, so a login failure cannot recurse
  through the refreshing transport. `Client.Close` cancels an in-progress
  recovery; individual recovery attempts also have a deadline.

`Login` keeps its package-level cache keyed by credentials, so the muxed
Terraform provider still performs a single handshake across both servers; the
cache now also carries the refreshing transport, removing the previous "expired
session 401s until restart" behaviour.

`AuthError` reports the failing stage (`login`, `otp_verification`,
`impersonation`, or `session_recovery`), kind, wrapped cause, and server retry
timing. Its message omits credentials, cookies, OTP values, and server bodies;
`errors.As(err, &apiErr)` still exposes the underlying `APIError` when needed.
Set `Config.OnAuthEvent` before calling `New` to observe bounded handshake,
recovery, cooldown, and rate-limit events, including the initial handshake.
Callbacks can run concurrently and should return quickly. Their stage,
reason, and outcome fields are safe for low-cardinality metrics.

## Optional local session cache

Set `Config.SessionCacheDir` (or `LoginOptions.SessionCacheDir` with
`LoginWithOptions`) to an absolute private directory to reuse a session across
short-lived local processes. Caching is disabled by default. The directory
must be owned by the current user with mode `0700`; entries and lock files use
`0600`. Unsafe permissions, symlinks, and corrupt entries return actionable
errors. Entries contain bearer cookies, cookie scope and expiry, an identity
binding, generation, and retry timing. They never contain the password or TOTP
seed. Session cookies without server expiry get a local 30-minute upper bound;
revoked cookies still use normal recovery.

An account-level OS lock serializes authentication across impersonation
targets, while entries are target-specific. Processes must share the same
local directory for this to coordinate them. It cannot prevent OTP collisions
with browsers, other hosts, or independently configured controllers. Controller
pods should leave caching disabled unless their storage and lifecycle have been
reviewed for that deployment.

## Usage

### Long-running controller (`New`)

```go
package main

import (
	"context"
	"errors"
	"net/http"

	csgo "github.com/ProRocketeers/cloudsigma-go"
)

type drive struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

func main() {
	ctx := context.Background()

	client, err := csgo.New(ctx, csgo.Config{
		BaseURL:   "prg1.t-cloud.eu/api/2.0/", // host + path, no scheme
		Username:  "user@example.com",
		Password:  "secret-password",
		OTPSecret: "GEZD GNBV GY3T QOJQ",
		UserAgent: "my-csi-driver/1.0",
		// Timeout defaults to 60s when zero.
	})
	if err != nil {
		panic(err)
	}

	var drives []drive
	if err := client.Get(ctx, "drives/", &drives); err != nil {
		var apiErr *csgo.APIError
		if errors.As(err, &apiErr) {
			switch apiErr.StatusCode {
			case http.StatusNotFound:
				// -> NOT_FOUND
			case http.StatusConflict:
				// -> ALREADY_EXISTS
			case http.StatusUnauthorized:
				// -> UNAUTHENTICATED
			}
		}
		panic(err)
	}

	// For the SDK or bespoke requests on the same session:
	_ = client.HTTPClient()
}
```

`APIError` carries `StatusCode`, `Body`, `Method` and `URL`, and renders as
`"%d: %s"` so existing string-matching continues to work. Branch on
`StatusCode` (and inspect `Body` when a status is overloaded, e.g. a `403`
hotplug-limit rejection vs. a permission denial).

### Terraform provider (`Login`)

```go
package main

import (
	"context"

	csgo "github.com/ProRocketeers/cloudsigma-go"
)

func main() {
	ctx := context.Background()

	client, err := csgo.Login(
		ctx,
		"prg1.t-cloud.eu/api/2.0/", // baseURL: host + path, no scheme
		"user@example.com",         // username
		"secret-password",          // password
		"GEZD GNBV GY3T QOJQ",      // otpSecret: base32 TOTP secret
		"",                         // impersonate: UUID, or "" for none
		"my-app/1.0",               // userAgent
	)
	if err != nil {
		panic(err)
	}

	// client carries the verified session cookie and CSRF token, and refreshes
	// the session on expiry. The second call with the same credentials returns
	// this same cached client.
	_ = client
}
```

`Endpoint` can be used to compute the base URL for `Login` from a location:

```go
base := csgo.Endpoint("", "zrh") // "zrh.cloudsigma.com/api/2.0/"
```

## License

Mozilla Public License 2.0. The code is derived from
[`terraform-provider-cloudsigma`](https://github.com/ProRocketeers/terraform-provider-cloudsigma);
see [LICENSE](LICENSE).
