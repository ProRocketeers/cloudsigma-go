# cloudsigma-go

Standalone, dependency-free Go package for the authentication leg of the
T-Mobile **T-Cloud** CloudSigma 2.0 API.

It implements the browser flow required by CloudSigma accounts that enforce
2FA (where HTTP Basic is rejected):

- `Login(ctx, baseURL, username, password, otpSecret, impersonate, userAgent)` —
  performs `login` + `verify_otp` and returns an `*http.Client` that carries the
  verified session cookie (and CSRF header).
- `New(Config)` — performs the same handshake and returns a `*Client` with typed
  JSON helpers (`Get`/`Post`/`Put`/`Delete`). Unlike `Login` it does **not**
  cache, so a long-running controller (CSI driver) gets its own session.
- `TOTP(secret, t)` — RFC 6238 TOTP codes for the `verify_otp` step.
- `Endpoint(baseURL, location)` — resolves the API host and path (no scheme),
  falling back to the `<location>.cloudsigma.com` endpoint.

The module uses only the Go standard library — there are no `require` entries.

## Install

```sh
go get github.com/ProRocketeers/cloudsigma-go
```

## Session refresh

Both `Login` and `New` attach a `RoundTripper` that detects session loss — a
`401`, or the login-page redirect the API returns for an unauthenticated
session — **before** the redirect is followed. On session loss it re-runs the
handshake and replays the original request exactly once:

- The handshake is **single-flight**: N goroutines that hit a `401` at the same
  time trigger exactly one login; the rest wait and then retry.
- Request bodies are buffered, so a retried write sends byte-identical content.
- Only session loss is retried. A `5xx` is returned untouched so the caller can
  decide (the CSI driver maps it to `UNAVAILABLE` and lets the CO retry).
- Rate-limited re-login ("too many failed authentication attempts") backs off
  with bounded exponential delays and gives up after a capped number of
  attempts, so bad credentials fail fast.
- The handshake itself runs on a bare client that shares the cookie jar, so a
  `401` during login can never re-enter the refreshing transport.

`Login` keeps its package-level cache keyed by credentials, so the muxed
Terraform provider still performs a single handshake across both servers; the
cache now also carries the refreshing transport, removing the previous "expired
session 401s until restart" behaviour.

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

	client, err := csgo.New(csgo.Config{
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
