# cloudsigma-go

Standalone, dependency-free Go package for the authentication leg of the
T-Mobile **T-Cloud** CloudSigma 2.0 API.

It implements the browser flow required by CloudSigma accounts that enforce
2FA (where HTTP Basic is rejected):

- `Login(ctx, baseURL, username, password, otpSecret, impersonate, userAgent)` —
  performs `login` + `verify_otp` and returns an `*http.Client` that carries the
  verified session cookie (and CSRF header).
- `TOTP(secret, t)` — RFC 6238 TOTP codes for the `verify_otp` step.
- `Endpoint(baseURL, location)` — resolves the API host and path (no scheme),
  falling back to the `<location>.cloudsigma.com` endpoint.

The module uses only the Go standard library — there are no `require` entries.

## Install

```sh
go get github.com/ProRocketeers/cloudsigma-go
```

## Usage

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

	// client now carries the verified session cookie and CSRF token; issue
	// API requests with it directly.
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
