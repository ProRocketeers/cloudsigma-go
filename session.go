// Package cloudsigma authenticates against a CloudSigma-compatible API that
// enforces 2FA (T-Mobile T-Cloud). HTTP Basic is rejected on such accounts, so
// the only way in is the browser flow: login, verify_otp, then ride the
// session cookie.
package cloudsigma

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
)

// TOTP returns the RFC 6238 code for a base32 secret at time t.
func TOTP(secret string, t time.Time) (string, error) {
	// Authenticator apps display the secret in space-separated groups.
	secret = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToUpper(r)
	}, secret)

	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := enc.DecodeString(strings.TrimRight(secret, "="))
	if err != nil {
		return "", fmt.Errorf("otp_secret is not valid base32: %w", err)
	}

	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(t.Unix())/30)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	sum := mac.Sum(nil)

	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1000000), nil
}

var (
	sessionMu    sync.Mutex
	sessionCache = map[[32]byte]*http.Client{}
)

// Login performs the login + verify_otp handshake and returns an http.Client
// whose requests carry the verified session. baseURL is host and path without
// a scheme, e.g. "prg1.t-cloud.eu/api/2.0/".
//
// Sessions are cached per credential set. The provider is muxed, so both
// servers configure independently, and the API rejects a TOTP code that has
// already been spent - the second login would fail every time.
func Login(ctx context.Context, baseURL, username, password, otpSecret, impersonate, userAgent string) (*http.Client, error) {
	key := sha256.Sum256([]byte(strings.Join([]string{baseURL, username, password, otpSecret, impersonate}, "\x00")))

	sessionMu.Lock()
	defer sessionMu.Unlock()
	if cached, ok := sessionCache[key]; ok {
		return cached, nil
	}

	root := "https://" + strings.TrimSuffix(baseURL, "/") + "/"
	u, err := url.Parse(root)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL %q: %w", root, err)
	}
	origin := u.Scheme + "://" + u.Host

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Jar: jar, Timeout: 60 * time.Second}

	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	if _, err := do(ctx, client, root+"accounts/action/?do=login", origin, userAgent, body, nil); err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	verify := func() error {
		otp, err := TOTP(otpSecret, time.Now())
		if err != nil {
			return err
		}
		headers := map[string]string{"OTP": otp, "X-CSRFToken": csrf(jar, u)}
		_, err = do(ctx, client, root+"accounts/action/?do=verify_otp", origin, userAgent, []byte("{}"), headers)
		return err
	}

	err = verify()
	var failed *statusError
	if errors.As(err, &failed) && failed.code == http.StatusUnauthorized {
		// Terraform runs a fresh provider process for the apply walk, so a
		// plan and an apply seconds apart present the same code twice and the
		// API rejects the second as a replay. The next window is a new code.
		//
		// ponytail: costs up to 30s per collision. If that grates, cache the
		// session cookie on disk instead of re-authenticating per process.
		if waitErr := waitForNextWindow(ctx); waitErr != nil {
			return nil, waitErr
		}
		err = verify()
	}
	if err != nil {
		return nil, fmt.Errorf("OTP verification failed: %w", err)
	}

	client.Transport = sessionTransport{jar: jar, origin: origin}

	// Impersonation is a GET that mutates the session: subsequent requests act
	// as the target user. Must run through sessionTransport so it carries CSRF.
	if impersonate != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, root+"impersonate/"+impersonate+"/", nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("impersonation failed: %w", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, fmt.Errorf("impersonation failed: %s", resp.Status)
		}
	}

	sessionCache[key] = client

	return client, nil
}

// waitForNextWindow blocks until the current TOTP code has expired.
func waitForNextWindow(ctx context.Context) error {
	next := time.Unix((time.Now().Unix()/30+1)*30+1, 0)

	timer := time.NewTimer(time.Until(next))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%d: %s", e.code, e.body)
}

func do(ctx context.Context, c *http.Client, url, origin, userAgent string, body []byte, headers map[string]string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Referer", origin)
	request.Header.Set("User-Agent", userAgent)
	for k, v := range headers {
		request.Header.Set(k, v)
	}

	response, err := c.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, &statusError{code: response.StatusCode, body: strings.TrimSpace(string(payload))}
	}
	return payload, nil
}

func csrf(jar http.CookieJar, u *url.URL) string {
	for _, cookie := range jar.Cookies(u) {
		if cookie.Name == "csrftoken" {
			return cookie.Value
		}
	}
	return ""
}

// sessionTransport swaps the SDK's HTTP Basic credentials for the session
// cookie and adds the CSRF header Django requires on unsafe methods.
type sessionTransport struct {
	jar    http.CookieJar
	origin string
}

func (t sessionTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	request.Header.Del("Authorization")
	request.Header.Set("Referer", t.origin)
	if token := csrf(t.jar, request.URL); token != "" {
		request.Header.Set("X-CSRFToken", token)
	}
	return http.DefaultTransport.RoundTrip(request)
}
