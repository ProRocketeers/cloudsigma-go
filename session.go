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

// loginResponseBytes caps handshake bodies. It stays much smaller than
// maxResponseBytes because the handshake only returns tiny JSON objects, but
// overflow is detected rather than silently truncated.
const loginResponseBytes = 1 << 16

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
// whose requests carry the verified session and transparently re-authenticate
// if the session expires. baseURL is host and path without a scheme, e.g.
// "prg1.t-cloud.eu/api/2.0/".
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

	auth, err := newAuthenticator(baseURL, username, password, otpSecret, impersonate, userAgent, 60*time.Second)
	if err != nil {
		return nil, err
	}
	refresher := newRefresher(auth)
	if err := refresher.refresh(ctx, refresher.currentGeneration()); err != nil {
		return nil, err
	}

	client := &http.Client{Jar: auth.jar, Timeout: auth.timeout, Transport: refresher.transport()}
	sessionCache[key] = client

	return client, nil
}

// authenticator owns one credential set, its cookie jar and the handshake that
// turns a username/password/TOTP triple into a session. It is deliberately
// transport-free: the handshake runs on a bare http.Client so a 401 during
// login can never re-enter the refreshing transport and recurse.
type authenticator struct {
	root     string
	origin   string
	apiURL   *url.URL
	jar      http.CookieJar
	timeout  time.Duration
	username string
	password string
	otp      string

	impersonate string
	userAgent   string

	sleep func(context.Context, time.Duration) error
	now   func() time.Time
}

func newAuthenticator(baseURL, username, password, otpSecret, impersonate, userAgent string, timeout time.Duration) (*authenticator, error) {
	root := baseURL
	if !strings.Contains(root, "://") {
		root = "https://" + strings.TrimSuffix(root, "/") + "/"
	}
	root = strings.TrimSuffix(root, "/") + "/"

	u, err := url.Parse(root)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL %q: %w", root, err)
	}
	origin := u.Scheme + "://" + u.Host

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	return &authenticator{
		root:        root,
		origin:      origin,
		apiURL:      u,
		jar:         jar,
		timeout:     timeout,
		username:    username,
		password:    password,
		otp:         otpSecret,
		impersonate: impersonate,
		userAgent:   userAgent,
		sleep:       realSleep,
		now:         time.Now,
	}, nil
}

func (a *authenticator) handshake(ctx context.Context) error {
	client := &http.Client{Jar: a.jar, Timeout: a.timeout}

	body, _ := json.Marshal(map[string]string{"username": a.username, "password": a.password})
	if _, err := a.doJSON(ctx, client, http.MethodPost, a.root+"accounts/action/?do=login", body, nil); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	verify := func() error {
		otp, err := TOTP(a.otp, a.now())
		if err != nil {
			return err
		}
		headers := map[string]string{"OTP": otp, "X-CSRFToken": csrf(a.jar, a.apiURL)}
		_, err = a.doJSON(ctx, client, http.MethodPost, a.root+"accounts/action/?do=verify_otp", []byte("{}"), headers)
		return err
	}

	err := verify()
	var failed *APIError
	if errors.As(err, &failed) && failed.StatusCode == http.StatusUnauthorized {
		// Terraform runs a fresh provider process for the apply walk, so a
		// plan and an apply seconds apart present the same code twice and the
		// API rejects the second as a replay. The next window is a new code.
		//
		// ponytail: costs up to 30s per collision. If that grates, cache the
		// session cookie on disk instead of re-authenticating per process.
		if waitErr := a.waitForNextWindow(ctx); waitErr != nil {
			return waitErr
		}
		err = verify()
	}
	if err != nil {
		return fmt.Errorf("OTP verification failed: %w", err)
	}

	if a.impersonate != "" {
		// Impersonation is a GET that mutates the session: subsequent requests
		// act as the target user. It is unsafe, so it carries CSRF.
		headers := map[string]string{"X-CSRFToken": csrf(a.jar, a.apiURL)}
		req, err := a.newRequest(ctx, http.MethodGet, a.root+"impersonate/"+a.impersonate+"/", nil, headers)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("impersonation failed: %w", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return fmt.Errorf("impersonation failed: %s", resp.Status)
		}
	}

	return nil
}

// waitForNextWindow blocks until the current TOTP code has expired.
func (a *authenticator) waitForNextWindow(ctx context.Context) error {
	next := time.Unix((a.now().Unix()/30+1)*30+1, 0)
	return a.sleep(ctx, time.Until(next))
}

func (a *authenticator) newRequest(ctx context.Context, method, url string, body []byte, headers map[string]string) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Referer", a.origin)
	request.Header.Set("User-Agent", a.userAgent)
	for k, v := range headers {
		request.Header.Set(k, v)
	}
	return request, nil
}

func (a *authenticator) doJSON(ctx context.Context, client *http.Client, method, url string, body []byte, headers map[string]string) ([]byte, error) {
	request, err := a.newRequest(ctx, method, url, body, headers)
	if err != nil {
		return nil, err
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	payload, err := readCapped(response.Body, loginResponseBytes)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, &APIError{
			StatusCode: response.StatusCode,
			Body:       strings.TrimSpace(string(payload)),
			Method:     method,
			URL:        url,
		}
	}
	return payload, nil
}

// refresher turns "the session is gone" into at most one in-flight login. The
// generation counter lets a request whose 401 raced with a completed refresh
// skip a redundant second login and retry against the new session instead.
type refresher struct {
	auth        *authenticator
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
	cooldown    time.Duration

	mu            sync.Mutex
	generation    uint64
	inFlight      chan struct{}
	lastErr       error
	lastFailureAt time.Time
}

func newRefresher(auth *authenticator) *refresher {
	return &refresher{
		auth:        auth,
		maxAttempts: 4,
		baseDelay:   time.Second,
		maxDelay:    10 * time.Second,
		cooldown:    30 * time.Second,
	}
}

func (r *refresher) currentGeneration() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.generation
}

// refresh re-authenticates once. seen is the generation the caller observed
// before sending its request; when it no longer matches, a concurrent refresh
// already fixed the session and the caller should just retry. Callers sharing
// the same generation block on a single handshake.
//
// A cycle that failed is remembered for cooldown: further refreshes at the same
// generation fail fast with the same error instead of starting another full
// handshake cycle. A newer generation always wins over the cooldown.
func (r *refresher) refresh(ctx context.Context, seen uint64) error {
	r.mu.Lock()
	if r.generation != seen {
		r.mu.Unlock()
		return nil
	}
	if r.inFlight != nil {
		done := r.inFlight
		r.mu.Unlock()
		select {
		case <-done:
			r.mu.Lock()
			err := r.lastErr
			r.mu.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if r.lastErr != nil && !r.lastFailureAt.IsZero() &&
		r.auth.now().Sub(r.lastFailureAt) < r.cooldown {
		err := r.lastErr
		r.mu.Unlock()
		return err
	}
	done := make(chan struct{})
	r.inFlight = done
	r.mu.Unlock()

	err := r.login(ctx)

	r.mu.Lock()
	r.lastErr = err
	if err == nil {
		r.generation++
		r.lastFailureAt = time.Time{}
	} else {
		r.lastFailureAt = r.auth.now()
	}
	r.inFlight = nil
	close(done)
	r.mu.Unlock()

	return err
}

// login retries only a rate-limited handshake, with bounded exponential
// backoff, and gives up after maxAttempts so a rejected credential fails fast
// instead of looping forever.
func (r *refresher) login(ctx context.Context) error {
	var err error
	for attempt := 0; attempt < r.maxAttempts; attempt++ {
		err = r.auth.handshake(ctx)
		if err == nil {
			return nil
		}
		if !isRateLimited(err) || attempt == r.maxAttempts-1 {
			return err
		}
		if sleepErr := r.auth.sleep(ctx, r.backoff(attempt)); sleepErr != nil {
			return sleepErr
		}
	}
	return err
}

func (r *refresher) backoff(attempt int) time.Duration {
	delay := r.baseDelay << attempt
	if delay <= 0 || delay > r.maxDelay {
		delay = r.maxDelay
	}
	return delay
}

func (r *refresher) transport() http.RoundTripper {
	return &refreshTransport{
		base:       sessionTransport{jar: r.auth.jar, origin: r.auth.origin},
		jar:        r.auth.jar,
		refresh:    r.refresh,
		generation: r.currentGeneration,
	}
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

// refreshTransport watches for session loss, re-logs-in through the shared
// single-flight refresher, and replays the buffered body exactly once. It never
// touches non-session failures, so a 5xx passes through for the caller (CSI)
// to retry.
type refreshTransport struct {
	base       http.RoundTripper
	jar        http.CookieJar
	refresh    func(context.Context, uint64) error
	generation func() uint64
}

func (t *refreshTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := bufferBody(request)
	if err != nil {
		return nil, err
	}

	generation := t.generation()
	response, err := t.attempt(request, body)
	if err != nil || !isSessionLoss(response) {
		return response, err
	}

	closeBody(response)
	if err := t.refresh(request.Context(), generation); err != nil {
		return nil, err
	}

	retried, err := t.attempt(request, body)
	if err != nil {
		return nil, err
	}
	if isSessionLoss(retried) {
		// Session loss survived the single retry. Return a typed error rather
		// than the response: for a login redirect the http.Client would
		// otherwise follow the Location and fetch the login page.
		return nil, sessionLossError(request, retried)
	}
	return retried, nil
}

func (t *refreshTransport) attempt(request *http.Request, body []byte) (*http.Response, error) {
	clone := request.Clone(request.Context())
	if body != nil {
		clone.Body = io.NopCloser(bytes.NewReader(body))
		clone.ContentLength = int64(len(body))
	}
	// The client's jar added cookies before RoundTrip ran; on a retry those are
	// stale, so rebuild them from the (possibly just refreshed) jar.
	if t.jar != nil {
		clone.Header.Del("Cookie")
		for _, cookie := range t.jar.Cookies(clone.URL) {
			clone.AddCookie(cookie)
		}
	}
	return t.base.RoundTrip(clone)
}

func bufferBody(request *http.Request) ([]byte, error) {
	if request.Body == nil || request.Body == http.NoBody {
		return nil, nil
	}
	payload, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	_ = request.Body.Close()
	request.Body = io.NopCloser(bytes.NewReader(payload))
	return payload, nil
}

func closeBody(response *http.Response) {
	_ = drainBody(response)
}

// drainBody consumes and closes a response body and returns what it read.
func drainBody(response *http.Response) []byte {
	if response == nil || response.Body == nil {
		return nil
	}
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	_ = response.Body.Close()
	return payload
}

// sessionLossError turns a persistent session-loss response into an APIError
// carrying the real status, body, method and URL.
func sessionLossError(request *http.Request, response *http.Response) error {
	payload := drainBody(response)
	return &APIError{
		StatusCode: response.StatusCode,
		Body:       strings.TrimSpace(string(payload)),
		Method:     request.Method,
		URL:        request.URL.String(),
	}
}

// isSessionLoss reports whether a response means the session is no longer
// valid: an explicit 401, or the login-page redirect the API uses for an
// unauthenticated session. It is checked in RoundTrip, before the client's
// redirect policy can follow that redirect.
func isSessionLoss(response *http.Response) bool {
	if response == nil {
		return false
	}
	if response.StatusCode == http.StatusUnauthorized {
		return true
	}
	if response.StatusCode < 300 || response.StatusCode > 399 {
		return false
	}
	return isLoginRedirect(response.Header.Get("Location"))
}

// isLoginRedirect reports whether a Location header targets a login path. It
// matches whole path segments, so a legitimate "/api/2.0/login_history/" is not
// mistaken for session loss. Relative and absolute locations both parse.
func isLoginRedirect(location string) bool {
	if location == "" {
		return false
	}
	u, err := url.Parse(location)
	if err != nil {
		return false
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if strings.EqualFold(segment, "login") {
			return true
		}
	}
	return false
}

func isRateLimited(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.StatusCode == http.StatusTooManyRequests {
		return true
	}
	body := strings.ToLower(apiErr.Body)
	return strings.Contains(body, "too many") ||
		strings.Contains(body, "wait a minute") ||
		strings.Contains(body, "rate limit")
}

func csrf(jar http.CookieJar, u *url.URL) string {
	for _, cookie := range jar.Cookies(u) {
		if cookie.Name == "csrftoken" {
			return cookie.Value
		}
	}
	return ""
}

func realSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
