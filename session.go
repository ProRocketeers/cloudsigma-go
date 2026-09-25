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
	"math/rand"
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
	return LoginWithOptions(ctx, baseURL, username, password, otpSecret, impersonate, userAgent, LoginOptions{})
}

// LoginWithOptions performs the legacy login flow with optional SDK
// configuration. A non-nil OnAuthEvent handler receives events from this
// client, including its initial handshake. Configured clients are intentionally
// not placed in Login's package cache: the cache predates per-caller event
// handlers and must never silently suppress a requested callback.
func LoginWithOptions(ctx context.Context, baseURL, username, password, otpSecret, impersonate, userAgent string, options LoginOptions) (*http.Client, error) {
	key := sha256.Sum256([]byte(strings.Join([]string{baseURL, username, password, otpSecret, impersonate}, "\x00")))

	cacheable := options.OnAuthEvent == nil && options.Timeout <= 0 && options.SessionCacheDir == ""
	if cacheable {
		sessionMu.Lock()
		defer sessionMu.Unlock()
		cached, ok := sessionCache[key]
		if ok {
			return cached, nil
		}
	}

	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	auth, err := newAuthenticatorWithEvents(baseURL, username, password, otpSecret, impersonate, userAgent, timeout, options.OnAuthEvent)
	if err != nil {
		return nil, err
	}
	refresher := newRefresher(auth)
	if err := refresher.configureStore(options.SessionCacheDir); err != nil {
		return nil, err
	}
	if err := refresher.initialize(ctx); err != nil {
		return nil, err
	}

	_, initialJar := refresher.snapshot()
	client := &http.Client{Jar: initialJar, Timeout: auth.timeout, Transport: refresher.transport()}
	if cacheable {
		sessionCache[key] = client
	}

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

	sleep   func(context.Context, time.Duration) error
	now     func() time.Time
	onEvent AuthEventHandler
}

func newAuthenticator(baseURL, username, password, otpSecret, impersonate, userAgent string, timeout time.Duration) (*authenticator, error) {
	return newAuthenticatorWithEvents(baseURL, username, password, otpSecret, impersonate, userAgent, timeout, nil)
}

func newAuthenticatorWithEvents(baseURL, username, password, otpSecret, impersonate, userAgent string, timeout time.Duration, onEvent AuthEventHandler) (*authenticator, error) {
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
		onEvent:     onEvent,
	}, nil
}

func (a *authenticator) handshake(ctx context.Context) error {
	a.emit(AuthEvent{
		Type:    AuthEventHandshakeStart,
		Stage:   AuthStageLogin,
		Reason:  authEventReasonInitial,
		Outcome: authEventOutcomeStarted,
	})

	client := &http.Client{Jar: a.jar, Timeout: a.timeout}

	body, _ := json.Marshal(map[string]string{"username": a.username, "password": a.password})
	if _, err := a.doJSON(ctx, client, http.MethodPost, a.root+"accounts/action/?do=login", body, nil); err != nil {
		return a.finishHandshake(AuthStageLogin, err)
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
	if !isRateLimited(err) && errors.As(err, &failed) && failed.StatusCode == http.StatusUnauthorized {
		// Terraform runs a fresh provider process for the apply walk, so a
		// plan and an apply seconds apart present the same code twice and the
		// API rejects the second as a replay. The next window is a new code.
		//
		// ponytail: costs up to 30s per collision. If that grates, cache the
		// session cookie on disk instead of re-authenticating per process.
		if waitErr := a.waitForNextWindow(ctx); waitErr != nil {
			return a.finishHandshake(AuthStageOTPVerification, waitErr)
		}
		err = verify()
	}
	if err != nil {
		return a.finishHandshake(AuthStageOTPVerification, err)
	}

	if a.impersonate != "" {
		// Impersonation is a GET that mutates the session: subsequent requests
		// act as the target user. It is unsafe, so it carries CSRF.
		headers := map[string]string{"X-CSRFToken": csrf(a.jar, a.apiURL)}
		req, err := a.newRequest(ctx, http.MethodGet, a.root+"impersonate/"+a.impersonate+"/", nil, headers)
		if err != nil {
			return a.finishHandshake(AuthStageImpersonation, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return a.finishHandshake(AuthStageImpersonation, err)
		}
		payload, readErr := readCapped(resp.Body, loginResponseBytes)
		_ = resp.Body.Close()
		if readErr != nil {
			return a.finishHandshake(AuthStageImpersonation, readErr)
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return a.finishHandshake(AuthStageImpersonation, &authAPIError{
				APIError: &APIError{
					StatusCode: resp.StatusCode,
					Body:       strings.TrimSpace(string(payload)),
					Method:     http.MethodGet,
					URL:        req.URL.String(),
				},
				retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), a.now()),
			})
		}
		return a.finishHandshake(AuthStageImpersonation, nil)
	}

	return a.finishHandshake(AuthStageOTPVerification, nil)
}

func (a *authenticator) finishHandshake(stage AuthStage, err error) error {
	if err != nil {
		authErr := classifyAuthError(stage, err)
		a.emit(AuthEvent{
			Type:       AuthEventHandshakeResult,
			Stage:      authErr.Stage,
			Reason:     string(authErr.Kind),
			Outcome:    authEventOutcomeFailure,
			RetryAfter: authErr.RetryAfter,
		})
		return authErr
	}
	a.emit(AuthEvent{
		Type:    AuthEventHandshakeResult,
		Stage:   stage,
		Reason:  authEventReasonAuthentication,
		Outcome: authEventOutcomeSuccess,
	})
	return nil
}

func (a *authenticator) emit(event AuthEvent) {
	if a == nil || a.onEvent == nil {
		return
	}
	a.onEvent(event)
}

// waitForNextWindow blocks until the current TOTP code has expired.
func (a *authenticator) waitForNextWindow(ctx context.Context) error {
	next := time.Unix((a.now().Unix()/30+1)*30+1, 0)
	return a.sleep(ctx, next.Sub(a.now()))
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
		return nil, &authAPIError{
			APIError: &APIError{
				StatusCode: response.StatusCode,
				Body:       strings.TrimSpace(string(payload)),
				Method:     method,
				URL:        url,
			},
			retryAfter: parseRetryAfter(response.Header.Get("Retry-After"), a.now()),
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
	jitter      func(time.Duration) time.Duration

	mu            sync.Mutex
	generation    uint64
	jar           http.CookieJar
	inFlight      chan struct{}
	lastErr       error
	lastFailureAt time.Time
	notBefore     time.Time
	lifetime      context.Context
	cancel        context.CancelFunc
	store         *FileSessionStore
	storeKey      SessionKey
}

func newRefresher(auth *authenticator) *refresher {
	lifetime, cancel := context.WithCancel(context.Background())
	return &refresher{
		auth:        auth,
		maxAttempts: 4,
		baseDelay:   time.Second,
		maxDelay:    10 * time.Second,
		cooldown:    30 * time.Second,
		jitter:      func(d time.Duration) time.Duration { return d - time.Duration(rand.Int63n(int64(d/4)+1)) },
		lifetime:    lifetime,
		cancel:      cancel,
	}
}

func (r *refresher) configureStore(dir string) error {
	if dir == "" {
		return nil
	}
	store, err := NewFileSessionStore(dir)
	if err != nil {
		return err
	}
	r.store = store
	r.storeKey = SessionKey{
		Endpoint:              r.auth.root,
		Username:              r.auth.username,
		Impersonate:           r.auth.impersonate,
		CredentialFingerprint: CredentialFingerprint(r.auth.root, r.auth.username, r.auth.password, r.auth.otp),
	}
	return nil
}

func (r *refresher) restoreRecord(record SessionRecord) (http.CookieJar, error) {
	jar := NewTrackedCookieJar(nil)
	jar.now = r.auth.now
	if err := jar.Restore(record.Cookies); err != nil {
		return nil, err
	}
	return jar, nil
}

func (r *refresher) saveRecord(ctx context.Context, jar http.CookieJar, generation uint64) error {
	tracked, ok := jar.(*TrackedCookieJar)
	if !ok {
		return errors.New("cloudsigma: session cookie tracking unavailable")
	}
	cookies, err := tracked.PersistentCookies(r.auth.now())
	if err != nil {
		return err
	}
	r.mu.Lock()
	notBefore := r.notBefore
	r.mu.Unlock()
	return r.store.Save(ctx, r.storeKey, SessionRecord{
		Version:               currentSessionStoreVersion,
		Endpoint:              r.storeKey.Endpoint,
		Username:              r.storeKey.Username,
		CredentialFingerprint: r.storeKey.CredentialFingerprint,
		Impersonate:           r.storeKey.Impersonate,
		Cookies:               cookies,
		Generation:            generation,
		RetryNotBefore:        notBefore,
	})
}

func (r *refresher) saveCooldown(ctx context.Context, generation uint64) error {
	_ = ctx // The retry deadline must survive cancellation of the waiting call.
	r.mu.Lock()
	notBefore := r.notBefore
	r.mu.Unlock()
	if r.store == nil || !notBefore.After(r.auth.now()) {
		return nil
	}
	persistCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return r.store.Save(persistCtx, r.storeKey, SessionRecord{
		Version:               currentSessionStoreVersion,
		Endpoint:              r.storeKey.Endpoint,
		Username:              r.storeKey.Username,
		CredentialFingerprint: r.storeKey.CredentialFingerprint,
		Impersonate:           r.storeKey.Impersonate,
		Generation:            generation,
		RetryNotBefore:        notBefore,
	})
}

func (r *refresher) initialize(ctx context.Context) error {
	if r.store == nil {
		jar, err := r.login(ctx)
		if err != nil {
			return err
		}
		r.mu.Lock()
		r.jar = jar
		r.generation = 1
		r.mu.Unlock()
		return nil
	}
	lock, err := r.store.LockAccount(ctx, r.storeKey)
	if err != nil {
		return err
	}
	defer lock.Close()
	record, err := r.store.Load(ctx, r.storeKey)
	if err == nil && len(record.Cookies) > 0 {
		jar, restoreErr := r.restoreRecord(record)
		if restoreErr != nil {
			return restoreErr
		}
		r.mu.Lock()
		r.jar = jar
		r.generation = record.Generation
		r.notBefore = record.RetryNotBefore
		r.mu.Unlock()
		return nil
	}
	if err != nil && !errors.Is(err, ErrSessionCacheNotFound) && !errors.Is(err, ErrSessionExpired) && !errors.Is(err, ErrSessionCacheCredentialMismatch) {
		return err
	}
	if remaining := record.RetryNotBefore.Sub(r.auth.now()); remaining > 0 {
		return &AuthError{Stage: AuthStageLogin, Kind: AuthKindRateLimited, RetryAfter: remaining}
	}
	jar, err := r.login(ctx)
	if err != nil {
		if saveErr := r.saveCooldown(ctx, record.Generation); saveErr != nil {
			return saveErr
		}
		return err
	}
	generation := record.Generation + 1
	if generation == 0 {
		generation = 1
	}
	if err := r.saveRecord(ctx, jar, generation); err != nil {
		return err
	}
	r.mu.Lock()
	r.jar = jar
	r.generation = generation
	r.mu.Unlock()
	return nil
}

// close stops an in-progress recovery. Callers may close a Client when it is
// no longer used; each recovery is also independently bounded by a deadline.
func (r *refresher) close() {
	if r.cancel != nil {
		r.cancel()
	}
}

func (r *refresher) snapshot() (uint64, http.CookieJar) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.generation, r.jar
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
	if err := ctx.Err(); err != nil {
		return err
	}
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
	if remaining := r.notBefore.Sub(r.auth.now()); remaining > 0 {
		err := r.lastErr
		r.mu.Unlock()
		if err == nil {
			err = &AuthError{Stage: AuthStageSessionRecovery, Kind: AuthKindRateLimited, RetryAfter: remaining}
		}
		return err
	}
	if r.lastErr != nil && !r.lastFailureAt.IsZero() &&
		r.auth.now().Sub(r.lastFailureAt) < r.cooldown {
		err := r.lastErr
		remaining := r.cooldown - r.auth.now().Sub(r.lastFailureAt)
		r.mu.Unlock()
		r.auth.emit(AuthEvent{
			Type:       AuthEventCooldown,
			Stage:      AuthStageSessionRecovery,
			Reason:     authEventReasonCooldown,
			Outcome:    authEventOutcomeSkipped,
			RetryAfter: remaining,
		})
		return err
	}
	done := make(chan struct{})
	r.inFlight = done
	r.mu.Unlock()
	// The client owns recovery. A canceled request leaves other waiters' shared
	// handshake intact; the deadline and Close bound its lifetime.
	go func() {
		limit := 2*r.auth.timeout + 35*time.Second
		if limit < 35*time.Second {
			limit = 35 * time.Second
		}
		lifetime := r.lifetime
		if lifetime == nil {
			lifetime = context.Background()
		}
		recoveryCtx, cancel := context.WithTimeout(lifetime, limit)
		defer cancel()
		jar, nextGeneration, err := r.recover(recoveryCtx, seen)
		r.mu.Lock()
		r.lastErr = err
		if err == nil {
			r.jar = jar
			r.generation = nextGeneration
			r.lastFailureAt = time.Time{}
			r.notBefore = time.Time{}
		} else {
			r.lastFailureAt = r.auth.now()
		}
		r.inFlight = nil
		close(done)
		r.mu.Unlock()
	}()
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

func (r *refresher) recover(ctx context.Context, seen uint64) (http.CookieJar, uint64, error) {
	if r.store == nil {
		jar, err := r.login(ctx)
		return jar, seen + 1, err
	}
	lock, err := r.store.LockAccount(ctx, r.storeKey)
	if err != nil {
		return nil, 0, err
	}
	defer lock.Close()
	record, loadErr := r.store.Load(ctx, r.storeKey)
	if loadErr == nil && len(record.Cookies) > 0 && record.Generation > seen {
		jar, err := r.restoreRecord(record)
		return jar, record.Generation, err
	}
	if loadErr != nil && !errors.Is(loadErr, ErrSessionCacheNotFound) && !errors.Is(loadErr, ErrSessionExpired) && !errors.Is(loadErr, ErrSessionCacheCredentialMismatch) {
		return nil, 0, loadErr
	}
	if remaining := record.RetryNotBefore.Sub(r.auth.now()); remaining > 0 {
		return nil, 0, &AuthError{Stage: AuthStageSessionRecovery, Kind: AuthKindRateLimited, RetryAfter: remaining}
	}
	jar, err := r.login(ctx)
	if err != nil {
		if saveErr := r.saveCooldown(ctx, record.Generation); saveErr != nil {
			return nil, 0, saveErr
		}
		return nil, 0, err
	}
	next := seen + 1
	if record.Generation >= next {
		next = record.Generation + 1
	}
	if err := r.saveRecord(ctx, jar, next); err != nil {
		return nil, 0, err
	}
	return jar, next, nil
}

// login retries only a rate-limited handshake, with bounded exponential
// backoff, and gives up after maxAttempts so a rejected credential fails fast
// instead of looping forever.
func (r *refresher) login(ctx context.Context) (http.CookieJar, error) {
	var err error
	for attempt := 0; attempt < r.maxAttempts; attempt++ {
		candidate := *r.auth
		tracked := NewTrackedCookieJar(nil)
		tracked.now = r.auth.now
		candidate.jar = tracked
		err = candidate.handshake(ctx)
		if err == nil {
			r.mu.Lock()
			r.notBefore = time.Time{}
			r.mu.Unlock()
			return candidate.jar, nil
		}
		if isRateLimited(err) && attempt == r.maxAttempts-1 {
			delay := authRetryAfter(err)
			if delay <= 0 {
				delay = r.backoff(attempt)
			}
			r.mu.Lock()
			r.notBefore = r.auth.now().Add(delay)
			r.mu.Unlock()
		}
		if !isRateLimited(err) || attempt == r.maxAttempts-1 {
			return nil, err
		}
		r.auth.emit(AuthEvent{
			Type:       AuthEventRateLimited,
			Stage:      authErrorStage(err, AuthStageSessionRecovery),
			Reason:     authEventReasonRateLimit,
			Outcome:    authEventOutcomeRetrying,
			RetryAfter: authRetryAfter(err),
		})
		delay := authRetryAfter(err)
		if delay <= 0 {
			delay = r.backoff(attempt)
		}
		notBefore := r.auth.now().Add(delay)
		r.mu.Lock()
		r.notBefore = notBefore
		r.mu.Unlock()
		if sleepErr := r.auth.sleep(ctx, delay); sleepErr != nil {
			return nil, &AuthError{Stage: authErrorStage(err, AuthStageLogin), Kind: AuthKindRateLimited, Cause: errors.Join(err, sleepErr), RetryAfter: delay}
		}
		// A test clock (or an interrupted sleep implementation) may not have
		// reached the deadline. Never spend another login before it has.
		if remaining := notBefore.Sub(r.auth.now()); remaining > 0 {
			return nil, &AuthError{Stage: authErrorStage(err, AuthStageLogin), Kind: AuthKindRateLimited, Cause: err, RetryAfter: remaining}
		}
	}
	return nil, err
}

func (r *refresher) backoff(attempt int) time.Duration {
	delay := r.baseDelay << attempt
	if delay <= 0 || delay > r.maxDelay {
		delay = r.maxDelay
	}
	if r.jitter != nil {
		delay = r.jitter(delay)
	}
	return delay
}

func (r *refresher) transport() http.RoundTripper {
	return &refreshTransport{
		base:            http.DefaultTransport,
		refresh:         r.refresh,
		snapshot:        r.snapshot,
		origin:          r.auth.origin,
		impersonate:     r.auth.impersonate != "",
		noteIneffective: r.noteIneffective,
		onEvent:         r.auth.onEvent,
	}
}

func (r *refresher) noteIneffective(err error) {
	r.mu.Lock()
	r.lastErr = err
	r.lastFailureAt = r.auth.now()
	r.mu.Unlock()
}

// refreshTransport watches for session loss, re-logs-in through the shared
// single-flight refresher, and replays the buffered body exactly once. It never
// touches non-session failures, so a 5xx passes through for the caller (CSI)
// to retry.
type refreshTransport struct {
	base            http.RoundTripper
	refresh         func(context.Context, uint64) error
	snapshot        func() (uint64, http.CookieJar)
	origin          string
	impersonate     bool
	noteIneffective func(error)
	onEvent         AuthEventHandler
}

func (t *refreshTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := bufferBody(request)
	if err != nil {
		return nil, err
	}

	generation, jar := t.snapshot()
	response, err := t.attempt(request, body, jar)
	if err != nil || !isSessionLossFor(response, t.impersonate) {
		return response, err
	}

	reason := sessionLossReason(response)
	closeBody(response)
	t.emit(AuthEvent{
		Type:    AuthEventRecovery,
		Stage:   AuthStageSessionRecovery,
		Reason:  reason,
		Outcome: authEventOutcomeStarted,
	})
	if err := t.refresh(request.Context(), generation); err != nil {
		t.emit(AuthEvent{
			Type:    AuthEventRecovery,
			Stage:   AuthStageSessionRecovery,
			Reason:  reason,
			Outcome: authEventOutcomeFailure,
		})
		return nil, err
	}
	t.emit(AuthEvent{
		Type:    AuthEventRecovery,
		Stage:   AuthStageSessionRecovery,
		Reason:  reason,
		Outcome: authEventOutcomeSuccess,
	})

	_, jar = t.snapshot()
	retried, err := t.attempt(request, body, jar)
	if err != nil {
		return nil, err
	}
	if isSessionLossFor(retried, t.impersonate) {
		// Session loss survived the single retry. Return a typed error rather
		// than the response: for a login redirect the http.Client would
		// otherwise follow the Location and fetch the login page.
		authErr := classifyAuthError(AuthStageSessionRecovery, sessionLossError(request, retried))
		if t.noteIneffective != nil {
			t.noteIneffective(authErr)
		}
		return nil, authErr
	}
	return retried, nil
}

func (t *refreshTransport) emit(event AuthEvent) {
	if t == nil || t.onEvent == nil {
		return
	}
	t.onEvent(event)
}

func (t *refreshTransport) attempt(request *http.Request, body []byte, jar http.CookieJar) (*http.Response, error) {
	clone := request.Clone(request.Context())
	if body != nil {
		clone.Body = io.NopCloser(bytes.NewReader(body))
		clone.ContentLength = int64(len(body))
	}
	clone.Header.Del("Authorization")
	clone.Header.Set("Referer", t.origin)
	// http.Client's exposed initial jar may have added old cookies. Always use
	// the jar captured with this session generation.
	clone.Header.Del("Cookie")
	if jar != nil {
		for _, cookie := range jar.Cookies(clone.URL) {
			clone.AddCookie(cookie)
		}
		if token := csrf(jar, clone.URL); token != "" {
			clone.Header.Set("X-CSRFToken", token)
		} else {
			clone.Header.Del("X-CSRFToken")
		}
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(clone)
	if err == nil && resp != nil && jar != nil {
		jar.SetCookies(clone.URL, resp.Cookies())
	}
	return resp, err
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

func authErrorStage(err error, fallback AuthStage) AuthStage {
	var authErr *AuthError
	if errors.As(err, &authErr) && authErr.Stage != "" {
		return authErr.Stage
	}
	return fallback
}

func sessionLossReason(response *http.Response) string {
	if response != nil && response.StatusCode >= 300 && response.StatusCode <= 399 {
		return authEventReasonLoginRedirect
	}
	return authEventReasonSessionLoss
}

// isSessionLoss reports whether a response means the session is no longer
// valid: an explicit 401, or the login-page redirect the API uses for an
// unauthenticated session. It is checked in RoundTrip, before the client's
// redirect policy can follow that redirect.
func isSessionLoss(response *http.Response) bool {
	return isSessionLossFor(response, false)
}

const impersonationSessionClosed = "impersonation session has been closed"

// isSessionLossFor peeks at most 4 KiB of a 403 and restores the consumed
// bytes, so unrelated permission responses remain intact for API callers.
func isSessionLossFor(response *http.Response, impersonate bool) bool {
	if response == nil {
		return false
	}
	if response.StatusCode == http.StatusUnauthorized {
		return true
	}
	if response.StatusCode == http.StatusForbidden && impersonate && response.Body != nil {
		prefix, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		response.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(prefix), response.Body), response.Body}
		return strings.Contains(strings.ToLower(string(prefix)), impersonationSessionClosed)
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
