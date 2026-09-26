package cloudsigma

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAPI is an httptest-backed CloudSigma stand-in. Every counter and knob is
// mutex-guarded so the concurrency tests are race-clean.
type fakeAPI struct {
	srv *httptest.Server

	mu             sync.Mutex
	loginCalls     int
	verifyCalls    int
	protectedCalls int
	writeCalls     int
	loginPageHits  int
	counter        int

	session string
	csrf    string

	alwaysUnauthorized   bool
	redirectUnauthorized bool
	forceStatus          int
	loginStatus          int
	loginBody            string

	verifyOTPs  []string
	verifyCSRFs []string
	writeCSRFs  []string
	writeBodies [][]byte
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/2.0/accounts/action/", f.handleAccount)
	mux.HandleFunc("/api/2.0/protected/", f.handleProtected)
	mux.HandleFunc("/api/2.0/drives/", f.handleProtected)
	mux.HandleFunc("/api/2.0/status/", f.handleStatus)
	mux.HandleFunc("/api/2.0/blob/", f.handleBlob)
	mux.HandleFunc("/accounts/login/", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.loginPageHits++
		f.mu.Unlock()
		_, _ = io.WriteString(w, "<html>login</html>")
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) baseURL() string { return f.srv.URL + "/api/2.0/" }

func (f *fakeAPI) handleAccount(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("do") {
	case "login":
		f.mu.Lock()
		f.loginCalls++
		status, body := f.loginStatus, f.loginBody
		f.mu.Unlock()
		if status != 0 {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
			return
		}
		f.mu.Lock()
		f.counter++
		f.session = fmt.Sprintf("session-%d", f.counter)
		f.csrf = fmt.Sprintf("csrf-%d", f.counter)
		session, token := f.session, f.csrf
		f.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: session, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: token, Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	case "verify_otp":
		f.mu.Lock()
		f.verifyCalls++
		f.verifyOTPs = append(f.verifyOTPs, r.Header.Get("OTP"))
		f.verifyCSRFs = append(f.verifyCSRFs, r.Header.Get("X-CSRFToken"))
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeAPI) handleProtected(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.protectedCalls++
	if r.Method != http.MethodGet {
		body, _ := io.ReadAll(r.Body)
		f.writeCalls++
		f.writeCSRFs = append(f.writeCSRFs, r.Header.Get("X-CSRFToken"))
		f.writeBodies = append(f.writeBodies, body)
	}
	always, redirect, force, valid := f.alwaysUnauthorized, f.redirectUnauthorized, f.forceStatus, f.session
	f.mu.Unlock()

	if force != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(force)
		_, _ = io.WriteString(w, `{"error":"forced"}`)
		return
	}

	authorized := valid != ""
	if authorized {
		if c, err := r.Cookie("sessionid"); err != nil || c.Value != valid {
			authorized = false
		}
	}
	if !always && authorized {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
		return
	}
	if redirect {
		http.Redirect(w, r, "/accounts/login/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, `{"error":"unauthorized"}`)
}

func (f *fakeAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/2.0/status/"), "/")
	code, err := strconv.Atoi(raw)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"status":%d}`, code)
}

func (f *fakeAPI) handleBlob(w http.ResponseWriter, r *http.Request) {
	size, err := strconv.Atoi(r.URL.Query().Get("size"))
	if err != nil || size < 0 {
		http.Error(w, "bad size", http.StatusBadRequest)
		return
	}
	const prefix = `{"ok":true}`
	if size < len(prefix) {
		size = len(prefix)
	}
	body := make([]byte, size)
	copy(body, prefix)
	for i := len(prefix); i < size; i++ {
		body[i] = ' '
	}
	w.Header().Set("Content-Type", "application/json")
	if s := r.URL.Query().Get("status"); s != "" {
		if code, convErr := strconv.Atoi(s); convErr == nil {
			w.WriteHeader(code)
		}
	}
	_, _ = w.Write(body)
}

func (f *fakeAPI) expire() {
	f.mu.Lock()
	f.session = ""
	f.mu.Unlock()
}

func (f *fakeAPI) counts() (login, verify, protected int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loginCalls, f.verifyCalls, f.protectedCalls
}

func (f *fakeAPI) loginPageCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loginPageHits
}

func (f *fakeAPI) observations() (verifyOTPs, verifyCSRFs, writeCSRFs []string, writeBodies [][]byte, csrf string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.verifyOTPs...),
		append([]string(nil), f.verifyCSRFs...),
		append([]string(nil), f.writeCSRFs...),
		append([][]byte(nil), f.writeBodies...),
		f.csrf
}

func (f *fakeAPI) newClient(t *testing.T) *Client {
	t.Helper()
	client, err := New(context.Background(), Config{
		BaseURL:   f.baseURL(),
		Username:  "user@example.com",
		Password:  "secret-password",
		OTPSecret: "GEZD GNBV GY3T QOJQ",
		UserAgent: "cloudsigma-go-test/1.0",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func TestNewHandshakeHappyPath(t *testing.T) {
	f := newFakeAPI(t)
	client := f.newClient(t)

	login, verify, _ := f.counts()
	if login != 1 || verify != 1 {
		t.Fatalf("handshake counts login=%d verify=%d, want 1/1", login, verify)
	}

	verifyOTPs, verifyCSRFs, _, _, csrf := f.observations()
	if verifyOTPs[0] == "" {
		t.Error("verify_otp carried no OTP header")
	}
	if verifyCSRFs[0] == "" {
		t.Error("verify_otp carried no X-CSRFToken header")
	}
	if verifyCSRFs[0] != csrf {
		t.Errorf("verify_otp CSRF %q, want %q", verifyCSRFs[0], csrf)
	}

	var out map[string]any
	if err := client.Put(context.Background(), "protected/", map[string]any{"name": "vol"}, &out); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if out["ok"] != true {
		t.Errorf("Put response = %v, want ok:true", out)
	}

	_, _, writeCSRFs, _, _ := f.observations()
	if len(writeCSRFs) != 1 || writeCSRFs[0] != csrf {
		t.Errorf("write CSRF headers = %v, want [%s]", writeCSRFs, csrf)
	}
}

func TestNewRequiresBaseURL(t *testing.T) {
	if _, err := New(context.Background(), Config{}); err == nil {
		t.Fatal("New with empty BaseURL returned nil error")
	}
}

func TestNewHonoursContext(t *testing.T) {
	cases := []struct {
		name string
		ctx  func() context.Context
	}{
		{"cancelled", func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}},
		{"expired deadline", func() context.Context {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			defer cancel()
			return ctx
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)

			client, err := New(tc.ctx(), Config{
				BaseURL:   f.baseURL(),
				Username:  "user@example.com",
				Password:  "secret-password",
				OTPSecret: "GEZD GNBV GY3T QOJQ",
				UserAgent: "cloudsigma-go-test/1.0",
			})
			if err == nil {
				t.Fatal("New returned nil error for a dead context")
			}
			if client != nil {
				t.Error("New returned a usable client for a dead context")
			}
			if login, _, _ := f.counts(); login != 0 {
				t.Errorf("login calls = %d, want 0 (request must not be sent)", login)
			}
		})
	}
}

func TestGetRecoversFrom401(t *testing.T) {
	f := newFakeAPI(t)
	client := f.newClient(t)
	f.expire()

	var out map[string]any
	if err := client.Get(context.Background(), "protected/", &out); err != nil {
		t.Fatalf("Get after expiry: %v", err)
	}
	if out["ok"] != true {
		t.Errorf("response = %v, want ok:true", out)
	}

	login, _, protected := f.counts()
	if login != 2 {
		t.Errorf("login calls = %d, want 2 (initial + one refresh)", login)
	}
	if protected != 2 {
		t.Errorf("protected calls = %d, want 2 (challenge + retry)", protected)
	}
}

func TestLoginPageRedirectRecovered(t *testing.T) {
	f := newFakeAPI(t)
	client := f.newClient(t)

	f.mu.Lock()
	f.redirectUnauthorized = true
	f.session = ""
	f.mu.Unlock()

	var out map[string]any
	if err := client.Get(context.Background(), "protected/", &out); err != nil {
		t.Fatalf("Get across login redirect: %v", err)
	}
	if out["ok"] != true {
		t.Errorf("response = %v, want ok:true", out)
	}
	if login, _, _ := f.counts(); login != 2 {
		t.Errorf("login calls = %d, want 2", login)
	}
}

func TestConcurrent401SingleFlight(t *testing.T) {
	const goroutines = 32

	f := newFakeAPI(t)
	client := f.newClient(t)
	f.expire()

	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var out map[string]any
			errs[i] = client.Get(ctx, "protected/", &out)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}

	login, _, _ := f.counts()
	if login != 2 {
		t.Errorf("login calls = %d, want exactly 2 (initial + one shared refresh)", login)
	}
}

func TestBodyReplayOnRetry(t *testing.T) {
	f := newFakeAPI(t)
	client := f.newClient(t)
	f.expire()

	body := map[string]any{"name": "volume-1", "size": 10 * 1024 * 1024 * 1024}
	var out map[string]any
	if err := client.Post(context.Background(), "protected/", body, &out); err != nil {
		t.Fatalf("Post: %v", err)
	}

	_, _, _, bodies, _ := f.observations()
	if len(bodies) != 2 {
		t.Fatalf("request bodies = %d, want 2 attempts", len(bodies))
	}
	if len(bodies[0]) == 0 || len(bodies[1]) == 0 {
		t.Fatal("an attempt sent an empty body")
	}
	if string(bodies[0]) != string(bodies[1]) {
		t.Errorf("replayed body %q, want identical to %q", bodies[1], bodies[0])
	}
}

func TestRetryHappensExactlyOnce(t *testing.T) {
	f := newFakeAPI(t)
	client := f.newClient(t)

	f.mu.Lock()
	f.alwaysUnauthorized = true
	f.mu.Unlock()

	err := client.Get(context.Background(), "protected/", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", apiErr.StatusCode)
	}
	if apiErr.Method != http.MethodGet {
		t.Errorf("Method = %q, want GET", apiErr.Method)
	}
	if !strings.Contains(apiErr.URL, "protected") {
		t.Errorf("URL = %q, want the protected request URL", apiErr.URL)
	}
	if apiErr.Body == "" {
		t.Error("Body is empty, want the upstream response text")
	}

	login, _, protected := f.counts()
	if protected != 2 {
		t.Errorf("protected calls = %d, want 2 (no loop)", protected)
	}
	if login != 2 {
		t.Errorf("login calls = %d, want 2 (initial + one refresh, no loop)", login)
	}
}

func TestPersistentLoginRedirectIsNotFollowed(t *testing.T) {
	f := newFakeAPI(t)
	client := f.newClient(t)

	f.mu.Lock()
	f.alwaysUnauthorized = true
	f.redirectUnauthorized = true
	f.mu.Unlock()

	err := client.Get(context.Background(), "protected/", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *APIError", err)
	}
	if apiErr.StatusCode < 300 || apiErr.StatusCode > 399 {
		t.Errorf("status = %d, want a 3xx login redirect", apiErr.StatusCode)
	}
	if apiErr.Method != http.MethodGet {
		t.Errorf("Method = %q, want GET", apiErr.Method)
	}
	if !strings.Contains(apiErr.URL, "protected") {
		t.Errorf("URL = %q, want the protected request URL", apiErr.URL)
	}
	if apiErr.Body == "" {
		t.Error("Body is empty, want the redirect response text")
	}
	if hits := f.loginPageCount(); hits != 0 {
		t.Errorf("login page fetched %d times, want 0", hits)
	}
	login, _, protected := f.counts()
	if protected != 2 {
		t.Errorf("protected calls = %d, want 2 (no loop)", protected)
	}
	if login != 2 {
		t.Errorf("login calls = %d, want 2 (initial + one refresh)", login)
	}
}

func TestServerErrorNotRetried(t *testing.T) {
	f := newFakeAPI(t)
	client := f.newClient(t)

	f.mu.Lock()
	f.forceStatus = http.StatusInternalServerError
	f.mu.Unlock()

	err := client.Get(context.Background(), "protected/", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", apiErr.StatusCode)
	}

	login, _, protected := f.counts()
	if protected != 1 {
		t.Errorf("protected calls = %d, want 1 (5xx must not be retried)", protected)
	}
	if login != 1 {
		t.Errorf("login calls = %d, want 1 (5xx must not trigger re-login)", login)
	}
}

func TestResponseTooLargeFailsLoudly(t *testing.T) {
	f := newFakeAPI(t)
	client := f.newClient(t)

	err := client.Get(context.Background(), fmt.Sprintf("blob/?size=%d", maxResponseBytes+1), nil)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v, want ErrResponseTooLarge", err)
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Errorf("error = %v, want the overflow sentinel, not *APIError", err)
	}
	if !strings.Contains(err.Error(), strconv.Itoa(maxResponseBytes)) {
		t.Errorf("error = %q, want it to name the %d-byte limit", err, maxResponseBytes)
	}
}

func TestOversizedNon2xxKeepsStatus(t *testing.T) {
	f := newFakeAPI(t)
	client := f.newClient(t)

	err := client.Get(context.Background(),
		fmt.Sprintf("blob/?size=%d&status=%d", maxResponseBytes+1, http.StatusForbidden), nil)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *APIError so callers can map the status code", err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", apiErr.StatusCode)
	}
	if errors.Is(err, ErrResponseTooLarge) {
		t.Error("error must not surface as the overflow sentinel when the status is known")
	}
	if !strings.Contains(apiErr.Body, strconv.Itoa(maxResponseBytes)) {
		t.Errorf("Body = %q, want it to note the %d-byte overflow", apiErr.Body, maxResponseBytes)
	}
}

func TestResponseAtCapDecodes(t *testing.T) {
	f := newFakeAPI(t)
	client := f.newClient(t)

	var out map[string]any
	if err := client.Get(context.Background(), fmt.Sprintf("blob/?size=%d", maxResponseBytes), &out); err != nil {
		t.Fatalf("Get at cap: %v", err)
	}
	if out["ok"] != true {
		t.Errorf("response = %v, want ok:true", out)
	}
}

func TestReadCapped(t *testing.T) {
	if got, err := readCapped(strings.NewReader("123"), 5); err != nil || string(got) != "123" {
		t.Errorf("under limit: got %q, err %v", got, err)
	}
	if got, err := readCapped(strings.NewReader("12345"), 5); err != nil || string(got) != "12345" {
		t.Errorf("at limit: got %q, err %v", got, err)
	}
	if _, err := readCapped(strings.NewReader("123456"), 5); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("over limit: err = %v, want ErrResponseTooLarge", err)
	}
}

func TestFailedRefreshCooldown(t *testing.T) {
	f := newFakeAPI(t)
	f.mu.Lock()
	f.loginStatus = http.StatusUnauthorized
	f.loginBody = "bad credentials"
	f.mu.Unlock()

	auth, err := newAuthenticator(f.baseURL(), "user", "pass", "GEZD GNBV GY3T QOJQ", "", "ua", time.Second)
	if err != nil {
		t.Fatalf("newAuthenticator: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	auth.now = func() time.Time { return now }
	auth.sleep = func(context.Context, time.Duration) error { return nil }

	r := newRefresher(auth)
	gen := r.currentGeneration()

	first := r.refresh(context.Background(), gen)
	if first == nil {
		t.Fatal("first refresh = nil, want error")
	}
	if login, _, _ := f.counts(); login != 1 {
		t.Fatalf("login calls = %d, want 1", login)
	}

	second := r.refresh(context.Background(), gen)
	if second == nil {
		t.Fatal("second refresh = nil, want the remembered error")
	}
	if second != first {
		t.Errorf("second refresh = %v, want the remembered %v", second, first)
	}
	if login, _, _ := f.counts(); login != 1 {
		t.Errorf("login calls = %d, want 1 (cooldown must not start a new cycle)", login)
	}

	now = now.Add(31 * time.Second)
	third := r.refresh(context.Background(), gen)
	if third == nil {
		t.Fatal("third refresh = nil, want a new failing cycle after cooldown")
	}
	if login, _, _ := f.counts(); login != 2 {
		t.Errorf("login calls = %d, want 2 (new cycle after cooldown)", login)
	}
}

func TestSuccessfulRefreshShortCircuitsAndClearsCooldown(t *testing.T) {
	f := newFakeAPI(t)
	f.mu.Lock()
	f.loginStatus = http.StatusUnauthorized
	f.loginBody = "bad credentials"
	f.mu.Unlock()

	auth, err := newAuthenticator(f.baseURL(), "user", "pass", "GEZD GNBV GY3T QOJQ", "", "ua", time.Second)
	if err != nil {
		t.Fatalf("newAuthenticator: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	auth.now = func() time.Time { return now }
	auth.sleep = func(context.Context, time.Duration) error { return nil }

	r := newRefresher(auth)
	gen := r.currentGeneration()
	if err := r.refresh(context.Background(), gen); err == nil {
		t.Fatal("first refresh = nil, want error")
	}

	now = now.Add(31 * time.Second)
	f.mu.Lock()
	f.loginStatus = 0
	f.loginBody = ""
	f.mu.Unlock()

	if err := r.refresh(context.Background(), gen); err != nil {
		t.Fatalf("refresh after cooldown: %v", err)
	}
	if login, _, _ := f.counts(); login != 2 {
		t.Fatalf("login calls = %d, want 2", login)
	}

	if err := r.refresh(context.Background(), gen); err != nil {
		t.Errorf("refresh at stale generation = %v, want nil", err)
	}
	if login, _, _ := f.counts(); login != 2 {
		t.Errorf("login calls = %d, want 2 (newer generation short-circuits)", login)
	}
}

func TestRateLimitedReloginBacksOffThenFailsFast(t *testing.T) {
	f := newFakeAPI(t)
	f.mu.Lock()
	f.loginStatus = http.StatusTooManyRequests
	f.loginBody = "too many failed authentication attempts, wait a minute"
	f.mu.Unlock()

	auth, err := newAuthenticator(f.baseURL(), "user", "pass", "GEZD GNBV GY3T QOJQ", "", "ua", time.Second)
	if err != nil {
		t.Fatalf("newAuthenticator: %v", err)
	}
	var sleeps []time.Duration
	now := time.Unix(1_700_000_000, 0)
	auth.now = func() time.Time { return now }
	auth.sleep = func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		now = now.Add(d)
		return nil
	}

	refresher := &refresher{auth: auth, maxAttempts: 3, baseDelay: time.Second, maxDelay: 8 * time.Second}
	err = refresher.refresh(context.Background(), refresher.currentGeneration())
	if err == nil {
		t.Fatal("refresh returned nil, want rate-limit error after cap")
	}

	login, _, _ := f.counts()
	if login != 3 {
		t.Errorf("login attempts = %d, want 3 (cap)", login)
	}
	if len(sleeps) != 2 {
		t.Fatalf("backoff sleeps = %v, want 2", sleeps)
	}
	if sleeps[0] <= 0 || sleeps[1] <= sleeps[0] {
		t.Errorf("backoff not increasing: %v", sleeps)
	}
	if sleeps[1] > 8*time.Second {
		t.Errorf("backoff exceeded cap: %v", sleeps)
	}
}

func TestBadCredentialsFailFast(t *testing.T) {
	f := newFakeAPI(t)
	f.mu.Lock()
	f.loginStatus = http.StatusUnauthorized
	f.loginBody = "bad credentials"
	f.mu.Unlock()

	auth, err := newAuthenticator(f.baseURL(), "user", "pass", "GEZD GNBV GY3T QOJQ", "", "ua", time.Second)
	if err != nil {
		t.Fatalf("newAuthenticator: %v", err)
	}
	slept := 0
	auth.sleep = func(_ context.Context, _ time.Duration) error {
		slept++
		return nil
	}

	refresher := &refresher{auth: auth, maxAttempts: 3, baseDelay: time.Second, maxDelay: 8 * time.Second}
	if err := refresher.refresh(context.Background(), refresher.currentGeneration()); err == nil {
		t.Fatal("refresh returned nil, want credential error")
	}

	login, _, _ := f.counts()
	if login != 1 {
		t.Errorf("login attempts = %d, want 1 (fail fast, no backoff)", login)
	}
	if slept != 0 {
		t.Errorf("sleeps = %d, want 0 for a non-rate-limited failure", slept)
	}
}

func TestAPIErrorErrorsAs(t *testing.T) {
	f := newFakeAPI(t)
	client := f.newClient(t)

	for _, code := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusConflict, http.StatusTooManyRequests} {
		err := client.Get(context.Background(), fmt.Sprintf("status/%d/", code), nil)

		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("status %d: error = %v, want *APIError", code, err)
		}
		if apiErr.StatusCode != code {
			t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, code)
		}
		if apiErr.Body == "" {
			t.Errorf("status %d: empty Body", code)
		}
		if apiErr.Method != http.MethodGet {
			t.Errorf("status %d: Method = %q, want GET", code, apiErr.Method)
		}
		if !strings.Contains(apiErr.URL, "status") {
			t.Errorf("status %d: URL = %q", code, apiErr.URL)
		}
		if want := fmt.Sprintf("%d: ", code); !strings.HasPrefix(apiErr.Error(), want) {
			t.Errorf("Error() = %q, want prefix %q", apiErr.Error(), want)
		}
	}
}

func TestSessionLossPredicate(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		location string
		want     bool
	}{
		{"unauthorized", http.StatusUnauthorized, "", true},
		{"forbidden", http.StatusForbidden, "", false},
		{"ok", http.StatusOK, "", false},
		{"server error", http.StatusInternalServerError, "", false},
		{"login redirect", http.StatusFound, "https://prg1.t-cloud.eu/accounts/login/", true},
		{"relative login redirect", http.StatusFound, "/accounts/login/", true},
		{"bare relative login", http.StatusFound, "login/", true},
		{"login redirect with query", http.StatusFound, "/accounts/login/?next=/api/2.0/", true},
		{"case-insensitive login", http.StatusFound, "/accounts/Login/", true},
		{"non-login redirect", http.StatusFound, "/api/2.0/drives/", false},
		{"login history path", http.StatusFound, "/api/2.0/login_history/", false},
		{"suffixed login path", http.StatusFound, "/api/2.0/something-login/", false},
		{"permanent login redirect", http.StatusMovedPermanently, "/login", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: tc.status, Header: http.Header{}}
			if tc.location != "" {
				resp.Header.Set("Location", tc.location)
			}
			if got := isSessionLoss(resp); got != tc.want {
				t.Errorf("isSessionLoss = %v, want %v", got, tc.want)
			}
		})
	}
	if isSessionLoss(nil) {
		t.Error("isSessionLoss(nil) = true, want false")
	}
}

func TestIsLoginRedirect(t *testing.T) {
	cases := []struct {
		location string
		want     bool
	}{
		{"", false},
		{"/login", true},
		{"/accounts/login/", true},
		{"login/", true},
		{"accounts/login/", true},
		{"https://prg1.t-cloud.eu/accounts/login/", true},
		{"/accounts/login/?next=/api/2.0/", true},
		{"/api/2.0/login_history/", false},
		{"/api/2.0/something-login/", false},
		{"/api/2.0/drives/", false},
		{"https://example.com/login-help", false},
		{"/login\x00", false},
	}
	for _, tc := range cases {
		t.Run(tc.location, func(t *testing.T) {
			if got := isLoginRedirect(tc.location); got != tc.want {
				t.Errorf("isLoginRedirect(%q) = %v, want %v", tc.location, got, tc.want)
			}
		})
	}
}

func TestIsRateLimited(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain", errors.New("boom"), false},
		{"unauthorized", &APIError{StatusCode: http.StatusUnauthorized, Body: "bad credentials"}, false},
		{"http 429", &APIError{StatusCode: http.StatusTooManyRequests}, true},
		{"too many message", &APIError{StatusCode: http.StatusBadRequest, Body: "Too many failed authentication attempts"}, true},
		{"wait a minute message", &APIError{StatusCode: http.StatusBadRequest, Body: "please wait a minute"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRateLimited(tc.err); got != tc.want {
				t.Errorf("isRateLimited = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLoginCache(t *testing.T) {
	f := newFakeAPI(t)
	ctx := context.Background()

	first, err := Login(ctx, f.baseURL(), "user@example.com", "secret", "GEZD GNBV GY3T QOJQ", "", "ua")
	if err != nil {
		t.Fatalf("first Login: %v", err)
	}
	second, err := Login(ctx, f.baseURL(), "user@example.com", "secret", "GEZD GNBV GY3T QOJQ", "", "ua")
	if err != nil {
		t.Fatalf("second Login: %v", err)
	}
	if first != second {
		t.Error("Login returned two different clients for the same credentials")
	}
	if login, verify, _ := f.counts(); login != 1 || verify != 1 {
		t.Errorf("handshake counts login=%d verify=%d, want 1/1 (cached)", login, verify)
	}

	f.expire()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.srv.URL+"/api/2.0/protected/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := first.Do(req)
	if err != nil {
		t.Fatalf("cached client request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("cached client status = %d, want 200 (refresh transport active)", resp.StatusCode)
	}
	if login, _, _ := f.counts(); login != 2 {
		t.Errorf("login calls = %d, want 2 after cached-client session expiry", login)
	}
}

func TestEndpoint(t *testing.T) {
	if got := Endpoint("", "zrh"); got != "zrh.cloudsigma.com/api/2.0/" {
		t.Errorf("Endpoint empty base = %q", got)
	}
	if got := Endpoint("https://prg1.t-cloud.eu/api/2.0", ""); got != "prg1.t-cloud.eu/api/2.0/" {
		t.Errorf("Endpoint scheme base = %q", got)
	}
}
