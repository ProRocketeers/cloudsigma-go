package cloudsigma

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testOTPSecret = "GEZD GNBV GY3T QOJQ"

func timeWithDifferentNextOTP(secret string, now time.Time) time.Time {
	for i := 0; i < 100; i++ {
		first, firstErr := TOTP(secret, now)
		next, nextErr := TOTP(secret, now.Add(31*time.Second))
		if firstErr == nil && nextErr == nil && first != next {
			return now
		}
		now = now.Add(30 * time.Second)
	}
	panic("could not find adjacent test TOTP steps with different codes")
}

func TestAuthenticationBudgetRegressionModel(t *testing.T) {
	t.Run("five successful login stages then sixth rejected", func(t *testing.T) {
		clock := &testOTPClock{now: time.Unix(1_800_000_000, 0)}
		server := newBudgetModelServer(t, clock)
		defer server.Close()
		auth := newBudgetModelAuthenticator(t, server.URL, clock)
		for i := 0; i < 5; i++ {
			if err := budgetLogin(auth); err != nil {
				t.Fatalf("login %d: %v", i+1, err)
			}
		}
		if err := budgetLogin(auth); !isRateLimited(err) {
			t.Fatalf("sixth login = %v, want modeled lockout", err)
		}
		clock.Advance(time.Minute)
		if err := budgetLogin(auth); err != nil {
			t.Fatalf("login after modeled window: %v", err)
		}
	})

	t.Run("failed OTP checks consume the remaining slots", func(t *testing.T) {
		clock := &testOTPClock{now: time.Unix(1_800_000_000, 0)}
		server := newBudgetModelServer(t, clock)
		defer server.Close()
		auth := newBudgetModelAuthenticator(t, server.URL, clock)
		for i := 0; i < 3; i++ {
			if err := budgetLogin(auth); err != nil {
				t.Fatalf("login %d: %v", i+1, err)
			}
		}
		for i := 0; i < 2; i++ {
			if err := budgetOTP(auth, "reject"); err == nil {
				t.Fatalf("OTP rejection %d succeeded", i+1)
			}
		}
		if err := budgetLogin(auth); !isRateLimited(err) {
			t.Fatalf("login after three logins and two OTP rejections = %v, want modeled lockout", err)
		}
	})

	t.Run("successful OTP neither spends nor resets a slot", func(t *testing.T) {
		clock := &testOTPClock{now: time.Unix(1_800_000_000, 0)}
		server := newBudgetModelServer(t, clock)
		defer server.Close()
		auth := newBudgetModelAuthenticator(t, server.URL, clock)
		for i := 0; i < 3; i++ {
			if err := budgetLogin(auth); err != nil {
				t.Fatalf("login %d: %v", i+1, err)
			}
		}
		if err := budgetOTP(auth, "accepted"); err != nil {
			t.Fatalf("successful OTP: %v", err)
		}
		for i := 0; i < 2; i++ {
			if err := budgetLogin(auth); err != nil {
				t.Fatalf("login %d after OTP: %v", i+4, err)
			}
		}
		if err := budgetLogin(auth); !isRateLimited(err) {
			t.Fatalf("sixth login around successful OTP = %v, want modeled lockout", err)
		}
	})
}

func newBudgetModelServer(t *testing.T, clock *testOTPClock) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	used := 0
	windowStart := clock.Now()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if clock.Now().Sub(windowStart) >= time.Minute {
			used = 0
			windowStart = clock.Now()
		}
		if r.URL.Query().Get("do") == "login" {
			if used >= 5 {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, "too many attempts")
				return
			}
			used++
			_, _ = io.WriteString(w, `{}`)
			return
		}
		if r.URL.Query().Get("do") == "verify_otp" {
			if r.Header.Get("OTP") == "reject" {
				used++
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{}`)
			return
		}
		http.NotFound(w, r)
	}))
	return server
}

func newBudgetModelAuthenticator(t *testing.T, baseURL string, clock *testOTPClock) *authenticator {
	t.Helper()
	auth, err := newAuthenticator(baseURL+"/api/2.0/", t.Name(), "pass", testOTPSecret, "", "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	auth.now = clock.Now
	auth.sleep = clock.Sleep
	return auth
}

func budgetLogin(auth *authenticator) error {
	_, err := auth.doJSON(context.Background(), &http.Client{}, http.MethodPost,
		auth.root+"accounts/action/?do=login", []byte(`{}`), nil, AuthStageLogin, 0)
	return err
}

func budgetOTP(auth *authenticator, code string) error {
	_, err := auth.doJSON(context.Background(), &http.Client{}, http.MethodPost,
		auth.root+"accounts/action/?do=verify_otp", []byte(`{}`), map[string]string{"OTP": code}, AuthStageOTPVerification, 0)
	return err
}

func TestAttemptResultEventsExposeIntermediateOTPFailure(t *testing.T) {
	var mu sync.Mutex
	var events []AuthEvent
	verify := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("do") {
		case "login":
			http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: "not-for-events", Path: "/"})
			_, _ = io.WriteString(w, `{}`)
		case "verify_otp":
			verify++
			if verify == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, "rejected OTP must not appear in callback")
				return
			}
			_, _ = io.WriteString(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	auth, err := newAuthenticatorWithEvents(server.URL+"/api/2.0/", t.Name(), "password-secret", testOTPSecret, "", "", time.Second,
		func(event AuthEvent) { mu.Lock(); events = append(events, event); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	clock := installTestOTPClock(auth, time.Unix(29, 0))
	if err := auth.handshake(context.Background()); err != nil {
		t.Fatal(err)
	}
	if verify != 2 {
		t.Fatalf("OTP requests = %d, want failed attempt followed by success", verify)
	}
	mu.Lock()
	defer mu.Unlock()
	var attempts []AuthEvent
	for _, event := range events {
		if event.Type == AuthEventAttemptResult {
			attempts = append(attempts, event)
		}
	}
	want := []struct {
		stage   AuthStage
		status  int
		outcome string
	}{
		{AuthStageLogin, http.StatusOK, authEventOutcomeSuccess},
		{AuthStageOTPVerification, http.StatusUnauthorized, authEventOutcomeFailure},
		{AuthStageOTPVerification, http.StatusOK, authEventOutcomeSuccess},
	}
	if len(attempts) != len(want) {
		t.Fatalf("attempt events = %#v, want %d events", attempts, len(want))
	}
	for i, expected := range want {
		if attempts[i].Stage != expected.stage || attempts[i].StatusCode != expected.status || attempts[i].Outcome != expected.outcome {
			t.Errorf("attempt %d = %#v, want stage=%s status=%d outcome=%s", i, attempts[i], expected.stage, expected.status, expected.outcome)
		}
	}
	if clock.Now().Unix() != 31 {
		t.Fatalf("injected clock = %s, want OTP retry to cross the step", clock.Now())
	}
	if strings.Contains(fmt.Sprint(events), "password-secret") || strings.Contains(fmt.Sprint(events), testOTPSecret) || strings.Contains(fmt.Sprint(events), "not-for-events") || strings.Contains(fmt.Sprint(events), "rejected OTP") {
		t.Fatalf("authentication event contains secret or response data: %#v", events)
	}
}

func TestAttemptResultUsesZeroStatusWithoutHTTPResponse(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	endpoint := server.URL + "/api/2.0/"
	server.Close()
	var events []AuthEvent
	auth, err := newAuthenticatorWithEvents(endpoint, t.Name(), "pass", testOTPSecret, "", "", time.Second,
		func(event AuthEvent) { events = append(events, event) })
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.handshake(context.Background()); err == nil {
		t.Fatal("handshake to closed server unexpectedly succeeded")
	}
	var attempts []AuthEvent
	for _, event := range events {
		if event.Type == AuthEventAttemptResult {
			attempts = append(attempts, event)
		}
	}
	if len(attempts) != 1 || attempts[0].Stage != AuthStageLogin || attempts[0].StatusCode != 0 || attempts[0].Outcome != authEventOutcomeFailure {
		t.Fatalf("attempt events = %#v, want one failed login attempt with status zero", attempts)
	}
}

func TestCachedSessionHitEmitsNoAuthenticationAttemptResults(t *testing.T) {
	f := newFakeAPI(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		BaseURL: f.baseURL(), Username: f.user, Password: "pass", OTPSecret: testOTPSecret,
		SessionCacheDir: dir,
	}
	first, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	var mu sync.Mutex
	var events []AuthEvent
	cfg.OnAuthEvent = func(event AuthEvent) { mu.Lock(); events = append(events, event); mu.Unlock() }
	second, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	mu.Lock()
	defer mu.Unlock()
	for _, event := range events {
		if event.Type == AuthEventAttemptResult {
			t.Fatalf("valid cached session emitted a request-attempt result: %#v", event)
		}
	}
	if login, verify, _ := f.counts(); login != 1 || verify != 1 {
		t.Fatalf("cache-hit login/OTP requests = %d/%d, want no additional handshake", login, verify)
	}
}

func TestCachedSessionRemainsUsableDuringAccountLoginCooldown(t *testing.T) {
	f := newFakeAPI(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		BaseURL: f.baseURL(), Username: f.user, Password: "pass", OTPSecret: testOTPSecret,
		SessionCacheDir: dir,
	}
	first, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	lock, err := first.refresher.store.LockAccount(context.Background(), first.refresher.storeKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.refresher.store.saveAccountRetry(context.Background(), first.refresher.storeKey, time.Now().Add(time.Minute)); err != nil {
		_ = lock.Close()
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("valid session was blocked by new-login cooldown: %v", err)
	}
	defer second.Close()
	if err := second.Get(context.Background(), "protected/", nil); err != nil {
		t.Fatalf("authenticated request during login cooldown: %v", err)
	}
	if login, _, _ := f.counts(); login != 1 {
		t.Fatalf("login requests during valid session reuse = %d, want only the initial handshake", login)
	}
}

func TestKnownAcceptedStepWaitsAcrossImpersonationTargets(t *testing.T) {
	var mu sync.Mutex
	var codes, targets []string
	logins := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Query().Get("do") == "login":
			logins++
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: fmt.Sprint(logins), Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: "csrf", Path: "/"})
			_, _ = io.WriteString(w, `{}`)
		case r.URL.Query().Get("do") == "verify_otp":
			codes = append(codes, r.Header.Get("OTP"))
			_, _ = io.WriteString(w, `{}`)
		case strings.Contains(r.URL.Path, "/impersonate/"):
			targets = append(targets, r.URL.Path)
			_, _ = io.WriteString(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	clock := &testOTPClock{now: time.Now().Truncate(30 * time.Second)}
	makeRefresher := func(baseURL, username, target string) *refresher {
		t.Helper()
		auth, err := newAuthenticator(baseURL, username, "pass", testOTPSecret, target, "", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		auth.now = clock.Now
		auth.sleep = clock.Sleep
		return newRefresher(auth)
	}
	first := makeRefresher(server.URL+"/api/2.0/", "Operator@Example.test", "target-a")
	defer first.close()
	if err := first.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	step := clock.Now().Unix() / 30
	second := makeRefresher(server.URL+"/api/2.0", "operator@example.test", "target-b")
	defer second.close()
	if err := second.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := clock.Now().Unix() / 30; got <= step {
		t.Fatalf("second handshake stayed in spent step %d", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if logins != 2 || len(codes) != 2 || len(targets) != 2 {
		t.Fatalf("logins/OTP/impersonation = %d/%d/%d, want 2/2/2", logins, len(codes), len(targets))
	}
	if targets[0] == targets[1] {
		t.Fatalf("target requests = %v, want separate impersonation targets", targets)
	}
}

func TestKnownStepWaitCancellationDoesNotBlockOtherAccounts(t *testing.T) {
	type counts struct{ logins, verifications int }
	var mu sync.Mutex
	byUser := make(map[string]counts)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("do") {
		case "login":
			var body struct {
				Username string `json:"username"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			current := byUser[body.Username]
			current.logins++
			byUser[body.Username] = current
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: "csrf", Path: "/"})
			_, _ = io.WriteString(w, `{}`)
		case "verify_otp":
			mu.Lock()
			for user, current := range byUser {
				if current.logins > current.verifications {
					current.verifications++
					byUser[user] = current
					break
				}
			}
			mu.Unlock()
			_, _ = io.WriteString(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	clock := &testOTPClock{now: time.Now().Truncate(30 * time.Second)}
	makeRefresher := func(user string) *refresher {
		auth, err := newAuthenticator(server.URL+"/api/2.0/", user, "pass", testOTPSecret, "", "", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		auth.now = clock.Now
		auth.sleep = clock.Sleep
		return newRefresher(auth)
	}
	first := makeRefresher("same-account@example.test")
	defer first.close()
	if err := first.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}

	waitStarted := make(chan struct{})
	var eventsMu sync.Mutex
	var events []AuthEvent
	secondAuth, err := newAuthenticatorWithEvents(server.URL+"/api/2.0/", "SAME-account@example.test", "pass", testOTPSecret, "target-b", "", time.Second,
		func(event AuthEvent) { eventsMu.Lock(); events = append(events, event); eventsMu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	secondAuth.now = clock.Now
	secondAuth.sleep = func(ctx context.Context, _ time.Duration) error {
		close(waitStarted)
		<-ctx.Done()
		return ctx.Err()
	}
	second := newRefresher(secondAuth)
	defer second.close()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- second.initialize(ctx) }()
	<-waitStarted

	other := makeRefresher("unrelated@example.test")
	defer other.close()
	if err := other.initialize(context.Background()); err != nil {
		t.Fatalf("unrelated account blocked by OTP wait: %v", err)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled known-step wait = %v, want context cancellation", err)
	}
	eventsMu.Lock()
	defer eventsMu.Unlock()
	for _, event := range events {
		if event.Type == AuthEventAttemptResult {
			t.Fatalf("canceled preemptive wait emitted request attempt: %#v", event)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if byUser["same-account@example.test"].logins != 1 || byUser["unrelated@example.test"].logins != 1 {
		t.Fatalf("login counts by account = %#v, want one original and one unrelated request", byUser)
	}
}

func TestAcceptedOTPMetadataSurvivesPasswordRotationButNotSecretRotation(t *testing.T) {
	var mu sync.Mutex
	logins, verifications := 0, 0
	seenCodes := make(map[string]bool)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("do") {
		case "login":
			mu.Lock()
			logins++
			session := fmt.Sprint(logins)
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: session, Path: "/", MaxAge: 3600})
			http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: "csrf", Path: "/", MaxAge: 3600})
			_, _ = io.WriteString(w, `{}`)
		case "verify_otp":
			mu.Lock()
			verifications++
			code := r.Header.Get("OTP")
			if seenCodes[code] {
				mu.Unlock()
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			seenCodes[code] = true
			mu.Unlock()
			_, _ = io.WriteString(w, `{}`)
		case "":
			_, _ = io.WriteString(w, `{}`) // cached-session validation
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	start := timeWithDifferentNextOTP(testOTPSecret, time.Now().Truncate(30*time.Second))
	base := Config{BaseURL: server.URL + "/api/2.0/", Username: t.Name(), Password: "before", OTPSecret: testOTPSecret, SessionCacheDir: dir}
	first, err := newTestClientWithClock(context.Background(), base, start)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()

	rotatedPassword := base
	rotatedPassword.Password = "after"
	second, err := newTestClientWithClock(context.Background(), rotatedPassword, start)
	if err != nil {
		t.Fatal(err)
	}
	if !second.refresher.auth.now().After(start) {
		t.Fatalf("password rotation did not wait for a fresh accepted step: now=%s start=%s", second.refresher.auth.now(), start)
	}
	second.Close()

	rotatedSecret := rotatedPassword
	rotatedSecret.OTPSecret = "JBSWY3DPEHPK3PXP"
	third, err := newTestClientWithClock(context.Background(), rotatedSecret, start)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if !third.refresher.auth.now().Equal(start) {
		t.Fatalf("OTP-secret rotation inherited old secret's wait: now=%s start=%s", third.refresher.auth.now(), start)
	}
	mu.Lock()
	defer mu.Unlock()
	if logins != 3 || verifications != 3 {
		t.Fatalf("login/OTP requests = %d/%d, want 3/3 without known replays", logins, verifications)
	}
}

func TestAcceptedOTPStorageFailureFailsClosedAndKeepsProcessKnowledge(t *testing.T) {
	var mu sync.Mutex
	logins, verifications := 0, 0
	seenCodes := make(map[string]bool)
	var metadataPath string
	var symlinkErr error
	var outsidePath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("do") {
		case "login":
			mu.Lock()
			logins++
			session := fmt.Sprint(logins)
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: session, Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: "csrf", Path: "/"})
			_, _ = io.WriteString(w, `{}`)
		case "verify_otp":
			mu.Lock()
			verifications++
			code := r.Header.Get("OTP")
			if seenCodes[code] {
				mu.Unlock()
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			seenCodes[code] = true
			current := verifications
			mu.Unlock()
			if current == 1 {
				err := os.Symlink(outsidePath, metadataPath)
				mu.Lock()
				symlinkErr = err
				mu.Unlock()
			}
			_, _ = io.WriteString(w, `{}`)
		case "":
			_, _ = io.WriteString(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	start := timeWithDifferentNextOTP(testOTPSecret, time.Now().Truncate(30*time.Second))
	makeRefresher := func(target string) *refresher {
		auth, err := newAuthenticator(server.URL+"/api/2.0/", t.Name(), "pass", testOTPSecret, target, "", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		installTestOTPClock(auth, start)
		r := newRefresher(auth)
		if err := r.configureStore(dir); err != nil {
			t.Fatal(err)
		}
		return r
	}
	first := makeRefresher("")
	metadataKey := acceptedOTPKey(first.storeKey, otpSecretBinding(testOTPSecret))
	metadataPath, _ = first.store.entryPath(metadataKey)
	outsidePath = filepath.Join(dir, "outside")
	if err := os.WriteFile(outsidePath, []byte("not a cache entry"), 0600); err != nil {
		t.Fatal(err)
	}
	err := first.initialize(context.Background())
	var authErr *AuthError
	if !errors.As(err, &authErr) || authErr.Kind != AuthKindStorageFailure || !errors.Is(err, ErrOTPStateStorage) || !errors.Is(err, ErrSessionCacheUnsafe) {
		t.Fatalf("first handshake = %v, want typed accepted-OTP storage failure", err)
	}
	mu.Lock()
	if symlinkErr != nil {
		mu.Unlock()
		t.Fatalf("could not inject unsafe metadata entry: %v", symlinkErr)
	}
	mu.Unlock()
	first.close()
	if err := os.Remove(metadataPath); err != nil {
		t.Fatal(err)
	}

	second := makeRefresher("another-target")
	defer second.close()
	if err := second.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if logins != 2 || verifications != 2 {
		t.Fatalf("requests after storage failure = %d/%d, want a new step and no known replay", logins, verifications)
	}
}

func TestAcceptedOTPIsRememberedBeforeFailedImpersonation(t *testing.T) {
	var mu sync.Mutex
	logins, verifications := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Query().Get("do") == "login":
			logins++
			http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: "csrf", Path: "/"})
			_, _ = io.WriteString(w, `{}`)
		case r.URL.Query().Get("do") == "verify_otp":
			verifications++
			_, _ = io.WriteString(w, `{}`)
		case strings.Contains(r.URL.Path, "/impersonate/"):
			w.WriteHeader(http.StatusForbidden)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	defer server.Close()
	clock := &testOTPClock{now: time.Now().Truncate(30 * time.Second)}
	makeRefresher := func(target string) *refresher {
		auth, err := newAuthenticator(server.URL+"/api/2.0/", t.Name(), "pass", testOTPSecret, target, "", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		auth.now = clock.Now
		auth.sleep = clock.Sleep
		return newRefresher(auth)
	}
	failed := makeRefresher("forbidden-target")
	if err := failed.initialize(context.Background()); err == nil {
		t.Fatal("expected impersonation failure")
	}
	failed.close()
	before := clock.Now()
	next := makeRefresher("")
	defer next.close()
	if err := next.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !clock.Now().After(before) {
		t.Fatal("retry reused the OTP accepted before impersonation failed")
	}
	mu.Lock()
	defer mu.Unlock()
	if logins != 2 || verifications != 2 {
		t.Fatalf("login/OTP requests = %d/%d, want two fresh handshakes", logins, verifications)
	}
}

func TestAcceptedStepRecordsTheSubmittedStepAcrossResponseBoundary(t *testing.T) {
	var mu sync.Mutex
	logins, verifications := 0, 0
	var clock *testOTPClock
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Query().Get("do") {
		case "login":
			logins++
			http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: "csrf", Path: "/"})
			_, _ = io.WriteString(w, `{}`)
		case "verify_otp":
			verifications++
			if verifications == 1 {
				clock.Advance(30 * time.Second)
			}
			_, _ = io.WriteString(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	clock = &testOTPClock{now: time.Now().Truncate(30 * time.Second)}
	makeRefresher := func() *refresher {
		auth, err := newAuthenticator(server.URL+"/api/2.0/", t.Name(), "pass", testOTPSecret, "", "", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		auth.now = clock.Now
		auth.sleep = clock.Sleep
		return newRefresher(auth)
	}
	first := makeRefresher()
	defer first.close()
	if err := first.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	boundaryTime := clock.Now()
	second := makeRefresher()
	defer second.close()
	if err := second.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !clock.Now().Equal(boundaryTime) {
		t.Fatalf("waited again after response crossed the step boundary: now=%s boundary=%s", clock.Now(), boundaryTime)
	}
	mu.Lock()
	defer mu.Unlock()
	if logins != 2 || verifications != 2 {
		t.Fatalf("login/OTP requests = %d/%d, want two without an extra preemptive wait", logins, verifications)
	}
}

func TestSessionCacheAcceptedOTPCoordinatesAcrossProcessesAndTargets(t *testing.T) {
	var mu sync.Mutex
	logins, verifications := 0, 0
	seenCodes := make(map[string]bool)
	targetSessions := make(map[string]string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Query().Get("do") == "login":
			mu.Lock()
			logins++
			session := fmt.Sprintf("session-%d", logins)
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: session, Path: "/", MaxAge: 3600})
			http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: "csrf", Path: "/", MaxAge: 3600})
			_, _ = io.WriteString(w, `{}`)
		case r.URL.Query().Get("do") == "verify_otp":
			mu.Lock()
			verifications++
			code := r.Header.Get("OTP")
			if seenCodes[code] {
				mu.Unlock()
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			seenCodes[code] = true
			mu.Unlock()
			_, _ = io.WriteString(w, `{}`)
		case strings.Contains(r.URL.Path, "/impersonate/"):
			target := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/2.0/impersonate/"), "/")
			cookie, _ := r.Cookie("sessionid")
			if cookie == nil {
				t.Errorf("impersonation %s had no session cookie", target)
			} else {
				mu.Lock()
				targetSessions[target] = cookie.Value
				mu.Unlock()
			}
			_, _ = io.WriteString(w, `{}`)
		case strings.HasSuffix(r.URL.Path, "/protected/"):
			_, _ = io.WriteString(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	start := timeWithDifferentNextOTP(testOTPSecret, time.Now().Truncate(30*time.Second))
	unix := fmt.Sprint(start.Unix())
	user := t.Name() + "@example.test"
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runProcess := func(target string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestSessionCacheProcessHelper$")
		cmd.Env = append(os.Environ(),
			"CLOUDSIGMA_TEST_CACHE_ENDPOINT="+server.URL+"/api/2.0/",
			"CLOUDSIGMA_TEST_CACHE_DIR="+dir,
			"CLOUDSIGMA_TEST_CACHE_USER="+user,
			"CLOUDSIGMA_TEST_CACHE_TARGET="+target,
			"CLOUDSIGMA_TEST_CACHE_NOW="+unix,
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("process for %s failed: %v\n%s", target, err, output)
		}
	}
	runProcess("target-a")
	runProcess("target-b")
	mu.Lock()
	defer mu.Unlock()
	if logins != 2 || verifications != 2 {
		t.Fatalf("cross-target login/OTP requests = %d/%d, want 2/2 without a replay retry", logins, verifications)
	}
	if targetSessions["target-a"] == "" || targetSessions["target-b"] == "" || targetSessions["target-a"] == targetSessions["target-b"] {
		t.Fatalf("target sessions = %#v, want separate cookies per impersonation target", targetSessions)
	}
}
