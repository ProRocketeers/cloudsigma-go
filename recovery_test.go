package cloudsigma

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestImpersonationClosureUsesFreshSession(t *testing.T) {
	var mu sync.Mutex
	login, impersonate, operations := 0, 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.Contains(r.URL.RawQuery, "do=login"):
			login++
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: string(rune('0' + login)), Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: string(rune('0' + login)), Path: "/"})
			_, _ = io.WriteString(w, `{}`)
		case strings.Contains(r.URL.RawQuery, "do=verify_otp"):
			_, _ = io.WriteString(w, `{}`)
		case strings.Contains(r.URL.Path, "/impersonate/"):
			impersonate++
			_, _ = io.WriteString(w, `{}`)
		case strings.HasSuffix(r.URL.Path, "/protected/"):
			operations++
			cookie, _ := r.Cookie("sessionid")
			if impersonate == 1 || cookie == nil || cookie.Value != string(rune('0'+login)) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, "impersonation session has been closed")
				return
			}
			_, _ = io.WriteString(w, `{"ok":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := New(context.Background(), Config{BaseURL: server.URL + "/api/2.0/", Username: "user", Password: "pass", OTPSecret: "GEZD GNBV GY3T QOJQ", Impersonate: "target"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var out map[string]any
	if err := client.Get(context.Background(), "protected/", &out); err != nil {
		t.Fatal(err)
	}
	if out["ok"] != true {
		t.Fatalf("response = %v", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if login != 2 || impersonate != 2 || operations != 2 {
		t.Fatalf("login/impersonate/operations = %d/%d/%d, want 2/2/2", login, impersonate, operations)
	}
}

func TestPersistentLossCooldownPreventsNextHandshake(t *testing.T) {
	f := newFakeAPI(t)
	client := f.newClient(t)
	f.mu.Lock()
	f.alwaysUnauthorized = true
	f.mu.Unlock()
	for i := 0; i < 2; i++ {
		err := client.Get(context.Background(), "protected/", nil)
		var authErr *AuthError
		if !errors.As(err, &authErr) || authErr.Kind != AuthKindPersistentSessionLoss {
			t.Fatalf("call %d: error = %v, want persistent session loss", i, err)
		}
	}
	if login, _, _ := f.counts(); login != 2 {
		t.Fatalf("login calls = %d, want initial plus one recovery", login)
	}
}

func TestFailedCandidateKeepsPublishedJar(t *testing.T) {
	var mu sync.Mutex
	login := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.Contains(r.URL.RawQuery, "do=login"):
			login++
			if login > 1 {
				http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "poison", Path: "/"})
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, "bad credentials")
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "good", Path: "/"})
			_, _ = io.WriteString(w, `{}`)
		case strings.Contains(r.URL.RawQuery, "do=verify_otp"):
			_, _ = io.WriteString(w, `{}`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()
	client, err := New(context.Background(), Config{BaseURL: server.URL + "/api/2.0/", Username: "user", Password: "pass", OTPSecret: "GEZD GNBV GY3T QOJQ"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, jar := client.refresher.snapshot()
	if err := client.Get(context.Background(), "protected/", nil); err == nil {
		t.Fatal("expected recovery failure")
	}
	_, published := client.refresher.snapshot()
	if jar != published {
		t.Fatal("failed candidate replaced published jar")
	}
	if cookies := published.Cookies(client.refresher.auth.apiURL); len(cookies) != 1 || cookies[0].Value != "good" {
		t.Fatalf("published cookies = %v", cookies)
	}
}

func TestSessionCacheReusesCookieAndRecoversRevocation(t *testing.T) {
	f := newFakeAPI(t)
	cacheDir := t.TempDir()
	if err := os.Chmod(cacheDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		BaseURL: f.baseURL(), Username: "user", Password: "pass",
		OTPSecret: "GEZD GNBV GY3T QOJQ", SessionCacheDir: cacheDir,
	}
	first, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	second, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if login, _, _ := f.counts(); login != 1 {
		t.Fatalf("login calls after restart = %d, want 1", login)
	}
	if err := second.Get(context.Background(), "protected/", nil); err != nil {
		t.Fatal(err)
	}
	f.expire()
	if err := second.Get(context.Background(), "protected/", nil); err != nil {
		t.Fatal(err)
	}
	if login, _, _ := f.counts(); login != 2 {
		t.Fatalf("login calls after revocation = %d, want 2", login)
	}
	third, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if err := third.Get(context.Background(), "protected/", nil); err != nil {
		t.Fatal(err)
	}
	if login, _, _ := f.counts(); login != 2 {
		t.Fatalf("login calls after restored refresh = %d, want 2", login)
	}
}

func TestSessionCacheProcessHelper(t *testing.T) {
	endpoint := os.Getenv("CLOUDSIGMA_TEST_CACHE_ENDPOINT")
	if endpoint == "" {
		return
	}
	client, err := New(context.Background(), Config{
		BaseURL: endpoint, Username: "user", Password: "pass",
		OTPSecret: "GEZD GNBV GY3T QOJQ", SessionCacheDir: os.Getenv("CLOUDSIGMA_TEST_CACHE_DIR"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Get(context.Background(), "protected/", nil); err != nil {
		t.Fatal(err)
	}
}

func TestSessionCacheCoordinatesIndependentProcesses(t *testing.T) {
	f := newFakeAPI(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runPair := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmds := make([]*exec.Cmd, 2)
		for i := range cmds {
			cmds[i] = exec.CommandContext(ctx, exe, "-test.run=^TestSessionCacheProcessHelper$")
			cmds[i].Env = append(os.Environ(), "CLOUDSIGMA_TEST_CACHE_ENDPOINT="+f.baseURL(), "CLOUDSIGMA_TEST_CACHE_DIR="+dir)
			if err := cmds[i].Start(); err != nil {
				t.Fatal(err)
			}
		}
		for _, cmd := range cmds {
			if err := cmd.Wait(); err != nil {
				t.Fatalf("helper failed: %v", err)
			}
		}
	}
	runPair()
	if login, _, _ := f.counts(); login != 1 {
		t.Fatalf("initial process pair logins = %d, want 1", login)
	}
	f.expire()
	runPair()
	if login, _, _ := f.counts(); login != 2 {
		t.Fatalf("expired process pair logins = %d, want 2", login)
	}
}

func TestCanceledRecoveryWaiterDoesNotCancelSharedHandshake(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "do=login") {
			close(entered)
			<-release
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	auth, err := newAuthenticator(server.URL+"/api/2.0/", "user", "pass", "GEZD GNBV GY3T QOJQ", "", "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r := newRefresher(auth)
	defer r.close()
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { first <- r.refresh(ctx, 0) }()
	<-entered
	second := make(chan error, 1)
	go func() { second <- r.refresh(context.Background(), 0) }()
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("first waiter = %v", err)
	}
	close(release)
	if err := <-second; err != nil {
		t.Fatalf("shared recovery = %v", err)
	}
	if got := r.currentGeneration(); got != 1 {
		t.Fatalf("generation = %d, want 1", got)
	}
}

func TestSessionCacheHonorsPersistedRetryDeadline(t *testing.T) {
	f := newFakeAPI(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileSessionStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	key := SessionKey{
		Endpoint: f.baseURL(), Username: "user", Impersonate: "target-a",
		CredentialFingerprint: CredentialFingerprint(f.baseURL(), "user", "pass", "GEZD GNBV GY3T QOJQ"),
	}
	lock, err := store.LockAccount(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.saveAccountRetry(context.Background(), key, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	_ = lock.Close()
	_, err = New(context.Background(), Config{BaseURL: f.baseURL(), Username: "user", Password: "pass", OTPSecret: "GEZD GNBV GY3T QOJQ", Impersonate: "target-b", SessionCacheDir: dir})
	var authErr *AuthError
	if !errors.As(err, &authErr) || authErr.Kind != AuthKindRateLimited {
		t.Fatalf("New = %v, want cached rate-limit error", err)
	}
	if login, _, _ := f.counts(); login != 0 {
		t.Fatalf("login calls = %d, want zero before retry deadline", login)
	}
}

func TestRateLimitFromOneTargetBlocksAnother(t *testing.T) {
	var mu sync.Mutex
	logins := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		logins++
		mu.Unlock()
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, "rate limited")
	}))
	defer server.Close()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	newTarget := func(target string) *refresher {
		t.Helper()
		auth, err := newAuthenticator(server.URL+"/api/2.0/", "user", "pass", "GEZD GNBV GY3T QOJQ", target, "", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		auth.sleep = func(context.Context, time.Duration) error { return context.Canceled }
		r := newRefresher(auth)
		if err := r.configureStore(dir); err != nil {
			t.Fatal(err)
		}
		return r
	}
	first := newTarget("target-a")
	defer first.close()
	if err := first.initialize(context.Background()); err == nil {
		t.Fatal("first target should be rate limited")
	}
	second := newTarget("target-b")
	defer second.close()
	err := second.initialize(context.Background())
	var authErr *AuthError
	if !errors.As(err, &authErr) || authErr.Kind != AuthKindRateLimited {
		t.Fatalf("second target = %v, want shared rate limit", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if logins != 1 {
		t.Fatalf("login calls = %d, want one across targets", logins)
	}
}

func TestIneffectiveRecoveryCooldownSurvivesRestart(t *testing.T) {
	f := newFakeAPI(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{BaseURL: f.baseURL(), Username: "user", Password: "pass", OTPSecret: "GEZD GNBV GY3T QOJQ", SessionCacheDir: dir}
	client, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	f.mu.Lock()
	f.alwaysUnauthorized = true
	f.mu.Unlock()
	err = client.Get(context.Background(), "protected/", nil)
	var authErr *AuthError
	if !errors.As(err, &authErr) || authErr.Kind != AuthKindPersistentSessionLoss {
		t.Fatalf("first failure = %v", err)
	}
	_, err = New(context.Background(), cfg)
	if !errors.As(err, &authErr) || authErr.Kind != AuthKindPersistentSessionLoss {
		t.Fatalf("restart = %v, want persistent cooldown", err)
	}
	if login, _, _ := f.counts(); login != 2 {
		t.Fatalf("login calls = %d, want initial plus one recovery", login)
	}
}

func TestLateFailedReplayCannotCoolDownNewGeneration(t *testing.T) {
	var mu sync.Mutex
	logins := 0
	aReplayEntered := make(chan struct{})
	releaseA := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.RawQuery, "do=login"):
			mu.Lock()
			logins++
			session := logins
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: fmt.Sprintf("s%d", session), Path: "/"})
			_, _ = io.WriteString(w, `{}`)
		case strings.Contains(r.URL.RawQuery, "do=verify_otp"):
			_, _ = io.WriteString(w, `{}`)
		case strings.HasSuffix(r.URL.Path, "/protected/"):
			cookie, _ := r.Cookie("sessionid")
			session := ""
			if cookie != nil {
				session = cookie.Value
			}
			flow := r.URL.Query().Get("flow")
			if flow == "a" && session == "s2" {
				close(aReplayEntered)
				<-releaseA
			}
			if (flow == "b" && session == "s3") || (flow == "c" && session == "s4") {
				_, _ = io.WriteString(w, `{"ok":true}`)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "expired")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := New(context.Background(), Config{BaseURL: server.URL + "/api/2.0/", Username: "user", Password: "pass", OTPSecret: "GEZD GNBV GY3T QOJQ"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	aResult := make(chan error, 1)
	go func() { aResult <- client.Get(context.Background(), "protected/?flow=a", nil) }()
	<-aReplayEntered
	if err := client.Get(context.Background(), "protected/?flow=b", nil); err != nil {
		t.Fatalf("newer recovery: %v", err)
	}
	close(releaseA)
	var authErr *AuthError
	if err := <-aResult; !errors.As(err, &authErr) || authErr.Kind != AuthKindPersistentSessionLoss {
		t.Fatalf("late replay = %v", err)
	}
	if err := client.Get(context.Background(), "protected/?flow=c", nil); err != nil {
		t.Fatalf("recovery after late replay: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if logins != 4 {
		t.Fatalf("login calls = %d, want four generations", logins)
	}
}

func TestIneffectiveReplayReservesGenerationWhilePersisting(t *testing.T) {
	f := newFakeAPI(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	client, err := New(context.Background(), Config{
		BaseURL: f.baseURL(), Username: "user", Password: "pass",
		OTPSecret: "GEZD GNBV GY3T QOJQ", SessionCacheDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	r := client.refresher
	generation := r.currentGeneration()
	lock, err := r.store.LockAccount(context.Background(), r.storeKey)
	if err != nil {
		t.Fatal(err)
	}
	failure := &AuthError{Stage: AuthStageSessionRecovery, Kind: AuthKindPersistentSessionLoss}
	noted := make(chan error, 1)
	go func() { noted <- r.noteIneffective(context.Background(), generation, failure) }()
	deadline := time.After(5 * time.Second)
	for {
		r.mu.Lock()
		reserved := r.inFlight != nil
		r.mu.Unlock()
		if reserved {
			break
		}
		select {
		case <-deadline:
			_ = lock.Close()
			t.Fatal("ineffective replay did not reserve its generation")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	refreshResult := make(chan error, 1)
	go func() { refreshResult <- r.refresh(context.Background(), generation) }()
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-noted; err != nil {
		t.Fatal(err)
	}
	if err := <-refreshResult; !errors.Is(err, failure) {
		t.Fatalf("concurrent recovery = %v, want ineffective replay failure", err)
	}
	if logins, _, _ := f.counts(); logins != 1 {
		t.Fatalf("login calls = %d, want no concurrent recovery login", logins)
	}
}

func TestCanceledReplayDoesNotWaitForCooldownPersistence(t *testing.T) {
	f := newFakeAPI(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	client, err := New(context.Background(), Config{
		BaseURL: f.baseURL(), Username: "user", Password: "pass",
		OTPSecret: "GEZD GNBV GY3T QOJQ", SessionCacheDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	r := client.refresher
	generation := r.currentGeneration()
	lock, err := r.store.LockAccount(context.Background(), r.storeKey)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	failure := &AuthError{Stage: AuthStageSessionRecovery, Kind: AuthKindPersistentSessionLoss}
	go func() { result <- r.noteIneffective(ctx, generation, failure) }()
	deadline := time.After(5 * time.Second)
	for {
		r.mu.Lock()
		reserved := r.inFlight != nil
		r.mu.Unlock()
		if reserved {
			break
		}
		select {
		case <-deadline:
			t.Fatal("ineffective replay did not begin persistence")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled caller = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled caller waited for the account lock")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	deadline = time.After(5 * time.Second)
	for {
		r.mu.Lock()
		pending := r.inFlight != nil
		r.mu.Unlock()
		if !pending {
			break
		}
		select {
		case <-deadline:
			t.Fatal("cooldown persistence did not complete")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	record, err := r.store.Load(context.Background(), r.storeKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Cookies) != 0 || !record.RetryNotBefore.After(time.Now()) {
		t.Fatalf("persisted record = %#v, want invalidated session and future retry deadline", record)
	}
}

func TestWriteMethodsReplayOnlyOnceWithOriginalPayload(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			f := newFakeAPI(t)
			client := f.newClient(t)
			f.expire()
			var err error
			switch method {
			case http.MethodPost:
				err = client.Post(context.Background(), "protected/", map[string]any{"name": "drive", "size": 42}, nil)
			case http.MethodPut:
				err = client.Put(context.Background(), "protected/", map[string]any{"name": "drive", "size": 42}, nil)
			case http.MethodDelete:
				err = client.Delete(context.Background(), "protected/", nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, bodies, _ := f.observations()
			if len(bodies) != 2 || string(bodies[0]) != string(bodies[1]) {
				t.Fatalf("replay bodies = %q", bodies)
			}
			if login, _, calls := f.counts(); login != 2 || calls != 2 {
				t.Fatalf("login/operation calls = %d/%d, want 2/2", login, calls)
			}
		})
	}
}

func TestAuthEventsIncludeInitialHandshakeAndRecovery(t *testing.T) {
	f := newFakeAPI(t)
	var mu sync.Mutex
	var events []AuthEvent
	client, err := New(context.Background(), Config{
		BaseURL: f.baseURL(), Username: "user", Password: "secret-password",
		OTPSecret:   "GEZD GNBV GY3T QOJQ",
		OnAuthEvent: func(event AuthEvent) { mu.Lock(); events = append(events, event); mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	f.expire()
	if err := client.Get(context.Background(), "protected/", nil); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	initial, recovery := false, false
	for _, event := range events {
		if event.Type == AuthEventHandshakeStart {
			initial = true
		}
		if event.Type == AuthEventRecovery {
			recovery = true
		}
		if strings.Contains(event.Reason, "secret-password") || strings.Contains(event.Reason, "GEZD") {
			t.Fatalf("unsafe event = %#v", event)
		}
	}
	if !initial || !recovery {
		t.Fatalf("events = %#v, want handshake and recovery", events)
	}
}

func TestStaleCachedSessionParallelBurstRecovers(t *testing.T) {
	f := newFakeAPI(t)
	cacheDir := t.TempDir()
	if err := os.Chmod(cacheDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		BaseURL: f.baseURL(), Username: "user", Password: "pass",
		OTPSecret: "GEZD GNBV GY3T QOJQ", SessionCacheDir: cacheDir,
	}
	first, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	f.expire() // the cached cookie died overnight

	second, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	login, _, probes := f.counts()
	if login != 2 {
		t.Fatalf("login calls after stale restore = %d, want 2 (re-login before first use)", login)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 46)
	for i := 0; i < 46; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- second.Get(context.Background(), "protected/", nil)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Get after stale cache: %v", err)
		}
	}
	// No dead-cookie burst: each Get hits the API exactly once.
	if login, _, protected := f.counts(); login != 2 || protected-probes != 46 {
		t.Fatalf("login calls = %d, protected calls = %d, want 2 and 46", login, protected-probes)
	}
}
