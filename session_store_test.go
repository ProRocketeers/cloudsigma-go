package cloudsigma

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileSessionStoreLockProcessHelper(t *testing.T) {
	dir := os.Getenv("CLOUDSIGMA_TEST_LOCK_DIR")
	if dir == "" {
		return
	}
	store, err := NewFileSessionStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := store.LockAccount(context.Background(), SessionKey{Endpoint: "https://api.example.test/", Username: "user"})
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	_, _ = os.Stdout.WriteString("locked\n")
	time.Sleep(time.Minute)
}

func TestFileSessionStoreLockReleasedOnProcessDeath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestFileSessionStoreLockProcessHelper$")
	cmd.Env = append(os.Environ(), "CLOUDSIGMA_TEST_LOCK_DIR="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "locked" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("lock helper did not acquire lock: %v", scanner.Err())
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	store, err := NewFileSessionStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lock, err := store.LockAccount(ctx, SessionKey{Endpoint: "https://api.example.test/", Username: "user"})
	if err != nil {
		t.Fatalf("lock remained held after process death: %v", err)
	}
	_ = lock.Close()
}

func testSessionStore(t *testing.T) (*FileSessionStore, SessionKey, time.Time) {
	t.Helper()
	now := time.Date(2036, time.January, 2, 3, 4, 5, 0, time.UTC)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileSessionStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.Now = func() time.Time { return now }
	key := SessionKey{
		Endpoint:              "https://api.example.test/api/2.0/",
		Username:              "user@example.test",
		Impersonate:           "target-a",
		CredentialFingerprint: CredentialFingerprint("https://api.example.test/api/2.0/", "user@example.test", "password", "otp-secret"),
	}
	return store, key, now
}

func testSessionRecord(key SessionKey, now time.Time) SessionRecord {
	return SessionRecord{
		Endpoint:              key.Endpoint,
		Username:              key.Username,
		Impersonate:           key.Impersonate,
		CredentialFingerprint: key.CredentialFingerprint,
		Generation:            7,
		RetryNotBefore:        now.Add(11 * time.Second),
		Cookies: []SessionCookie{
			{Name: "sessionid", Value: "session-cookie", Domain: "api.example.test", Path: "/", Expires: now.Add(time.Hour), HTTPOnly: true, Secure: true},
			{Name: "csrftoken", Value: "csrf-cookie", Domain: "api.example.test", Path: "/api/2.0/", Expires: now.Add(time.Hour), Secure: true},
		},
	}
}

func TestFileSessionStoreRoundTripAndPermissions(t *testing.T) {
	store, key, now := testSessionStore(t)
	record := testSessionRecord(key, now)
	if err := store.Save(context.Background(), key, record); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := store.Load(context.Background(), key)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Generation != record.Generation || !got.RetryNotBefore.Equal(record.RetryNotBefore) {
		t.Fatalf("metadata = %#v, want generation %d and retry time %s", got, record.Generation, record.RetryNotBefore)
	}
	if len(got.Cookies) != 2 || got.Cookies[0].Value == "" || got.Cookies[1].Value == "" {
		t.Fatalf("cookies = %#v, want two bearer cookies", got.Cookies)
	}

	dirInfo, err := os.Stat(store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Errorf("cache directory mode = %o, want 0700", dirInfo.Mode().Perm())
	}
	entries, err := os.ReadDir(store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("cache entries = %d, want one session file", len(entries))
	}
	entryInfo, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if entryInfo.Mode().Perm() != 0600 {
		t.Errorf("session file mode = %o, want 0600", entryInfo.Mode().Perm())
	}
	if strings.Contains(entries[0].Name(), key.CredentialFingerprint) || strings.Contains(entries[0].Name(), "password") || strings.Contains(entries[0].Name(), "otp-secret") {
		t.Errorf("cache filename %q exposes credential material", entries[0].Name())
	}

	payload, err := os.ReadFile(filepath.Join(store.Dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "password") || strings.Contains(string(payload), "otp-secret") {
		t.Errorf("cache payload contains password or OTP secret: %q", payload)
	}
}

func TestFileSessionStoreBindsCredentialAndIdentity(t *testing.T) {
	store, key, now := testSessionStore(t)
	if err := store.Save(context.Background(), key, testSessionRecord(key, now)); err != nil {
		t.Fatal(err)
	}
	changed := key
	changed.CredentialFingerprint = CredentialFingerprint(key.Endpoint, key.Username, "changed-password", "otp-secret")
	if _, err := store.Load(context.Background(), changed); !errors.Is(err, ErrSessionCacheCredentialMismatch) {
		t.Fatalf("changed credentials: error = %v, want credential mismatch", err)
	}
	otherTarget := key
	otherTarget.Impersonate = "target-b"
	if _, err := store.Load(context.Background(), otherTarget); !errors.Is(err, ErrSessionCacheNotFound) {
		t.Fatalf("other impersonation target: error = %v, want not found", err)
	}
}

func TestFileSessionStoreRejectsUnexpiredRequirementAndExpiry(t *testing.T) {
	store, key, now := testSessionStore(t)
	noExpiry := testSessionRecord(key, now)
	noExpiry.Cookies[0].Expires = time.Time{}
	if err := store.Save(context.Background(), key, noExpiry); !errors.Is(err, ErrSessionCookieNoExpiry) {
		t.Fatalf("Save without expiry: error = %v, want no-expiry error", err)
	}

	if err := store.Save(context.Background(), key, testSessionRecord(key, now)); err != nil {
		t.Fatal(err)
	}
	store.Now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, err := store.Load(context.Background(), key); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expired Load: error = %v, want expired error", err)
	}
}

func TestFileSessionStorePreservesCooldownMetadataWithoutCookies(t *testing.T) {
	store, key, now := testSessionStore(t)
	record := SessionRecord{
		Endpoint:              key.Endpoint,
		Username:              key.Username,
		Impersonate:           key.Impersonate,
		CredentialFingerprint: key.CredentialFingerprint,
		Generation:            12,
		RetryNotBefore:        now.Add(time.Minute),
	}
	if err := store.Save(context.Background(), key, record); err != nil {
		t.Fatalf("Save cooldown-only record: %v", err)
	}
	got, err := store.Load(context.Background(), key)
	if err != nil {
		t.Fatalf("Load cooldown-only record: %v", err)
	}
	if got.Generation != record.Generation || !got.RetryNotBefore.Equal(record.RetryNotBefore) || len(got.Cookies) != 0 {
		t.Fatalf("cooldown-only record = %#v, want generation and retry metadata", got)
	}
}

func TestFileSessionStoreLoadReturnsExpiredRecordMetadata(t *testing.T) {
	store, key, now := testSessionStore(t)
	record := testSessionRecord(key, now)
	record.Generation = 13
	record.RetryNotBefore = now.Add(10 * time.Minute)
	if err := store.Save(context.Background(), key, record); err != nil {
		t.Fatal(err)
	}
	store.Now = func() time.Time { return now.Add(2 * time.Hour) }
	got, err := store.Load(context.Background(), key)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Load expired record: error = %v, want expired", err)
	}
	if got.Generation != record.Generation || !got.RetryNotBefore.Equal(record.RetryNotBefore) {
		t.Fatalf("expired record metadata = %#v, want it preserved with error", got)
	}
}

func TestFileSessionStoreRejectsUnsafeDirectoryAndEntry(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileSessionStore(dir); !errors.Is(err, ErrSessionCacheUnsafe) {
		t.Fatalf("insecure directory: error = %v, want unsafe error", err)
	}

	store, key, now := testSessionStore(t)
	if err := store.Save(context.Background(), key, testSessionRecord(key, now)); err != nil {
		t.Fatal(err)
	}
	path, err := store.entryPath(key)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(store.Dir, "outside")
	if err := os.WriteFile(target, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := store.Load(context.Background(), key); !errors.Is(err, ErrSessionCacheUnsafe) {
		t.Fatalf("symlink entry: error = %v, want unsafe error", err)
	}
}

func TestFileSessionStoreLocksSeparateScopesAndHonorsContext(t *testing.T) {
	store, key, _ := testSessionStore(t)
	account, err := store.LockAccount(context.Background(), key)
	if err != nil {
		t.Fatalf("LockAccount: %v", err)
	}
	defer account.Close()

	other := key
	other.Impersonate = "target-b"
	entry, err := store.LockEntry(context.Background(), other)
	if err != nil {
		t.Fatalf("different target entry lock: %v", err)
	}
	if err := entry.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := store.LockAccount(ctx, other); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("same account lock: error = %v, want context deadline", err)
	}

	entryA, err := store.LockEntry(context.Background(), key)
	if err != nil {
		t.Fatalf("LockEntry: %v", err)
	}
	defer entryA.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := store.LockEntry(ctx, key); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("same entry lock: error = %v, want context deadline", err)
	}
}

func TestFileSessionStoreCorruptAndCanceled(t *testing.T) {
	store, key, _ := testSessionStore(t)
	if _, err := store.Load(context.Background(), key); !errors.Is(err, ErrSessionCacheNotFound) {
		t.Fatalf("missing Load: error = %v, want not found", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Load(ctx, key); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Load: error = %v, want context canceled", err)
	}
	if err := store.Save(ctx, key, testSessionRecord(key, store.now())); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Save: error = %v, want context canceled", err)
	}

	if err := store.Save(context.Background(), key, testSessionRecord(key, store.now())); err != nil {
		t.Fatal(err)
	}
	path, err := store.entryPath(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background(), key); !errors.Is(err, ErrSessionCacheCorrupt) {
		t.Fatalf("corrupt Load: error = %v, want corrupt error", err)
	}
}

func TestCredentialFingerprintDoesNotExposeInputs(t *testing.T) {
	fingerprint := CredentialFingerprint("https://example.test", "user@example.test", "password", "otp-secret")
	if len(fingerprint) != 64 {
		t.Fatalf("fingerprint length = %d, want 64 hex characters", len(fingerprint))
	}
	if strings.Contains(fingerprint, "password") || strings.Contains(fingerprint, "otp-secret") {
		t.Fatalf("fingerprint exposes credential input: %q", fingerprint)
	}
}

func TestNewSessionCookieWithBoundedTTL(t *testing.T) {
	now := time.Date(2036, time.January, 2, 3, 4, 5, 0, time.UTC)
	cookie, err := NewSessionCookieWithTTL(http.Cookie{Name: "sessionid", Value: "value", Path: "/"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !cookie.LocalExpiry || !cookie.Expires.Equal(now.Add(time.Hour)) {
		t.Fatalf("synthetic cookie expiry = %#v, want one hour local expiry", cookie)
	}
	if _, err := NewSessionCookieWithTTL(http.Cookie{Name: "sessionid", Value: "value"}, now, 25*time.Hour); !errors.Is(err, ErrSessionCookieNoExpiry) {
		t.Fatalf("overlong TTL: error = %v, want no-expiry error", err)
	}
}

func TestNewSessionCookieUsesMaxAgeOverExpires(t *testing.T) {
	now := time.Date(2036, time.January, 2, 3, 4, 5, 0, time.UTC)
	cookie, err := NewSessionCookie(http.Cookie{
		Name:    "sessionid",
		Value:   "value",
		Path:    "/",
		Expires: now.Add(-24 * time.Hour),
		MaxAge:  60,
	}, now)
	if err != nil {
		t.Fatalf("NewSessionCookie: %v", err)
	}
	wantExpiry := now.Add(time.Minute)
	if !cookie.Expires.Equal(wantExpiry) {
		t.Fatalf("expiry = %s, want Max-Age deadline %s", cookie.Expires, wantExpiry)
	}
	if cookie.LocalExpiry {
		t.Fatal("Max-Age cookie was marked as a local expiry")
	}

	// Restoration must use the stored absolute deadline. Reapplying Max-Age
	// here would extend the session on every process restart.
	restored := cookie.ToHTTPCookie()
	if restored.MaxAge != 0 {
		t.Fatalf("restored MaxAge = %d, want omitted", restored.MaxAge)
	}
	if !restored.Expires.Equal(wantExpiry) {
		t.Fatalf("restored expiry = %s, want %s", restored.Expires, wantExpiry)
	}

	persisted := cookie
	persisted.Domain = "api.example.test"
	persisted.HostOnly = true
	restoredJar := NewTrackedCookieJar(nil)
	restoredJar.now = func() time.Time { return now.Add(30 * time.Second) }
	if err := restoredJar.Restore([]SessionCookie{persisted}); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	restoredCookies, err := restoredJar.PersistentCookies(now.Add(30 * time.Second))
	if err != nil {
		t.Fatalf("PersistentCookies after restore: %v", err)
	}
	if len(restoredCookies) != 1 || !restoredCookies[0].Expires.Equal(wantExpiry) {
		t.Fatalf("restored tracked cookie = %#v, want expiry %s", restoredCookies, wantExpiry)
	}
}
