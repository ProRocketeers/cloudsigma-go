package cloudsigma

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	currentSessionStoreVersion = 1
	maxSessionRecordBytes      = 1 << 20
	lockPollInterval           = 20 * time.Millisecond
	// DefaultSessionCookieTTL bounds reuse of a session cookie that the server
	// marked as a browser session cookie without persistent expiry.
	DefaultSessionCookieTTL = 30 * time.Minute
	MaxSessionCookieTTL     = 24 * time.Hour
)

var (
	// ErrSessionCacheUnsafe means the cache path, owner, permissions, or file
	// type cannot safely hold bearer session cookies.
	ErrSessionCacheUnsafe = errors.New("cloudsigma: unsafe session cache")
	// ErrSessionCacheNotFound means no entry exists for the requested key.
	ErrSessionCacheNotFound = errors.New("cloudsigma: session cache entry not found")
	// ErrSessionCacheCorrupt means an entry cannot be trusted or decoded.
	ErrSessionCacheCorrupt = errors.New("cloudsigma: corrupt session cache entry")
	// ErrSessionCacheCredentialMismatch means the entry was created for a
	// different credential fingerprint.
	ErrSessionCacheCredentialMismatch = errors.New("cloudsigma: session cache credential mismatch")
	// ErrSessionCookieNoExpiry means a cookie has no persistent expiry and
	// therefore cannot safely be restored after a process restart.
	ErrSessionCookieNoExpiry = errors.New("cloudsigma: session cookie has no persistent expiry")
	// ErrSessionExpired means all or part of a cached session has expired.
	ErrSessionExpired = errors.New("cloudsigma: cached session expired")
)

// Compatibility aliases keep the storage errors easy to discover for callers
// that use the shorter names.
var (
	ErrSessionNotFound           = ErrSessionCacheNotFound
	ErrSessionStoreUnsafe        = ErrSessionCacheUnsafe
	ErrSessionStoreCorrupt       = ErrSessionCacheCorrupt
	ErrSessionCredentialMismatch = ErrSessionCacheCredentialMismatch
)

// SessionKey identifies one restorable session. CredentialFingerprint must be
// produced from the current credentials and is compared with the persisted
// value; the password and OTP secret are never stored.
type SessionKey struct {
	Endpoint              string
	Username              string
	Impersonate           string
	CredentialFingerprint string
}

// CredentialFingerprint returns a stable, non-reversible binding for an
// endpoint and credential set. It is suitable for persisted metadata, but is
// deliberately excluded from cache filenames.
func CredentialFingerprint(endpoint, username, password, otpSecret string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, "cloudsigma-go/session-credential/v1\x00")
	for _, value := range []string{endpoint, username, password, otpSecret} {
		_, _ = io.WriteString(h, value)
		_, _ = io.WriteString(h, "\x00")
	}
	return hex.EncodeToString(h.Sum(nil))
}

// SessionCookie is the persistent subset of http.Cookie. Raw and unparsed
// attributes are intentionally omitted; only attributes needed to restore
// the cookie's scope and expiry are retained.
type SessionCookie struct {
	Name        string        `json:"name"`
	Value       string        `json:"value"`
	Path        string        `json:"path,omitempty"`
	Domain      string        `json:"domain,omitempty"`
	HostOnly    bool          `json:"host_only,omitempty"`
	Expires     time.Time     `json:"expires"`
	MaxAge      int           `json:"max_age,omitempty"`
	Secure      bool          `json:"secure,omitempty"`
	HTTPOnly    bool          `json:"http_only,omitempty"`
	SameSite    http.SameSite `json:"same_site,omitempty"`
	LocalExpiry bool          `json:"local_expiry,omitempty"`
}

// NewSessionCookie converts a cookie from an authenticated jar into the
// persisted representation. Session cookies without Expires or positive
// MaxAge are rejected because they cannot be safely reused after restart.
func NewSessionCookie(cookie http.Cookie, now time.Time) (SessionCookie, error) {
	return newSessionCookie(cookie, now, 0)
}

// NewSessionCookieWithTTL converts a cookie and assigns a bounded local
// expiry when the server provided a session cookie without one. The synthetic
// expiry is persisted as LocalExpiry so operators can distinguish it from a
// server-directed expiry when diagnosing cache behavior.
func NewSessionCookieWithTTL(cookie http.Cookie, now time.Time, ttl time.Duration) (SessionCookie, error) {
	return newSessionCookie(cookie, now, ttl)
}

func newSessionCookie(cookie http.Cookie, now time.Time, ttl time.Duration) (SessionCookie, error) {
	if now.IsZero() {
		now = time.Now()
	}
	if cookie.Expires.IsZero() && cookie.MaxAge <= 0 {
		if ttl <= 0 || ttl > MaxSessionCookieTTL {
			return SessionCookie{}, ErrSessionCookieNoExpiry
		}
	}
	stored := SessionCookie{
		Name:        cookie.Name,
		Value:       cookie.Value,
		Path:        cookie.Path,
		Domain:      cookie.Domain,
		Expires:     cookie.Expires,
		MaxAge:      cookie.MaxAge,
		Secure:      cookie.Secure,
		HTTPOnly:    cookie.HttpOnly,
		SameSite:    cookie.SameSite,
		LocalExpiry: cookie.Expires.IsZero() && cookie.MaxAge <= 0,
	}
	if stored.Expires.IsZero() {
		if cookie.MaxAge <= 0 {
			stored.Expires = now.Add(ttl)
		} else {
			if int64(cookie.MaxAge) > maxCookieAgeSeconds {
				return SessionCookie{}, ErrSessionCookieNoExpiry
			}
			stored.Expires = now.Add(time.Duration(cookie.MaxAge) * time.Second)
		}
	}
	if err := validateSessionCookie(stored, now); err != nil {
		return SessionCookie{}, err
	}
	return stored, nil
}

// ToHTTPCookie converts a persisted cookie for insertion into an http.CookieJar.
func (c SessionCookie) ToHTTPCookie() http.Cookie {
	domain := c.Domain
	if c.HostOnly {
		domain = ""
	}
	return http.Cookie{
		Name:    c.Name,
		Value:   c.Value,
		Path:    c.Path,
		Domain:  domain,
		Expires: c.Expires,
		// MaxAge is relative to receipt time. Restoring it would extend the
		// session each time; the stored absolute Expires is authoritative.
		MaxAge:   0,
		Secure:   c.Secure,
		HttpOnly: c.HTTPOnly,
		SameSite: c.SameSite,
	}
}

// SessionRecord is the complete persisted session state. It contains no
// password, OTP secret, authorization header, or account secret beyond the
// intentionally persisted bearer cookie values.
type SessionRecord struct {
	Version               int             `json:"version"`
	Endpoint              string          `json:"endpoint"`
	Username              string          `json:"username"`
	CredentialFingerprint string          `json:"credential_fingerprint"`
	Impersonate           string          `json:"impersonate,omitempty"`
	Cookies               []SessionCookie `json:"cookies"`
	Generation            uint64          `json:"generation"`
	RetryNotBefore        time.Time       `json:"retry_not_before,omitempty"`
}

// FileSessionStore stores opt-in sessions in a private local directory.
// Construct it with NewFileSessionStore when eager validation is useful, or
// initialize Dir directly and let each operation validate it.
type FileSessionStore struct {
	Dir string
	Now func() time.Time
}

// NewFileSessionStore creates and validates a private cache directory.
func NewFileSessionStore(dir string) (*FileSessionStore, error) {
	store := &FileSessionStore{Dir: dir}
	if err := store.ensureDir(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *FileSessionStore) now() time.Time {
	if s != nil && s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Load reads and validates an entry. Callers should acquire the appropriate
// account lock before loading when coordinating authentication.
func (s *FileSessionStore) Load(ctx context.Context, key SessionKey) (SessionRecord, error) {
	if err := contextErr(ctx); err != nil {
		return SessionRecord{}, err
	}
	path, err := s.entryPath(key)
	if err != nil {
		return SessionRecord{}, err
	}
	payload, err := readPrivateFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return SessionRecord{}, ErrSessionCacheNotFound
		}
		return SessionRecord{}, err
	}
	var record SessionRecord
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return SessionRecord{}, fmt.Errorf("%w: invalid JSON", ErrSessionCacheCorrupt)
	}
	if err := validateSessionRecord(key, &record, s.now()); err != nil {
		if errors.Is(err, ErrSessionExpired) {
			return record, err
		}
		return SessionRecord{}, err
	}
	return record, nil
}

// Save validates and atomically replaces an entry. The target is never
// followed when it is a symlink, and temporary files are created in the same
// private directory before rename.
func (s *FileSessionStore) Save(ctx context.Context, key SessionKey, record SessionRecord) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	path, err := s.entryPath(key)
	if err != nil {
		return err
	}
	now := s.now()
	if record.Version == 0 {
		record.Version = currentSessionStoreVersion
	}
	if record.Endpoint == "" {
		record.Endpoint = key.Endpoint
	}
	if record.Username == "" {
		record.Username = key.Username
	}
	if record.Impersonate == "" {
		record.Impersonate = key.Impersonate
	}
	if record.CredentialFingerprint == "" {
		record.CredentialFingerprint = key.CredentialFingerprint
	}
	if err := validateSessionRecord(key, &record, now); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: encode failed", ErrSessionCacheCorrupt)
	}
	payload = append(payload, '\n')

	if err := validateExistingEntry(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, ".session-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: create temporary entry", ErrSessionCacheUnsafe)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0600); err != nil {
		return fmt.Errorf("%w: secure temporary entry", ErrSessionCacheUnsafe)
	}
	if _, err := tmp.Write(payload); err != nil {
		return fmt.Errorf("%w: write temporary entry", ErrSessionCacheUnsafe)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("%w: sync temporary entry", ErrSessionCacheUnsafe)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%w: close temporary entry", ErrSessionCacheUnsafe)
	}
	if err := validateTempFile(tmpPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("%w: replace session entry", ErrSessionCacheUnsafe)
	}
	return syncDirectory(s.Dir)
}

// SessionLockScope separates account authentication from target-specific
// session state. Account locks intentionally omit impersonation, so different
// targets using one account serialize OTP-consuming authentication.
type SessionLockScope string

const (
	SessionLockAccount SessionLockScope = "account"
	SessionLockEntry   SessionLockScope = "entry"
)

// SessionLockKey identifies a lock scope. CredentialFingerprint is not part of
// a lock identity: changed credentials must still coordinate on the same
// account lock before replacing a stale entry.
type SessionLockKey struct {
	Endpoint    string
	Username    string
	Impersonate string
	Scope       SessionLockScope
}

// Lock acquires a context-aware exclusive OS lock.
func (s *FileSessionStore) Lock(ctx context.Context, key SessionLockKey) (*SessionLock, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if err := key.validate(); err != nil {
		return nil, err
	}
	if err := s.ensureDir(); err != nil {
		return nil, err
	}
	path := s.lockPath(key)
	file, err := openLockFile(path)
	if err != nil {
		return nil, err
	}
	lock := &SessionLock{file: file, path: path}
	for {
		if err := contextErr(ctx); err != nil {
			_ = lock.Close()
			return nil, err
		}
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = lock.Close()
			return nil, fmt.Errorf("%w: acquire lock", ErrSessionCacheUnsafe)
		}
		timer := time.NewTimer(lockPollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = lock.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// LockAccount serializes authentication for an endpoint and authenticating
// identity, including different impersonation targets.
func (s *FileSessionStore) LockAccount(ctx context.Context, key SessionKey) (*SessionLock, error) {
	return s.Lock(ctx, SessionLockKey{Endpoint: key.Endpoint, Username: key.Username, Scope: SessionLockAccount})
}

// LockEntry serializes access to one endpoint, identity, and impersonation
// target cache entry.
func (s *FileSessionStore) LockEntry(ctx context.Context, key SessionKey) (*SessionLock, error) {
	return s.Lock(ctx, SessionLockKey{Endpoint: key.Endpoint, Username: key.Username, Impersonate: key.Impersonate, Scope: SessionLockEntry})
}

// SessionLock releases an OS lock. Close is idempotent.
type SessionLock struct {
	file *os.File
	path string
	once sync.Once
	err  error
}

func (l *SessionLock) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.file == nil {
			return
		}
		if err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN); err != nil {
			l.err = err
		}
		if err := l.file.Close(); l.err == nil {
			l.err = err
		}
	})
	return l.err
}

func (k SessionLockKey) validate() error {
	if strings.TrimSpace(k.Endpoint) == "" || strings.TrimSpace(k.Username) == "" {
		return fmt.Errorf("%w: endpoint and username are required for a lock", ErrSessionCacheUnsafe)
	}
	if k.Scope != SessionLockAccount && k.Scope != SessionLockEntry {
		return fmt.Errorf("%w: unknown session lock scope", ErrSessionCacheUnsafe)
	}
	return nil
}

func (s *FileSessionStore) entryPath(key SessionKey) (string, error) {
	if err := key.validate(); err != nil {
		return "", err
	}
	if strings.TrimSpace(key.CredentialFingerprint) == "" {
		return "", fmt.Errorf("%w: credential fingerprint is required", ErrSessionCacheCredentialMismatch)
	}
	if err := s.ensureDir(); err != nil {
		return "", err
	}
	material := strings.Join([]string{"entry", key.Endpoint, key.Username, key.Impersonate}, "\x00")
	hash := sha256.Sum256([]byte(material))
	return filepath.Join(s.Dir, "session-"+hex.EncodeToString(hash[:])+".json"), nil
}

func (s *FileSessionStore) lockPath(key SessionLockKey) string {
	impersonate := ""
	if key.Scope == SessionLockEntry {
		impersonate = key.Impersonate
	}
	material := strings.Join([]string{string(key.Scope), key.Endpoint, key.Username, impersonate}, "\x00")
	hash := sha256.Sum256([]byte(material))
	return filepath.Join(s.Dir, ".lock-"+hex.EncodeToString(hash[:])+".lck")
}

func (s *FileSessionStore) ensureDir() error {
	if s == nil || strings.TrimSpace(s.Dir) == "" || !filepath.IsAbs(s.Dir) {
		return fmt.Errorf("%w: cache directory must be an absolute path", ErrSessionCacheUnsafe)
	}
	dir := filepath.Clean(s.Dir)
	if err := rejectSymlinkComponents(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("%w: create cache directory", ErrSessionCacheUnsafe)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%w: inspect cache directory", ErrSessionCacheUnsafe)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0700 || !ownedByCurrentUser(info) {
		return fmt.Errorf("%w: cache directory must be an owned 0700 directory", ErrSessionCacheUnsafe)
	}
	return nil
}

func (k SessionKey) validate() error {
	if strings.TrimSpace(k.Endpoint) == "" || strings.TrimSpace(k.Username) == "" || strings.ContainsRune(k.Username, '\x00') || strings.ContainsRune(k.Endpoint, '\x00') {
		return fmt.Errorf("%w: endpoint and username are required", ErrSessionCacheUnsafe)
	}
	return nil
}

func validateSessionRecord(key SessionKey, record *SessionRecord, now time.Time) error {
	if record == nil || record.Version != currentSessionStoreVersion {
		return fmt.Errorf("%w: unsupported session record version", ErrSessionCacheCorrupt)
	}
	if record.Endpoint != key.Endpoint || record.Username != key.Username || record.Impersonate != key.Impersonate {
		return ErrSessionCacheCredentialMismatch
	}
	if record.CredentialFingerprint == "" || record.CredentialFingerprint != key.CredentialFingerprint {
		return ErrSessionCacheCredentialMismatch
	}
	if len(record.Cookies) == 0 && record.RetryNotBefore.IsZero() {
		return fmt.Errorf("%w: session has no cookies", ErrSessionCacheCorrupt)
	}
	for _, cookie := range record.Cookies {
		if err := validateSessionCookie(cookie, now); err != nil {
			return err
		}
	}
	return nil
}

const maxCookieAgeSeconds = int64((1<<63 - 1) / int64(time.Second))

func validateSessionCookie(cookie SessionCookie, now time.Time) error {
	if cookie.Name == "" || strings.ContainsAny(cookie.Name, "\r\n\x00") {
		return fmt.Errorf("%w: invalid cookie name", ErrSessionCacheCorrupt)
	}
	if cookie.Expires.IsZero() {
		return ErrSessionCookieNoExpiry
	}
	if !now.IsZero() && !cookie.Expires.After(now) {
		return ErrSessionExpired
	}
	if cookie.MaxAge < 0 || int64(cookie.MaxAge) > maxCookieAgeSeconds {
		return fmt.Errorf("%w: invalid cookie lifetime", ErrSessionCacheCorrupt)
	}
	httpCookie := cookie.ToHTTPCookie()
	if err := httpCookie.Valid(); err != nil {
		return fmt.Errorf("%w: invalid cookie attributes", ErrSessionCacheCorrupt)
	}
	return nil
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint32(os.Getuid()) == stat.Uid
}

func rejectSymlinkComponents(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: cache path contains a symlink", ErrSessionCacheUnsafe)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: inspect cache path", ErrSessionCacheUnsafe)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func readPrivateFile(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: cache entry is a symlink", ErrSessionCacheUnsafe)
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: inspect cache entry", ErrSessionCacheUnsafe)
	}
	if err := validatePrivateFileInfo(info); err != nil {
		return nil, err
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxSessionRecordBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read cache entry", ErrSessionCacheCorrupt)
	}
	if len(payload) > maxSessionRecordBytes {
		return nil, fmt.Errorf("%w: cache entry is too large", ErrSessionCacheCorrupt)
	}
	return payload, nil
}

func validatePrivateFileInfo(info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ownedByCurrentUser(info) {
		return fmt.Errorf("%w: cache file must be an owned 0600 regular file", ErrSessionCacheUnsafe)
	}
	return nil
}

func validateExistingEntry(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: cache entry is a symlink", ErrSessionCacheUnsafe)
	}
	return validatePrivateFileInfo(info)
}

func validateTempFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: inspect temporary entry", ErrSessionCacheUnsafe)
	}
	return validatePrivateFileInfo(info)
}

func openLockFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: lock file is a symlink", ErrSessionCacheUnsafe)
		}
		return nil, fmt.Errorf("%w: open lock file", ErrSessionCacheUnsafe)
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ownedByCurrentUser(info) {
		_ = file.Close()
		return nil, fmt.Errorf("%w: lock file must be an owned 0600 regular file", ErrSessionCacheUnsafe)
	}
	return file, nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%w: open cache directory", ErrSessionCacheUnsafe)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("%w: sync cache directory", ErrSessionCacheUnsafe)
	}
	return nil
}
