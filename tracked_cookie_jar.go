package cloudsigma

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// TrackedCookieJar wraps a normal http.CookieJar while retaining the cookie
// attributes that CookieJar.Cookies intentionally omits. Use
// PersistentCookies to build a SessionRecord; Cookies continues to satisfy
// net/http's request-time interface.
type TrackedCookieJar struct {
	jar http.CookieJar
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	cookies map[trackedCookieKey]SessionCookie
}

type trackedCookieKey struct {
	name   string
	domain string
	path   string
}

// NewTrackedCookieJar wraps jar with the default bounded local TTL for
// server session cookies that have no persistent expiry. A nil jar creates a
// standard cookie jar.
func NewTrackedCookieJar(jar http.CookieJar) *TrackedCookieJar {
	tracked, err := NewTrackedCookieJarWithTTL(jar, DefaultSessionCookieTTL)
	if err != nil {
		// The default is a package constant and therefore cannot fail. Keep the
		// fallback defensive if that invariant changes in a future release.
		return &TrackedCookieJar{jar: jar, ttl: DefaultSessionCookieTTL, cookies: make(map[trackedCookieKey]SessionCookie)}
	}
	return tracked
}

// NewTrackedCookieJarWithTTL creates a tracked jar with an explicit bounded
// local lifetime for cookies lacking server-provided expiry.
func NewTrackedCookieJarWithTTL(jar http.CookieJar, ttl time.Duration) (*TrackedCookieJar, error) {
	if ttl <= 0 || ttl > MaxSessionCookieTTL {
		return nil, errors.New("cloudsigma: tracked cookie TTL must be within (0, 24h]")
	}
	if jar == nil {
		var err error
		jar, err = cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
	}
	return &TrackedCookieJar{
		jar:     jar,
		ttl:     ttl,
		now:     time.Now,
		cookies: make(map[trackedCookieKey]SessionCookie),
	}, nil
}

// CookieJar returns the wrapped request-time jar for callers that need its
// concrete implementation.
func (j *TrackedCookieJar) CookieJar() http.CookieJar {
	if j == nil {
		return nil
	}
	return j.jar
}

// Cookies implements http.CookieJar. Request-time behavior remains delegated
// to the wrapped jar; tracked attributes are available through
// PersistentCookies.
func (j *TrackedCookieJar) Cookies(u *url.URL) []*http.Cookie {
	if j == nil || j.jar == nil {
		return nil
	}
	return j.jar.Cookies(u)
}

// SetCookies implements http.CookieJar and records each accepted cookie's
// scope and expiry before delegating to the wrapped jar.
func (j *TrackedCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if j == nil || j.jar == nil {
		return
	}
	now := j.currentTime()
	tracked := make([]SessionCookie, 0, len(cookies))
	keys := make([]trackedCookieKey, 0, len(cookies))
	remove := make([]trackedCookieKey, 0)
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}
		copyCookie := *cookie
		domain := cookieDomain(u, copyCookie.Domain)
		path := copyCookie.Path
		if path == "" {
			path = defaultCookiePath(u)
		}
		key := trackedCookieKey{name: copyCookie.Name, domain: domain, path: path}
		if copyCookie.MaxAge < 0 || (copyCookie.MaxAge <= 0 && !copyCookie.Expires.IsZero() && !copyCookie.Expires.After(now)) {
			remove = append(remove, key)
			continue
		}
		stored, err := NewSessionCookieWithTTL(copyCookie, now, j.ttl)
		if err != nil {
			continue
		}
		stored.Domain = domain
		stored.HostOnly = copyCookie.Domain == ""
		stored.Path = path
		tracked = append(tracked, stored)
		keys = append(keys, key)
	}

	j.mu.Lock()
	for _, key := range remove {
		delete(j.cookies, key)
	}
	for index, key := range keys {
		j.cookies[key] = tracked[index]
	}
	j.mu.Unlock()

	// Do not hold the tracking lock while entering a caller-provided jar.
	j.jar.SetCookies(u, cookies)
}

// PersistentCookies returns a stable snapshot of tracked cookies with valid
// local or server-provided expiry. The returned values are safe to place in a
// SessionRecord.
func (j *TrackedCookieJar) PersistentCookies(now time.Time) ([]SessionCookie, error) {
	if j == nil {
		return nil, nil
	}
	if now.IsZero() {
		now = j.currentTime()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	result := make([]SessionCookie, 0, len(j.cookies))
	for key, cookie := range j.cookies {
		if !cookie.Expires.After(now) {
			delete(j.cookies, key)
			continue
		}
		if err := validateSessionCookie(cookie, now); err != nil {
			return nil, err
		}
		result = append(result, cookie)
	}
	sort.Slice(result, func(i, k int) bool {
		if result[i].Domain != result[k].Domain {
			return result[i].Domain < result[k].Domain
		}
		if result[i].Path != result[k].Path {
			return result[i].Path < result[k].Path
		}
		return result[i].Name < result[k].Name
	})
	return result, nil
}

// Restore validates and installs persisted cookies into both the tracker and
// its wrapped jar. Cookie scope is reconstructed from each stored Domain and
// Path; host-only cookies retain their host-only flag.
func (j *TrackedCookieJar) Restore(cookies []SessionCookie) error {
	if j == nil || j.jar == nil {
		return errors.New("cloudsigma: nil tracked cookie jar")
	}
	now := j.currentTime()
	type restoredCookie struct {
		key    trackedCookieKey
		cookie SessionCookie
		url    *url.URL
	}
	restored := make([]restoredCookie, 0, len(cookies))
	for _, cookie := range cookies {
		if err := validateSessionCookie(cookie, now); err != nil {
			return err
		}
		domain := strings.TrimPrefix(strings.ToLower(cookie.Domain), ".")
		if domain == "" {
			return errors.New("cloudsigma: persisted cookie has no domain")
		}
		path := cookie.Path
		if path == "" {
			path = "/"
		}
		copyCookie := cookie
		copyCookie.Path = path
		restored = append(restored, restoredCookie{
			key:    trackedCookieKey{name: cookie.Name, domain: domain, path: path},
			cookie: copyCookie,
			url:    &url.URL{Scheme: "https", Host: domain, Path: path},
		})
	}

	j.mu.Lock()
	for _, item := range restored {
		j.cookies[item.key] = item.cookie
	}
	j.mu.Unlock()
	for _, item := range restored {
		httpCookie := item.cookie.ToHTTPCookie()
		if item.cookie.HostOnly {
			httpCookie.Domain = ""
		}
		j.jar.SetCookies(item.url, []*http.Cookie{&httpCookie})
	}
	return nil
}

// SessionCookies is an alias that reads naturally at integration call sites.
func (j *TrackedCookieJar) SessionCookies(now time.Time) ([]SessionCookie, error) {
	return j.PersistentCookies(now)
}

func (j *TrackedCookieJar) currentTime() time.Time {
	if j != nil && j.now != nil {
		return j.now()
	}
	return time.Now()
}

func cookieDomain(u *url.URL, domain string) string {
	if domain != "" {
		return strings.TrimPrefix(strings.ToLower(domain), ".")
	}
	if u == nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func defaultCookiePath(u *url.URL) string {
	if u == nil || u.Path == "" || u.Path[0] != '/' {
		return "/"
	}
	if index := strings.LastIndex(u.Path, "/"); index > 0 {
		return u.Path[:index]
	}
	return "/"
}
