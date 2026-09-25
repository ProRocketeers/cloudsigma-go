package cloudsigma

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"
)

func TestTrackedCookieJarRetainsScopeExpiryAndRestores(t *testing.T) {
	now := time.Date(2036, time.January, 2, 3, 4, 5, 0, time.UTC)
	base, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	tracked, err := NewTrackedCookieJarWithTTL(base, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tracked.now = func() time.Time { return now }
	endpoint, _ := url.Parse("https://api.example.test/api/2.0/accounts/action/")
	tracked.SetCookies(endpoint, []*http.Cookie{
		{Name: "sessionid", Value: "session", Path: "/", Expires: now.Add(2 * time.Hour), Secure: true, HttpOnly: true},
		{Name: "csrftoken", Value: "csrf", Path: "/api/2.0/", Expires: now.Add(2 * time.Hour), Secure: true},
		{Name: "browser_session", Value: "temporary", Path: "/"},
	})

	cookies, err := tracked.PersistentCookies(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 3 {
		t.Fatalf("tracked cookies = %d, want 3", len(cookies))
	}
	var session, csrf, browser SessionCookie
	for _, cookie := range cookies {
		switch cookie.Name {
		case "sessionid":
			session = cookie
		case "csrftoken":
			csrf = cookie
		case "browser_session":
			browser = cookie
		}
	}
	if session.HostOnly != true || session.Path != "/" || !session.HTTPOnly || !session.Secure || session.LocalExpiry {
		t.Errorf("session attributes = %#v, want host-only / HTTP-only / secure / server expiry", session)
	}
	if csrf.Path != "/api/2.0/" {
		t.Errorf("csrf path = %q, want /api/2.0/", csrf.Path)
	}
	if !browser.LocalExpiry || !browser.Expires.Equal(now.Add(time.Hour)) {
		t.Errorf("browser session = %#v, want one-hour synthetic expiry", browser)
	}

	requestURL, _ := url.Parse("https://api.example.test/api/2.0/drives/")
	requestCookies := tracked.Cookies(requestURL)
	if len(requestCookies) != 3 {
		t.Fatalf("request cookies = %d, want 3", len(requestCookies))
	}

	restored := NewTrackedCookieJar(nil)
	restored.now = func() time.Time { return now }
	if err := restored.Restore(cookies); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	restoredCookies, err := restored.PersistentCookies(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(restoredCookies) != len(cookies) {
		t.Fatalf("restored cookies = %d, want %d", len(restoredCookies), len(cookies))
	}
	if got := restored.Cookies(requestURL); len(got) != 3 {
		t.Fatalf("restored request cookies = %d, want 3", len(got))
	}
}

func TestTrackedCookieJarDeletionAndExpiry(t *testing.T) {
	now := time.Date(2036, time.January, 2, 3, 4, 5, 0, time.UTC)
	tracked := NewTrackedCookieJar(nil)
	tracked.now = func() time.Time { return now }
	endpoint, _ := url.Parse("https://api.example.test/login/")
	tracked.SetCookies(endpoint, []*http.Cookie{{Name: "sessionid", Value: "session", Path: "/", Expires: now.Add(time.Hour)}})
	if got, err := tracked.PersistentCookies(now); err != nil || len(got) != 1 {
		t.Fatalf("initial snapshot = %v, %v; want one cookie", got, err)
	}
	tracked.SetCookies(endpoint, []*http.Cookie{{Name: "sessionid", MaxAge: -1, Path: "/"}})
	if got, err := tracked.PersistentCookies(now); err != nil || len(got) != 0 {
		t.Fatalf("after deletion = %v, %v; want no cookies", got, err)
	}

	tracked.SetCookies(endpoint, []*http.Cookie{{Name: "sessionid", Value: "session", Path: "/", Expires: now.Add(time.Hour)}})
	if got, err := tracked.PersistentCookies(now.Add(2 * time.Hour)); err != nil || len(got) != 0 {
		t.Fatalf("after expiry = %v, %v; want no cookies", got, err)
	}
}

func TestTrackedCookieJarSetCookiesUsesPositiveMaxAgeOverExpiredExpires(t *testing.T) {
	now := time.Date(2036, time.January, 2, 3, 4, 5, 0, time.UTC)
	tracked := NewTrackedCookieJar(nil)
	tracked.now = func() time.Time { return now }
	endpoint, _ := url.Parse("https://api.example.test/login/")
	tracked.SetCookies(endpoint, []*http.Cookie{{
		Name:    "sessionid",
		Value:   "session",
		Path:    "/",
		Expires: now.Add(-time.Hour),
		MaxAge:  60,
	}})

	cookies, err := tracked.PersistentCookies(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 1 {
		t.Fatalf("tracked cookies = %d, want one cookie", len(cookies))
	}
	if want := now.Add(time.Minute); !cookies[0].Expires.Equal(want) {
		t.Fatalf("tracked expiry = %s, want Max-Age deadline %s", cookies[0].Expires, want)
	}
}

func TestTrackedCookieJarRejectsUnboundedTTL(t *testing.T) {
	if _, err := NewTrackedCookieJarWithTTL(nil, 0); err == nil {
		t.Fatal("zero TTL returned nil error")
	}
	if _, err := NewTrackedCookieJarWithTTL(nil, MaxSessionCookieTTL+time.Second); err == nil {
		t.Fatal("overlong TTL returned nil error")
	}
	if _, err := NewSessionCookie(http.Cookie{Name: "sessionid", Value: "value"}, time.Now()); !errors.Is(err, ErrSessionCookieNoExpiry) {
		t.Fatalf("unbounded session cookie: error = %v, want no-expiry error", err)
	}
}

func TestTrackedCookieJarRequiresCookieDomainOnRestore(t *testing.T) {
	tracked := NewTrackedCookieJar(nil)
	tracked.now = func() time.Time { return time.Now() }
	err := tracked.Restore([]SessionCookie{{Name: "sessionid", Value: "value", Path: "/", Expires: time.Now().Add(time.Hour)}})
	if err == nil {
		t.Fatal("Restore without domain returned nil error")
	}
}
