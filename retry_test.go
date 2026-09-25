package cloudsigma

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRetryAfterSecondsAndHTTPDate(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	if got := parseRetryAfter("7", now); got != 7*time.Second {
		t.Fatalf("seconds = %s", got)
	}
	if got := parseRetryAfter(now.Add(13*time.Second).Format(http.TimeFormat), now); got != 13*time.Second {
		t.Fatalf("HTTP date = %s", got)
	}
	for _, value := range []string{"bad", "-1", now.Add(-time.Second).Format(http.TimeFormat)} {
		if got := parseRetryAfter(value, now); got != 0 {
			t.Errorf("%q = %s, want zero", value, got)
		}
	}
}

func TestOTPNextWindowUsesInjectedClock(t *testing.T) {
	verify := 0
	var codes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.RawQuery, "do=login"):
			http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: "csrf", Path: "/"})
			_, _ = io.WriteString(w, `{}`)
		case strings.Contains(r.URL.RawQuery, "do=verify_otp"):
			verify++
			codes = append(codes, r.Header.Get("OTP"))
			if verify == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	auth, err := newAuthenticator(server.URL+"/api/2.0/", "user", "pass", "GEZD GNBV GY3T QOJQ", "", "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(29, 0)
	auth.now = func() time.Time { return now }
	var slept time.Duration
	auth.sleep = func(_ context.Context, d time.Duration) error { slept = d; now = now.Add(d); return nil }
	if err := auth.handshake(context.Background()); err != nil {
		t.Fatal(err)
	}
	if verify != 2 || slept != 2*time.Second {
		t.Fatalf("verify/sleep = %d/%s, want 2/2s", verify, slept)
	}
	if codes[0] == codes[1] {
		t.Fatal("OTP retry reused the same TOTP window")
	}
}

func TestRateLimitedOTPDoesNotTakeNextWindowRetry(t *testing.T) {
	verify := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.RawQuery, "do=login"):
			_, _ = io.WriteString(w, `{}`)
		case strings.Contains(r.URL.RawQuery, "do=verify_otp"):
			verify++
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, "rate limit")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	auth, err := newAuthenticator(server.URL+"/api/2.0/", "user", "pass", "GEZD GNBV GY3T QOJQ", "", "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	slept := false
	auth.sleep = func(context.Context, time.Duration) error { slept = true; return nil }
	err = auth.handshake(context.Background())
	var authErr *AuthError
	if !errors.As(err, &authErr) || authErr.Kind != AuthKindRateLimited || authErr.RetryAfter != 7*time.Second {
		t.Fatalf("error = %v, want rate limited with 7s", err)
	}
	if verify != 1 || slept {
		t.Fatalf("verify/slept = %d/%t, want 1/false", verify, slept)
	}
}

func TestRateLimitNeverRetriesBeforeInjectedDeadline(t *testing.T) {
	logins := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logins++
		w.Header().Set("Retry-After", "9")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, "rate limited")
	}))
	defer server.Close()
	auth, err := newAuthenticator(server.URL+"/api/2.0/", "user", "pass", "GEZD GNBV GY3T QOJQ", "", "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	auth.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	auth.sleep = func(context.Context, time.Duration) error { return nil } // clock has not advanced
	r := newRefresher(auth)
	defer r.close()
	if err := r.refresh(context.Background(), 0); err == nil {
		t.Fatal("expected rate limit")
	}
	if err := r.refresh(context.Background(), 0); err == nil {
		t.Fatal("expected retained rate limit")
	}
	if logins != 1 {
		t.Fatalf("login calls = %d, want one before retry deadline", logins)
	}
}
