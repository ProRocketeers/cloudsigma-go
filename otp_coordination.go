package cloudsigma

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
)

const otpBindingDomain = "cloudsigma-go/accepted-otp/v1\x00"

type otpAccountLock struct {
	semaphore chan struct{}
	users     int
}

var otpCoordination = struct {
	sync.Mutex
	locks    map[string]*otpAccountLock
	accepted map[string]int64
}{
	locks:    make(map[string]*otpAccountLock),
	accepted: make(map[string]int64),
}

func normalizeOTPSecret(secret string) string {
	normalized := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToUpper(r)
	}, secret)
	return strings.TrimRight(normalized, "=")
}

func otpSecretBinding(secret string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(otpBindingDomain))
	_, _ = h.Write([]byte(normalizeOTPSecret(secret)))
	return hex.EncodeToString(h.Sum(nil))
}

func normalizedAuthEndpoint(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimRight(strings.ToLower(endpoint), "/")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	u.User = nil
	u.Fragment = ""
	u.Path = strings.TrimRight(u.Path, "/") + "/"
	u.RawPath = ""
	return u.String()
}

func otpAccountIdentity(endpoint, username string) string {
	material := normalizedAuthEndpoint(endpoint) + "\x00" + strings.ToLower(strings.TrimSpace(username))
	hash := sha256.Sum256([]byte(material))
	return hex.EncodeToString(hash[:])
}

func otpStateIdentity(endpoint, username, binding string) string {
	return otpAccountIdentity(endpoint, username) + ":" + binding
}

func acquireOTPAccount(ctx context.Context, identity string) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	otpCoordination.Lock()
	lock := otpCoordination.locks[identity]
	if lock == nil {
		lock = &otpAccountLock{semaphore: make(chan struct{}, 1)}
		lock.semaphore <- struct{}{}
		otpCoordination.locks[identity] = lock
	}
	lock.users++
	otpCoordination.Unlock()

	select {
	case <-ctx.Done():
		otpCoordination.Lock()
		lock.users--
		if lock.users == 0 {
			delete(otpCoordination.locks, identity)
		}
		otpCoordination.Unlock()
		return nil, ctx.Err()
	case <-lock.semaphore:
	}
	if err := contextErr(ctx); err != nil {
		lock.semaphore <- struct{}{}
		otpCoordination.Lock()
		lock.users--
		if lock.users == 0 {
			delete(otpCoordination.locks, identity)
		}
		otpCoordination.Unlock()
		return nil, err
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			lock.semaphore <- struct{}{}
			otpCoordination.Lock()
			lock.users--
			if lock.users == 0 {
				delete(otpCoordination.locks, identity)
			}
			otpCoordination.Unlock()
		})
	}, nil
}

func acceptedOTPStep(identity string) (int64, bool) {
	otpCoordination.Lock()
	defer otpCoordination.Unlock()
	step, ok := otpCoordination.accepted[identity]
	return step, ok
}

func rememberAcceptedOTPStep(identity string, step int64) {
	otpCoordination.Lock()
	if previous, ok := otpCoordination.accepted[identity]; !ok || step > previous {
		otpCoordination.accepted[identity] = step
	}
	otpCoordination.Unlock()
}

func waitForAcceptedOTPStep(ctx context.Context, now func() time.Time, sleep func(context.Context, time.Duration) error, accepted int64) error {
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = realSleep
	}
	for {
		if err := contextErr(ctx); err != nil {
			return err
		}
		before := now()
		current := before.Unix() / 30
		if current > accepted {
			return nil
		}
		deadline := time.Unix((accepted+1)*30+1, 0)
		delay := deadline.Sub(before)
		if delay <= 0 {
			// A custom clock must advance along with its sleep implementation.
			return fmt.Errorf("cloudsigma: clock did not advance past accepted OTP step")
		}
		if err := sleep(ctx, delay); err != nil {
			return err
		}
		if !now().After(before) {
			return fmt.Errorf("cloudsigma: clock did not advance during accepted OTP wait")
		}
	}
}
