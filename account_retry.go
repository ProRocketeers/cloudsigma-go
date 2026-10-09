package cloudsigma

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Account retry timing is distinct from target-specific bearer cookies. The
// marker cannot be an impersonation UUID and the fixed binding deliberately
// does not depend on credentials: server rate limits apply to the account even
// when its password changes. Callers hold the account lock around these calls.
const (
	accountRetryTarget = "\x00cloudsigma-account-retry-v1"
	acceptedOTPTarget  = "\x00cloudsigma-accepted-otp-v1:"
)

func accountRetryKey(key SessionKey) SessionKey {
	return SessionKey{
		Endpoint:              normalizedAuthEndpoint(key.Endpoint),
		Username:              strings.ToLower(strings.TrimSpace(key.Username)),
		Impersonate:           accountRetryTarget,
		CredentialFingerprint: "account-retry-v1",
	}
}

func legacyAccountRetryKey(key SessionKey) SessionKey {
	return SessionKey{
		Endpoint:              key.Endpoint,
		Username:              key.Username,
		Impersonate:           accountRetryTarget,
		CredentialFingerprint: "account-retry-v1",
	}
}

func (s *FileSessionStore) loadAccountRetry(ctx context.Context, key SessionKey) (time.Time, error) {
	canonicalKey := accountRetryKey(key)
	deadline := time.Time{}
	record, err := s.Load(ctx, canonicalKey)
	if err == nil {
		deadline = record.RetryNotBefore
	} else if !errors.Is(err, ErrSessionCacheNotFound) {
		return time.Time{}, err
	}

	legacyKey := legacyAccountRetryKey(key)
	if legacyKey.Endpoint == canonicalKey.Endpoint && legacyKey.Username == canonicalKey.Username {
		return deadline, nil
	}
	legacy, err := s.Load(ctx, legacyKey)
	if errors.Is(err, ErrSessionCacheNotFound) {
		return deadline, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	if legacy.RetryNotBefore.After(deadline) {
		deadline = legacy.RetryNotBefore
	}
	return deadline, nil
}

func (s *FileSessionStore) saveAccountRetry(ctx context.Context, key SessionKey, deadline time.Time) error {
	if deadline.IsZero() {
		return nil
	}
	previous, err := s.loadAccountRetry(ctx, key)
	if err != nil {
		return err
	}
	if previous.After(deadline) {
		deadline = previous
	}
	return s.Save(ctx, accountRetryKey(key), SessionRecord{RetryNotBefore: deadline})
}

func acceptedOTPKey(key SessionKey, binding string) SessionKey {
	return SessionKey{
		Endpoint:              normalizedAuthEndpoint(key.Endpoint),
		Username:              strings.ToLower(strings.TrimSpace(key.Username)),
		Impersonate:           acceptedOTPTarget + binding,
		CredentialFingerprint: "accepted-otp-v1",
	}
}

func (s *FileSessionStore) loadAcceptedOTPStep(ctx context.Context, key SessionKey, binding string) (int64, bool, error) {
	record, err := s.Load(ctx, acceptedOTPKey(key, binding))
	if errors.Is(err, ErrSessionCacheNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if record.OTPSecretBinding != binding {
		return 0, false, fmt.Errorf("%w: accepted OTP binding mismatch", ErrSessionCacheCorrupt)
	}
	return record.AcceptedOTPStep, true, nil
}

func (s *FileSessionStore) saveAcceptedOTPStep(ctx context.Context, key SessionKey, binding string, step int64) error {
	storeKey := acceptedOTPKey(key, binding)
	previous, ok, err := s.loadAcceptedOTPStep(ctx, key, binding)
	if err != nil {
		return err
	}
	if ok && previous > step {
		step = previous
	}
	return s.Save(ctx, storeKey, SessionRecord{
		AcceptedOTPStep:  step,
		OTPSecretBinding: binding,
	})
}
