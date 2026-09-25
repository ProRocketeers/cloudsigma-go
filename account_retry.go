package cloudsigma

import (
	"context"
	"errors"
	"time"
)

// Account retry timing is distinct from target-specific bearer cookies. The
// marker cannot be an impersonation UUID and the fixed binding deliberately
// does not depend on credentials: server rate limits apply to the account even
// when its password changes. Callers hold the account lock around these calls.
const accountRetryTarget = "\x00cloudsigma-account-retry-v1"

func accountRetryKey(key SessionKey) SessionKey {
	return SessionKey{
		Endpoint:              key.Endpoint,
		Username:              key.Username,
		Impersonate:           accountRetryTarget,
		CredentialFingerprint: "account-retry-v1",
	}
}

func (s *FileSessionStore) loadAccountRetry(ctx context.Context, key SessionKey) (time.Time, error) {
	record, err := s.Load(ctx, accountRetryKey(key))
	if errors.Is(err, ErrSessionCacheNotFound) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return record.RetryNotBefore, nil
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
