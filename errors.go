package cloudsigma

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ErrResponseTooLarge reports that an HTTP response body was larger than the
// cap the package reads. It is returned (wrapped, naming the limit) instead of
// silently truncating the body, so callers can detect it with errors.Is.
var ErrResponseTooLarge = errors.New("cloudsigma: response body too large")

// readCapped reads at most limit bytes. When the body has more it returns
// ErrResponseTooLarge rather than a truncated slice, so an oversized response
// fails loudly instead of surfacing later as a confusing JSON syntax error.
func readCapped(body io.Reader, limit int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("%w: limit is %d bytes", ErrResponseTooLarge, limit)
	}
	return payload, nil
}

// APIError is returned for any non-2xx HTTP response, from the JSON client and
// from the login handshake. Callers branch on StatusCode via errors.As; Body
// carries the response text needed to distinguish e.g. a 403 hotplug-limit
// rejection from a plain permission denial.
type APIError struct {
	StatusCode int
	Body       string
	Method     string
	URL        string
}

// Error reports the status code and response body as "%d: %s".
func (e *APIError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Body)
}

// AuthStage identifies the step of authentication that failed.
type AuthStage string

const (
	AuthStageLogin           AuthStage = "login"
	AuthStageOTPVerification AuthStage = "otp_verification"
	AuthStageImpersonation   AuthStage = "impersonation"
	AuthStageSessionRecovery AuthStage = "session_recovery"
	AuthStageOTP             AuthStage = AuthStageOTPVerification
	AuthStageVerifyOTP       AuthStage = AuthStageOTPVerification
)

// AuthKind classifies an authentication failure without exposing response
// bodies or other credential material through the classification itself.
type AuthKind string

const (
	AuthKindRejectedCredentials   AuthKind = "rejected_credentials"
	AuthKindRejectedOTP           AuthKind = "rejected_otp"
	AuthKindPermissionDenied      AuthKind = "permission_denied"
	AuthKindRateLimited           AuthKind = "rate_limited"
	AuthKindPersistentSessionLoss AuthKind = "persistent_session_loss"
	AuthKindTransportFailure      AuthKind = "transport_failure"

	// Compatibility aliases use the adjective-last names that read naturally
	// at call sites while retaining one wire value for each kind.
	AuthKindCredentialsRejected AuthKind = AuthKindRejectedCredentials
	AuthKindOTPRejected         AuthKind = AuthKindRejectedOTP
	AuthKindTransport           AuthKind = AuthKindTransportFailure
)

// AuthError reports a failure while establishing or recovering an
// authenticated session. Cause is retained for errors.As/errors.Is: callers
// can still inspect an underlying *APIError or context cancellation without
// requiring routine logs to print an unfiltered response body.
type AuthError struct {
	Stage      AuthStage
	Kind       AuthKind
	Cause      error
	RetryAfter time.Duration
}

// Error returns a bounded, body-free description suitable for routine logs.
// The underlying cause remains available through Unwrap.
func (e *AuthError) Error() string {
	if e == nil {
		return "cloudsigma authentication error"
	}
	message := fmt.Sprintf("cloudsigma authentication %s failed (%s)", e.Stage, e.Kind)
	if e.RetryAfter > 0 {
		message += fmt.Sprintf("; retry after %s", e.RetryAfter)
	}
	return message
}

// Unwrap exposes the underlying API or context error to errors.As/errors.Is.
func (e *AuthError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// authAPIError keeps Retry-After metadata attached to handshake failures
// without changing APIError's exported field layout. It unwraps to APIError,
// preserving errors.As compatibility for existing callers.
type authAPIError struct {
	*APIError
	retryAfter time.Duration
}

func (e *authAPIError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.APIError
}

func classifyAuthError(stage AuthStage, err error) *AuthError {
	if err == nil {
		return nil
	}
	var existing *AuthError
	if errors.As(err, &existing) {
		return existing
	}

	kind := AuthKindTransportFailure
	if isRateLimited(err) {
		kind = AuthKindRateLimited
	} else {
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			switch stage {
			case AuthStageLogin:
				switch apiErr.StatusCode {
				case http.StatusBadRequest, http.StatusUnauthorized:
					kind = AuthKindRejectedCredentials
				case http.StatusForbidden:
					kind = AuthKindPermissionDenied
				}
			case AuthStageOTPVerification:
				switch apiErr.StatusCode {
				case http.StatusBadRequest, http.StatusUnauthorized:
					kind = AuthKindRejectedOTP
				case http.StatusForbidden:
					kind = AuthKindPermissionDenied
				}
			case AuthStageImpersonation:
				if apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden {
					kind = AuthKindPermissionDenied
				}
			case AuthStageSessionRecovery:
				if apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden || (apiErr.StatusCode >= 300 && apiErr.StatusCode <= 399) {
					kind = AuthKindPersistentSessionLoss
				}
			}
			if apiErr.StatusCode >= 500 {
				kind = AuthKindTransportFailure
			}
		}
	}

	return &AuthError{
		Stage:      stage,
		Kind:       kind,
		Cause:      err,
		RetryAfter: authRetryAfter(err),
	}
}

func authRetryAfter(err error) time.Duration {
	var authErr *AuthError
	if errors.As(err, &authErr) && authErr.RetryAfter > 0 {
		return authErr.RetryAfter
	}
	var responseErr *authAPIError
	if errors.As(err, &responseErr) {
		return responseErr.retryAfter
	}
	return 0
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		maxSeconds := int64((1<<63 - 1) / int64(time.Second))
		if seconds >= 0 && seconds <= maxSeconds {
			return time.Duration(seconds) * time.Second
		}
		return 0
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0
	}
	if delay := when.Sub(now); delay > 0 {
		return delay
	}
	return 0
}
