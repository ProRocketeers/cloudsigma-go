package cloudsigma

import "time"

// AuthEventType names the bounded authentication events emitted by an optional
// AuthEventHandler, including lifecycle events and individual request results.
type AuthEventType string

const (
	AuthEventHandshakeStart  AuthEventType = "handshake_start"
	AuthEventHandshakeResult AuthEventType = "handshake_result"
	AuthEventRecovery        AuthEventType = "recovery"
	AuthEventCooldown        AuthEventType = "cooldown"
	AuthEventRateLimited     AuthEventType = "rate_limited"
	// AuthEventAttemptResult reports one SDK-issued login or OTP request result.
	AuthEventAttemptResult AuthEventType = "attempt_result"

	// Readable aliases for callers that prefer past-tense event names.
	AuthEventHandshakeStarted  AuthEventType = AuthEventHandshakeStart
	AuthEventHandshakeFinished AuthEventType = AuthEventHandshakeResult
)

// AuthEvent is a safe, low-cardinality authentication observation. StatusCode
// is populated for authentication-attempt results (zero means no HTTP response
// was obtained). It never contains credentials, OTP values, cookies,
// authorization headers, endpoint URLs, account identifiers, or response
// bodies.
//
// A handler may be called concurrently from independent request and
// handshake goroutines. The SDK never calls it while holding an internal
// synchronization lock, but it calls synchronously on the reporting
// goroutine, so handlers should be quick and safe for concurrent use.
type AuthEvent struct {
	Type       AuthEventType
	Stage      AuthStage
	Reason     string
	Outcome    string
	StatusCode int
	RetryAfter time.Duration
}

// AuthEventHandler receives bounded authentication lifecycle and attempt
// observations.
type AuthEventHandler func(AuthEvent)

// AuthEventCallback is an alias retained for callers that use callback
// terminology in their configuration code.
type AuthEventCallback = AuthEventHandler

// LoginOptions configures the optional behavior of LoginWithOptions. The
// legacy Login function remains unchanged and uses the package cache.
type LoginOptions struct {
	OnAuthEvent     AuthEventHandler
	Timeout         time.Duration
	SessionCacheDir string
}

const (
	authEventOutcomeStarted  = "started"
	authEventOutcomeSuccess  = "success"
	authEventOutcomeFailure  = "failure"
	authEventOutcomeSkipped  = "skipped"
	authEventOutcomeRetrying = "retrying"

	authEventReasonInitial        = "initial"
	authEventReasonSessionLoss    = "session_loss"
	authEventReasonLoginRedirect  = "login_redirect"
	authEventReasonRateLimit      = "rate_limit"
	authEventReasonCooldown       = "cooldown"
	authEventReasonAuthentication = "authentication"
)
