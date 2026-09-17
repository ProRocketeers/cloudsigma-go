package cloudsigma

import (
	"errors"
	"fmt"
	"io"
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
