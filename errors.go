package cloudsigma

import "fmt"

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
