package cloudsigma

import (
	"strings"
)

// Endpoint returns the API host and path (no scheme) for the given base URL,
// falling back to the CloudSigma location subdomain.
func Endpoint(baseURL, location string) string {
	if baseURL == "" {
		return location + ".cloudsigma.com/api/2.0/"
	}
	baseURL = strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://")
	return strings.TrimSuffix(baseURL, "/") + "/"
}
