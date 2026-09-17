package cloudsigma

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultTimeout = 60 * time.Second

// maxResponseBytes caps the response body Client.do will read. An oversized
// body fails with ErrResponseTooLarge rather than being silently truncated.
const maxResponseBytes = 8 << 20

// Config configures a Client. BaseURL follows the same convention as Login:
// host and path without a scheme, e.g. "prg1.t-cloud.eu/api/2.0/". A scheme is
// accepted too, which lets tests point the client at an httptest server.
type Config struct {
	BaseURL     string
	Username    string
	Password    string
	OTPSecret   string
	Impersonate string
	UserAgent   string
	Timeout     time.Duration
}

// New performs the login handshake under ctx and returns a ready Client. Each
// call authenticates independently: unlike Login there is no cache, so a
// long-running controller gets its own session and its own refresh path.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("cloudsigma: BaseURL is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	auth, err := newAuthenticator(cfg.BaseURL, cfg.Username, cfg.Password, cfg.OTPSecret, cfg.Impersonate, cfg.UserAgent, timeout)
	if err != nil {
		return nil, err
	}
	refresher := newRefresher(auth)
	if err := refresher.refresh(ctx, refresher.currentGeneration()); err != nil {
		return nil, err
	}

	return &Client{
		http: &http.Client{Jar: auth.jar, Timeout: timeout, Transport: refresher.transport()},
		base: auth.root,
	}, nil
}

// Client is a JSON client for the CloudSigma 2.0 API. It shares one session
// across all goroutines and transparently recovers from session expiry.
type Client struct {
	http *http.Client
	base string
}

// HTTPClient returns the underlying client, for callers that need to drive the
// SDK or issue bespoke requests through the same session.
func (c *Client) HTTPClient() *http.Client { return c.http }

// Get issues a GET and decodes the JSON response into out (when non-nil).
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// Post issues a POST with a JSON-encoded body and decodes the JSON response
// into out (when non-nil).
func (c *Client) Post(ctx context.Context, path string, body any, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

// Put issues a PUT with a JSON-encoded body and decodes the JSON response into
// out (when non-nil).
func (c *Client) Put(ctx context.Context, path string, body any, out any) error {
	return c.do(ctx, http.MethodPut, path, body, out)
}

// Delete issues a DELETE and decodes the JSON response into out (when non-nil).
func (c *Client) Delete(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodDelete, path, nil, out)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}

	endpoint := c.base + strings.TrimPrefix(path, "/")
	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Accept", "application/json")

	response, err := c.http.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		// The refreshing transport surfaces persistent session loss as an
		// *APIError; unwrap it so callers see the same typed shape as the
		// ordinary non-2xx path instead of a *url.Error.
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			return apiErr
		}
		return err
	}
	defer func() { _ = response.Body.Close() }()

	payload, readErr := readCapped(response.Body, maxResponseBytes)
	if response.StatusCode < 200 || response.StatusCode > 299 {
		apiErr := &APIError{
			StatusCode: response.StatusCode,
			Method:     method,
			URL:        endpoint,
		}
		switch {
		case readErr == nil:
			apiErr.Body = strings.TrimSpace(string(payload))
		case errors.Is(readErr, ErrResponseTooLarge):
			// Keep the status: callers branch on it, and a truncated body would mislead.
			apiErr.Body = fmt.Sprintf("<response body exceeded %d bytes>", maxResponseBytes)
		default:
			return readErr
		}
		return apiErr
	}
	if readErr != nil {
		return readErr
	}
	if out != nil && len(bytes.TrimSpace(payload)) > 0 {
		if err := json.Unmarshal(payload, out); err != nil {
			return err
		}
	}
	return nil
}
