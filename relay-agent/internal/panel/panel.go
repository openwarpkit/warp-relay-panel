// Package panel is a client for startup-resync from the panel.
package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	URL     string
	APIKey  string
	RelayID string
	HTTP    *http.Client
}

type ClientEntry struct {
	IP       string `json:"ip"`
	ClientID int64  `json:"client_id"`
}

type RateLimitEntry struct {
	IP        string  `json:"ip"`
	Mbps      float64 `json:"mbps"`
	ExpiresAt string  `json:"expires_at,omitempty"`
	ClientID  *int64  `json:"client_id,omitempty"`
}

type Payload struct {
	Clients    []ClientEntry    `json:"clients"`
	RateLimits []RateLimitEntry `json:"rate_limits"`
}

func New(url, apiKey, relayID string) *Client {
	return &Client{
		URL: url, APIKey: apiKey, RelayID: relayID,
		HTTP: &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *Client) Configured() bool {
	return c.URL != "" && c.APIKey != "" && c.RelayID != ""
}

// FetchWhitelistPayload - GET /api/relays/{id}/whitelist-payload.
func (c *Client) FetchWhitelistPayload() (*Payload, error) {
	url := fmt.Sprintf("%s/api/relays/%s/whitelist-payload", c.URL, c.RelayID)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", c.APIKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("panel returned %d: %s", resp.StatusCode, string(body))
	}
	var p Payload
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, err
	}
	return &p, nil
}
