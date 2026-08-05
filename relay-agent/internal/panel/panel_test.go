package panel

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchWhitelistPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "secret" {
			http.Error(w, "invalid key", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"clients":[{"ip":"198.51.100.10","client_id":7}],"rate_limits":[]}`))
	}))
	defer server.Close()

	client := New(server.URL, "secret", "1", 3*time.Second)
	payload, err := client.FetchWhitelistPayload()
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.Clients) != 1 || payload.Clients[0].ClientID != 7 {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if client.HTTP.Timeout != 3*time.Second {
		t.Fatalf("unexpected timeout: %s", client.HTTP.Timeout)
	}
}

func TestNewUsesDefaultTimeout(t *testing.T) {
	client := New("https://example.com", "secret", "1", 0)
	if client.HTTP.Timeout != 60*time.Second {
		t.Fatalf("unexpected timeout: %s", client.HTTP.Timeout)
	}
}
