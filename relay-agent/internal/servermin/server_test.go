package servermin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/config"
)

func TestAuthMiddleware(t *testing.T) {
	s := &Server{
		Cfg: config.Config{AgentSecret: "secret123"},
	}

	handler := s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test /health bypass
	req1 := httptest.NewRequest("GET", "/health", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Errorf("expected 200 for /health without auth, got %d", rr1.Code)
	}

	// Test missing auth
	req2 := httptest.NewRequest("GET", "/some-path", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Errorf("expected 403 for missing auth, got %d", rr2.Code)
	}

	// Test valid auth
	req3 := httptest.NewRequest("GET", "/some-path", nil)
	req3.Header.Set("X-Agent-Key", "secret123")
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Errorf("expected 200 for valid auth, got %d", rr3.Code)
	}
}
