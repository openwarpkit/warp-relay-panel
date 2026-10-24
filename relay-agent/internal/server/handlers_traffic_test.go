package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/config"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/traffic"
)

func TestTrafficResetIPRoute(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	state := map[string]interface{}{
		"month": time.Now().In(time.FixedZone("MSK", 3*3600)).Format("2006-01"),
		"ips": map[string]interface{}{
			"203.0.113.7": map[string]int{"tx": 100, "rx": 200},
			"203.0.113.8": map[string]int{"tx": 30, "rx": 40},
		},
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{Cfg: config.Config{AgentSecret: "secret"}, Traffic: traffic.New(path, time.Second, nil, traffic.ModePerIP)}
	router := s.Routes()
	for _, tc := range []struct {
		path   string
		key    string
		status int
	}{
		{"/traffic/203.0.113.7/reset", "", http.StatusForbidden},
		{"/traffic/invalid/reset", "secret", http.StatusBadRequest},
		{"/traffic/203.0.113.7/reset", "secret", http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, nil)
		req.Header.Set("X-Agent-Key", tc.key)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		if resp.Code != tc.status {
			t.Fatalf("%s: got %d, expected %d: %s", tc.path, resp.Code, tc.status, resp.Body.String())
		}
		if tc.status == http.StatusOK {
			var body struct {
				OK    bool `json:"ok"`
				Reset bool `json:"reset"`
			}
			if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil || !body.OK || !body.Reset {
				t.Fatalf("unexpected response: %s", resp.Body.String())
			}
		}
	}
	summary := s.Traffic.GetAll(func(string) int { return 0 }, func(string) []int64 { return nil })
	if summary.IPCount != 1 || summary.TotalBytes != 70 {
		t.Fatalf("unexpected remaining traffic: %+v", summary)
	}
}
