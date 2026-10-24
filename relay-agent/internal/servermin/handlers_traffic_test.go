package servermin

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

func TestTrafficResetIPPreservesAggregate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	state := map[string]interface{}{
		"month":  time.Now().In(time.FixedZone("MSK", 3*3600)).Format("2006-01"),
		"agg_tx": 1000, "agg_rx": 2000,
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{Cfg: config.Config{AgentSecret: "secret"}, Traffic: traffic.New(path, time.Second, nil, traffic.ModeAggregate)}
	for _, tc := range []struct {
		ip     string
		key    string
		status int
	}{
		{"203.0.113.7", "", http.StatusForbidden},
		{"invalid", "secret", http.StatusBadRequest},
		{"203.0.113.7", "secret", http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodPost, "/traffic/"+tc.ip+"/reset", nil)
		req.Header.Set("X-Agent-Key", tc.key)
		resp := httptest.NewRecorder()
		s.Routes().ServeHTTP(resp, req)
		if resp.Code != tc.status {
			t.Fatalf("got %d, expected %d: %s", resp.Code, tc.status, resp.Body.String())
		}
		if tc.status == http.StatusOK {
			var body struct {
				OK    bool `json:"ok"`
				Reset bool `json:"reset"`
			}
			if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil || !body.OK || body.Reset {
				t.Fatalf("unexpected response: %s", resp.Body.String())
			}
		}
	}
	summary := s.Traffic.GetAll(noRefcount, noClients)
	if summary.TotalTXBytes != 1000 || summary.TotalRXBytes != 2000 {
		t.Fatalf("aggregate traffic changed: %+v", summary)
	}
}
