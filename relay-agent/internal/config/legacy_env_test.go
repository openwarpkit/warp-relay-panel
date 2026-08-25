package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoveLegacyPanelCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	content := strings.Join([]string{
		"AGENT_SECRET=relay-secret",
		"PANEL_URL=https://panel.example",
		"PANEL_API_KEY=panel-secret",
		"RELAY_ID=7",
		"PANEL_REQUEST_TIMEOUT=60",
		"SELF_SYNC_INTERVAL=600",
		"TRAFFIC_INTERVAL=30",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	removed, err := RemoveLegacyPanelCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 5 {
		t.Fatalf("expected 5 removed keys, got %d", removed)
	}
	result, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(result)
	if strings.Contains(text, "PANEL_") || strings.Contains(text, "RELAY_ID") || strings.Contains(text, "SELF_SYNC") {
		t.Fatalf("legacy credentials remain: %s", text)
	}
	if !strings.Contains(text, "AGENT_SECRET=relay-secret") || !strings.Contains(text, "TRAFFIC_INTERVAL=30") {
		t.Fatalf("unrelated settings removed: %s", text)
	}
}
