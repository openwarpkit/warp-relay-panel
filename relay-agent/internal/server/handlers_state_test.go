package server

import (
	"testing"

	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/ratelimit"
)

func TestStateHashStable(t *testing.T) {
	clientID := int64(7)
	left := stateHash(
		map[string][]int64{"203.0.113.2": {8, 7}, "203.0.113.1": {3}},
		[]ratelimit.Limit{{IP: "203.0.113.2", Mbps: 5, ClientID: &clientID}},
	)
	right := stateHash(
		map[string][]int64{"203.0.113.1": {3}, "203.0.113.2": {7, 8}},
		[]ratelimit.Limit{{IP: "203.0.113.2", Mbps: 5, ClientID: &clientID}},
	)
	if left != right {
		t.Fatalf("state hash depends on map order: %s != %s", left, right)
	}
	const expected = "c20e72f5cbc44e49acd5f50f249d1fc22bd7608be22c911c867a932de5c580cd"
	if left != expected {
		t.Fatalf("unexpected state hash: %s", left)
	}
}

func TestWhitelistHashStable(t *testing.T) {
	left := whitelistHash(map[string]struct{}{"203.0.113.2": {}, "203.0.113.1": {}})
	right := whitelistHash(map[string]struct{}{"203.0.113.1": {}, "203.0.113.2": {}})
	if left != right {
		t.Fatalf("whitelist hash depends on map order: %s != %s", left, right)
	}
	const expected = "22819dc99b331ec12e7d48f36347489718292e838f9e709ad78f7011f2b2f744"
	if left != expected {
		t.Fatalf("unexpected whitelist hash: %s", left)
	}
}
