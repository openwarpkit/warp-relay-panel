package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/ipsetgo"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/ratelimit"
)

func stateHash(refcounts map[string][]int64, limits []ratelimit.Limit) string {
	lines := make([]string, 0, len(refcounts)+len(limits))
	for ip, clientIDs := range refcounts {
		for _, clientID := range clientIDs {
			lines = append(lines, fmt.Sprintf("C\t%s\t%d", ip, clientID))
		}
	}
	for _, limit := range limits {
		clientID := ""
		if limit.ClientID != nil {
			clientID = strconv.FormatInt(*limit.ClientID, 10)
		}
		lines = append(lines, fmt.Sprintf("R\t%s\t%.6f\t%s\t%s",
			limit.IP, limit.Mbps, limit.ExpiresAt, clientID))
	}
	return hashSortedLines(lines)
}

func whitelistHash(ips map[string]struct{}) string {
	lines := make([]string, 0, len(ips))
	for ip := range ips {
		lines = append(lines, "I\t"+ip)
	}
	return hashSortedLines(lines)
}

func hashSortedLines(lines []string) string {
	slices.Sort(lines)
	digest := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(digest[:])
}

func (s *Server) currentState() (map[string]interface{}, error) {
	members, err := ipsetgo.Members(s.Cfg.IpsetName)
	if err != nil {
		return nil, err
	}
	refcounts := s.Refcount.All()
	limits := s.RateLimit.All()
	return map[string]interface{}{
		"state_hash":        stateHash(refcounts, limits),
		"whitelist_hash":    whitelistHash(members),
		"whitelist_count":   len(members),
		"client_refs_count": countClientRefs(refcounts),
		"rate_limits_count": len(limits),
	}, nil
}

func countClientRefs(refcounts map[string][]int64) int {
	total := 0
	for _, ids := range refcounts {
		total += len(ids)
	}
	return total
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	state, err := s.currentState()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	state["ok"] = true
	writeJSON(w, http.StatusOK, state)
}
