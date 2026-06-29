package server

import (
	"context"
	"log"
	"time"

	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/panel"
)

// SelfSyncLoop periodically pulls the whitelist + rate-limit payload from the
// panel and applies it through the same full reconcile as a panel-pushed
// /whitelist/sync. Self-heals drift when a live push failed, without waiting
// for an agent restart.
func (s *Server) SelfSyncLoop(ctx context.Context, pc *panel.Client, interval time.Duration) {
	if pc == nil || !pc.Configured() || interval <= 0 {
		log.Println("self-sync: disabled")
		return
	}
	log.Printf("self-sync: enabled every %s", interval)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.selfSyncOnce(pc)
		}
	}
}

func (s *Server) selfSyncOnce(pc *panel.Client) {
	payload, err := pc.FetchWhitelistPayload()
	if err != nil {
		log.Printf("self-sync: fetch failed: %v", err)
		return
	}
	clients := make([]syncEntry, 0, len(payload.Clients))
	for _, c := range payload.Clients {
		clients = append(clients, syncEntry{IP: c.IP, ClientID: c.ClientID})
	}
	rls := make([]syncRateLimitEntry, 0, len(payload.RateLimits))
	for _, r := range payload.RateLimits {
		rls = append(rls, syncRateLimitEntry{
			IP: r.IP, Mbps: r.Mbps, ExpiresAt: r.ExpiresAt, ClientID: r.ClientID,
		})
	}

	if !s.SyncInProgress.CompareAndSwap(false, true) {
		log.Println("self-sync: skipped (sync already in progress)")
		return
	}
	res := s.doSync(clients, &rls)
	log.Printf("self-sync: synced=%v rl_applied=%v rl_removed=%v",
		res["synced"], res["rate_limits_applied"], res["rate_limits_removed"])
}
