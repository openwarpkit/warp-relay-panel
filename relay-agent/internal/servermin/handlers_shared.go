package servermin

import "net/http"

// /shaped - list of IPs under limit + classid + lastSeen.
func (s *Server) handleShaped(w http.ResponseWriter, r *http.Request) {
	cfg := s.SharedLimit.Cfg()
	writeJSON(w, 200, map[string]interface{}{
		"items":         s.SharedLimit.Shaped(),
		"count":         s.SharedLimit.Count(),
		"limit_mbps":    cfg.LimitMbps,
		"scan_interval": int(cfg.ScanInterval.Seconds()),
		"idle_grace":    int(cfg.IdleGrace.Seconds()),
	})
}

// /shaped/reset - remove all limits, reconcile-loop will reapply on next tick.
func (s *Server) handleShapedReset(w http.ResponseWriter, r *http.Request) {
	count := s.SharedLimit.Count()
	s.SharedLimit.Reset()
	writeJSON(w, 200, map[string]interface{}{
		"ok":      true,
		"removed": count,
	})
}
