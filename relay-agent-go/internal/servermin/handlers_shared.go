package servermin

import "net/http"

// /shaped — список IP под лимитом + classid + lastSeen.
func (s *Server) handleShaped(w http.ResponseWriter, r *http.Request) {
	cfg := s.SharedLimit.Cfg()
	writeJSON(w, 200, map[string]interface{}{
		"items":          s.SharedLimit.Shaped(),
		"count":          s.SharedLimit.Count(),
		"limit_mbps":     cfg.LimitMbps,
		"scan_interval": int(cfg.ScanInterval.Seconds()),
		"idle_grace":    int(cfg.IdleGrace.Seconds()),
	})
}

// /shaped/reset — снять все лимиты, reconcile-loop переналожит на следующем тике.
func (s *Server) handleShapedReset(w http.ResponseWriter, r *http.Request) {
	count := s.SharedLimit.Count()
	s.SharedLimit.Reset()
	writeJSON(w, 200, map[string]interface{}{
		"ok":      true,
		"removed": count,
	})
}
