package servermin

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/shell"
)

func (s *Server) handleTrafficAll(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.Traffic.GetAll(noRefcount, noClients))
}

func (s *Server) handleTrafficByIP(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if !shell.ValidIPv4(ip) {
		writeError(w, 400, "Invalid IP: "+ip)
		return
	}
	stats, _, month, _ := s.Traffic.GetIP(ip, noRefcount, noClients)
	resp := map[string]interface{}{
		"ip":            ip,
		"month":         month,
		"tx_bytes":      stats.TXBytes,
		"rx_bytes":      stats.RXBytes,
		"total_bytes":   stats.TotalBytes,
		"tx_human":      stats.TXHuman,
		"rx_human":      stats.RXHuman,
		"total_human":   stats.TotalHuman,
		"clients_on_ip": 0,
		"updated":       stats.Updated,
	}
	if stats.TXHuman == "" {
		resp["tx_human"] = "0 B"
		resp["rx_human"] = "0 B"
		resp["total_human"] = "0 B"
	}
	writeJSON(w, 200, resp)
}

func (s *Server) handleTrafficReset(w http.ResponseWriter, r *http.Request) {
	month := s.Traffic.Reset()
	writeJSON(w, 200, map[string]interface{}{"ok": true, "month": month})
}
