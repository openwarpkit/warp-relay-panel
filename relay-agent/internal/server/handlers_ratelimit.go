package server

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/shell"
)

type rateLimitReq struct {
	IP        string  `json:"ip"`
	Mbps      float64 `json:"mbps"`
	ExpiresAt string  `json:"expires_at,omitempty"`
	ClientID  *int64  `json:"client_id,omitempty"`
}

func (s *Server) handleRateLimitSet(w http.ResponseWriter, r *http.Request) {
	var req rateLimitReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "invalid json")
		return
	}
	if !shell.ValidIPv4(req.IP) {
		writeError(w, 400, "Invalid ip: "+req.IP)
		return
	}
	if req.Mbps <= 0 {
		writeError(w, 400, "mbps must be > 0")
		return
	}
	limit, err := s.RateLimit.Set(req.IP, req.Mbps, req.ExpiresAt, req.ClientID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"ok":         true,
		"ip":         req.IP,
		"mbps":       limit.Mbps,
		"mark":       limit.Mark,
		"expires_at": limit.ExpiresAt,
		"client_id":  limit.ClientID,
		"applied_at": limit.AppliedAt,
	})
}

func (s *Server) handleRateLimitDelete(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if !shell.ValidIPv4(ip) {
		writeError(w, 400, "Invalid ip: "+ip)
		return
	}
	removed, ok := s.RateLimit.Remove(ip)
	if !ok {
		writeError(w, 404, "not_found")
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"ok": true, "ip": ip, "removed": removed,
	})
}

func (s *Server) handleRateLimitGet(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if !shell.ValidIPv4(ip) {
		writeError(w, 400, "Invalid ip: "+ip)
		return
	}
	l, ok := s.RateLimit.Get(ip)
	if !ok {
		writeJSON(w, 200, map[string]interface{}{"ip": ip, "limited": false})
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"limited":    true,
		"ip":         ip,
		"mbps":       l.Mbps,
		"mark":       l.Mark,
		"expires_at": l.ExpiresAt,
		"client_id":  l.ClientID,
		"applied_at": l.AppliedAt,
	})
}

func (s *Server) handleRateLimitList(w http.ResponseWriter, r *http.Request) {
	all := s.RateLimit.All()
	writeJSON(w, 200, map[string]interface{}{
		"items": all,
		"count": len(all),
	})
}
