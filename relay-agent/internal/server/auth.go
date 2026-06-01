package server

import "net/http"

// authMiddleware: X-Agent-Key for all paths, except /health.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		key := r.Header.Get("X-Agent-Key")
		if key != s.Cfg.AgentSecret {
			writeError(w, http.StatusForbidden, "Invalid agent key")
			return
		}
		next.ServeHTTP(w, r)
	})
}
