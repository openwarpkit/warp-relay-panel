// Package servermin — chi router и handlers для min-агента (без whitelist).
//
// Эндпоинты, которые делают реальную работу: /health, /stats, /traffic*,
// /shaped, /shaped/reset, /update.
// Эндпоинты от full-агента (whitelist/*, rate-limit*, refcount) присутствуют
// как 200-OK stub'ы, чтобы случайные вызовы от панели не падали.
package servermin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/config"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/conntrackgo"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/metrics"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/selfupdate"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/sharedlimit"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/traffic"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/watchdog"
)

type Server struct {
	Cfg         config.Config
	Conntrack   *conntrackgo.Client
	Traffic     *traffic.Monitor
	SharedLimit *sharedlimit.Manager
	Metrics     *metrics.Sampler
	Watchdog    *watchdog.Watchdog
	Updater     *selfupdate.Updater
	Version     string
	StartTime   time.Time
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(s.authMiddleware)

	r.Get("/health", s.handleHealth)
	r.Get("/stats", s.handleStats)

	r.Get("/traffic", s.handleTrafficAll)
	r.Get("/traffic/{ip}", s.handleTrafficByIP)
	r.Post("/traffic/reset", s.handleTrafficReset)

	r.Get("/shaped", s.handleShaped)
	r.Post("/shaped/reset", s.handleShapedReset)

	r.Post("/update", s.handleSelfUpdate)

	// /refcount → пустой объект (для совместимости с панелью)
	r.Get("/refcount", s.handleNoopJSON(map[string]interface{}{}))

	// Stubs для full-эндпоинтов: 200-OK noop. Панель ОБЯЗАНА их не звать
	// (db.get_active_relays(agent_type='full')), но защищаемся на случай ошибки.
	stub := s.handleStub
	r.Post("/whitelist/update", stub)
	r.Post("/whitelist/remove", stub)
	r.Post("/whitelist/sync", stub)
	r.Get("/whitelist/list", stub)
	r.Post("/rate-limit", stub)
	r.Delete("/rate-limit/{ip}", stub)
	r.Get("/rate-limit/{ip}", stub)
	r.Get("/rate-limits", stub)

	return r
}

// ── helpers ──

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("X-Agent-Key") != s.Cfg.AgentSecret {
			writeError(w, http.StatusForbidden, "Invalid agent key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleStub — 200 OK с {agent_type:"min", skipped:true}
func (s *Server) handleStub(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent_type": "min",
		"skipped":    true,
		"message":    "this endpoint is not applicable to min-agent",
	})
}

// handleNoopJSON — отдаёт фиксированный JSON-объект.
func (s *Server) handleNoopJSON(body interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, body)
	}
}
