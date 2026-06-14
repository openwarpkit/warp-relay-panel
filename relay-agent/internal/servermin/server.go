// Package servermin is a chi router and handlers for min-agent (no whitelist).
//
// Endpoints that do real work: /health, /stats, /traffic*,
// /shaped, /shaped/reset, /update.
// Endpoints from full-agent (whitelist/*, rate-limit*, refcount) are present
// as 200-OK stubs, so accidental calls from panel do not fail.
package servermin

import (
	"encoding/json"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/config"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/conntrackgo"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/metrics"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/selfupdate"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/sharedlimit"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/traffic"
	"github.com/openwarpkit/warp-relay-panel/relay-agent/internal/watchdog"
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

	// pprof - under the same authMiddleware (X-Agent-Key). Use like this:
	//   curl -H "X-Agent-Key: $SECRET" http://relay:7580/debug/pprof/profile?seconds=60 > cpu.prof
	//   go tool pprof -http=:8081 cpu.prof
	r.Route("/debug/pprof", func(r chi.Router) {
		r.HandleFunc("/", pprof.Index)
		r.HandleFunc("/cmdline", pprof.Cmdline)
		r.HandleFunc("/profile", pprof.Profile)
		r.HandleFunc("/symbol", pprof.Symbol)
		r.HandleFunc("/trace", pprof.Trace)
		for _, name := range []string{
			"goroutine", "heap", "allocs", "threadcreate", "block", "mutex",
		} {
			r.Handle("/"+name, pprof.Handler(name))
		}
	})

	// /refcount -> empty object (for panel compatibility)
	r.Get("/refcount", s.handleNoopJSON(map[string]interface{}{}))

	// Stubs for full endpoints: 200-OK noop. Panel MUST NOT call them
	// (db.get_active_relays(agent_type='full')), but we protect just in case.
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
	_ = enc.Encode(body)
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

// handleStub - 200 OK with {agent_type:"min", skipped:true}
func (s *Server) handleStub(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent_type": "min",
		"skipped":    true,
		"message":    "this endpoint is not applicable to min-agent",
	})
}

// handleNoopJSON - returns fixed JSON object.
func (s *Server) handleNoopJSON(body interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, body)
	}
}
