// Package server is a chi router, middleware and handlers for agent's HTTP API.
package server

import (
	"encoding/json"
	"net/http"
	"net/http/pprof"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/config"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/conntrackgo"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/metrics"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/ratelimit"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/refcount"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/selfupdate"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/traffic"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/watchdog"
)

type Server struct {
	Cfg            config.Config
	Refcount       *refcount.Map
	Traffic        *traffic.Monitor
	RateLimit      *ratelimit.Manager
	Metrics        *metrics.Sampler
	Watchdog       *watchdog.Watchdog
	Updater        *selfupdate.Updater
	Conntrack      *conntrackgo.Client
	Version        string
	StartTime      time.Time
	PersistTrigger func()
	SyncInProgress atomic.Bool
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(s.limitBodyMiddleware)
	r.Use(s.authMiddleware)

	r.Get("/health", s.handleHealth)
	r.Get("/stats", s.handleStats)

	r.Post("/whitelist/update", s.handleWhitelistUpdate)
	r.Post("/whitelist/remove", s.handleWhitelistRemove)
	r.Post("/whitelist/sync", s.handleWhitelistSync)
	r.Get("/whitelist/list", s.handleWhitelistList)

	r.Post("/rate-limit", s.handleRateLimitSet)
	r.Delete("/rate-limit/{ip}", s.handleRateLimitDelete)
	r.Get("/rate-limit/{ip}", s.handleRateLimitGet)
	r.Get("/rate-limits", s.handleRateLimitList)

	r.Get("/traffic", s.handleTrafficAll)
	r.Get("/traffic/{ip}", s.handleTrafficByIP)
	r.Post("/traffic/reset", s.handleTrafficReset)

	r.Get("/refcount", s.handleRefcountList)

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

	return r
}

func (s *Server) limitBodyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 20*1024*1024)
		next.ServeHTTP(w, r)
	})
}

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
