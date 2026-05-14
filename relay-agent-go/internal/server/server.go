// Package server — chi router, middleware и хендлеры HTTP API агента.
package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openwarpkit/warp-relay-agent/internal/config"
	"github.com/openwarpkit/warp-relay-agent/internal/conntrackgo"
	"github.com/openwarpkit/warp-relay-agent/internal/metrics"
	"github.com/openwarpkit/warp-relay-agent/internal/ratelimit"
	"github.com/openwarpkit/warp-relay-agent/internal/refcount"
	"github.com/openwarpkit/warp-relay-agent/internal/selfupdate"
	"github.com/openwarpkit/warp-relay-agent/internal/traffic"
	"github.com/openwarpkit/warp-relay-agent/internal/watchdog"
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
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
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

	return r
}

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
