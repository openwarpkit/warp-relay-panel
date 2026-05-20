package server

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/ipsetgo"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/ratelimit"
	"github.com/nellimonix/warp-relay-panel/relay-agent/internal/shell"
)

type ipReq struct {
	IP string `json:"ip"`
}

type ipUpdateReq struct {
	NewIP    string `json:"new_ip"`
	OldIP    string `json:"old_ip,omitempty"`
	ClientID *int64 `json:"client_id,omitempty"`
}

type syncEntry struct {
	IP       string `json:"ip"`
	ClientID int64  `json:"client_id"`
}

type syncRateLimitEntry struct {
	IP        string  `json:"ip"`
	Mbps      float64 `json:"mbps"`
	ExpiresAt string  `json:"expires_at,omitempty"`
	ClientID  *int64  `json:"client_id,omitempty"`
}

type syncReq struct {
	Clients []syncEntry `json:"clients"`
	// pointer: nil = поле отсутствует (старая panel) — лимиты не трогаем.
	// pointer to [] = явный пустой массив — снять все локальные.
	RateLimits *[]syncRateLimitEntry `json:"rate_limits,omitempty"`
}

func (s *Server) handleWhitelistUpdate(w http.ResponseWriter, r *http.Request) {
	var req ipUpdateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "invalid json")
		return
	}
	if !shell.ValidIPv4(req.NewIP) {
		writeError(w, 400, "Invalid new_ip: "+req.NewIP)
		return
	}
	if req.OldIP != "" && !shell.ValidIPv4(req.OldIP) {
		writeError(w, 400, "Invalid old_ip: "+req.OldIP)
		return
	}

	removed := ""
	if req.ClientID != nil {
		canRemove := s.Refcount.Add(req.NewIP, *req.ClientID, req.OldIP)
		if req.OldIP != "" && canRemove {
			s.deleteIP(req.OldIP)
			removed = req.OldIP
		} else if req.OldIP != "" {
			log.Printf("Keeping %s in ipset (refcount=%d)", req.OldIP, s.Refcount.Count(req.OldIP))
		}
	} else if req.OldIP != "" {
		s.deleteIP(req.OldIP)
		removed = req.OldIP
	}
	if err := ipsetgo.Add(s.Cfg.IpsetName, req.NewIP); err != nil {
		log.Printf("ipset add %s: %v", req.NewIP, err)
	}
	if s.PersistTrigger != nil {
		s.PersistTrigger()
	}

	writeJSON(w, 200, map[string]interface{}{
		"added":     req.NewIP,
		"removed":   removed,
		"client_id": req.ClientID,
		"refcount":  s.Refcount.Count(req.NewIP),
	})
}

// deleteIP — атомарное удаление: ipset del + conntrack flush для UDP-флоу.
func (s *Server) deleteIP(ip string) {
	if err := ipsetgo.Del(s.Cfg.IpsetName, ip); err != nil {
		log.Printf("ipset del %s: %v", ip, err)
	}
	if err := s.Conntrack.DeleteBySrcUDP(ip); err != nil {
		log.Printf("conntrack delete %s: %v", ip, err)
	}
}

func (s *Server) handleWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	var req ipReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "invalid json")
		return
	}
	if !shell.ValidIPv4(req.IP) {
		writeError(w, 400, "Invalid ip: "+req.IP)
		return
	}
	canRemove := s.Refcount.RemoveClient(req.IP, 0)
	if canRemove {
		s.deleteIP(req.IP)
		if s.PersistTrigger != nil {
			s.PersistTrigger()
		}
		writeJSON(w, 200, map[string]string{"removed": req.IP})
		return
	}
	rc := s.Refcount.Count(req.IP)
	log.Printf("Keeping %s in ipset (refcount=%d)", req.IP, rc)
	writeJSON(w, 200, map[string]interface{}{
		"removed": nil, "kept": req.IP, "refcount": rc,
	})
}

// handleWhitelistSync — fire-and-forget, тяжёлая работа в горутине.
func (s *Server) handleWhitelistSync(w http.ResponseWriter, r *http.Request) {
	var req syncReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "invalid json")
		return
	}
	total := len(req.Clients)
	totalRL := -1 // -1 = поле отсутствует, лимиты не трогаем
	if req.RateLimits != nil {
		totalRL = len(*req.RateLimits)
	}
	go s.doSync(req.Clients, req.RateLimits)
	writeJSON(w, 200, map[string]interface{}{
		"accepted":             true,
		"received":             total,
		"received_rate_limits": totalRL,
		"message":              "Sync started in background",
		"check_status":         "GET /health → last_sync",
	})
}

// doSync — фоновая обработка sync payload.
// rlEntries == nil — поле "rate_limits" отсутствует в payload (старая panel
// или manual curl) → шейпинг не трогаем (чтобы случайно не снести лимиты).
// rlEntries != nil — даже если пустой → diff-replace (полная синхронизация).
func (s *Server) doSync(entries []syncEntry, rlEntries *[]syncRateLimitEntry) {
	startedAt := time.Now().In(time.FixedZone("MSK", 3*3600)).Format(time.RFC3339)
	statusInit := map[string]interface{}{
		"ok": nil, "in_progress": true,
		"total":      len(entries),
		"started_at": startedAt,
	}
	if rlEntries != nil {
		statusInit["total_rate_limits"] = len(*rlEntries)
	}
	s.saveSyncStatus(statusInit)

	valid := []syncEntry{}
	invalid := 0
	for _, e := range entries {
		if shell.ValidIPv4(e.IP) {
			valid = append(valid, e)
		} else {
			invalid++
		}
	}

	if err := ipsetgo.Create(s.Cfg.IpsetName, 1000000); err != nil {
		log.Printf("ipset create %s: %v", s.Cfg.IpsetName, err)
	}
	if err := ipsetgo.Flush(s.Cfg.IpsetName); err != nil {
		s.saveSyncStatus(map[string]interface{}{
			"ok": false, "in_progress": false,
			"error":       "flush failed: " + err.Error(),
			"started_at":  startedAt,
			"finished_at": time.Now().In(time.FixedZone("MSK", 3*3600)).Format(time.RFC3339),
		})
		return
	}

	uniqueIPs := make(map[string]struct{}, len(valid))
	rcEntries := make(map[string][]int64, len(valid))
	for _, e := range valid {
		uniqueIPs[e.IP] = struct{}{}
		rcEntries[e.IP] = append(rcEntries[e.IP], e.ClientID)
	}
	for ip := range uniqueIPs {
		if err := ipsetgo.Add(s.Cfg.IpsetName, ip); err != nil {
			log.Printf("ipset add %s: %v", ip, err)
		}
	}
	s.Refcount.SetAll(rcEntries)
	shell.Run("ipset save > /etc/ipset.rules 2>/dev/null", 10*time.Second)

	// Rate-limits: применить пришедшие batch'ем + удалить stale (которых нет в payload).
	// Это даёт «полную пересинхронизацию» — после Sync шейпинг 1-в-1 соответствует БД.
	// rlEntries == nil → старая panel или manual curl без поля → шейпинг не трогаем.
	statusFin := map[string]interface{}{
		"ok": true, "in_progress": false,
		"synced":      len(uniqueIPs),
		"clients":     len(valid),
		"invalid":     invalid,
		"started_at":  startedAt,
		"finished_at": time.Now().In(time.FixedZone("MSK", 3*3600)).Format(time.RFC3339),
	}
	if rlEntries != nil {
		appliedRL, removedRL, invalidRL := s.syncRateLimits(*rlEntries)
		statusFin["rate_limits_applied"] = appliedRL
		statusFin["rate_limits_removed"] = removedRL
		statusFin["rate_limits_invalid"] = invalidRL
		log.Printf("Sync complete: %d IPs, %d clients, %d invalid, %d rate-limits applied, %d stale removed",
			len(uniqueIPs), len(valid), invalid, appliedRL, removedRL)
	} else {
		log.Printf("Sync complete: %d IPs, %d clients, %d invalid (rate_limits not in payload — skipped)",
			len(uniqueIPs), len(valid), invalid)
	}
	s.saveSyncStatus(statusFin)
}

// syncRateLimits применяет batch + удаляет stale (которых нет в payload).
// Вызывается только когда rate_limits явно есть в payload (даже пустой []).
func (s *Server) syncRateLimits(entries []syncRateLimitEntry) (applied, removed, invalid int) {
	if s.RateLimit == nil {
		return 0, 0, 0
	}
	items := make([]ratelimit.SetItem, 0, len(entries))
	incoming := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if !shell.ValidIPv4(e.IP) || e.Mbps <= 0 {
			invalid++
			continue
		}
		items = append(items, ratelimit.SetItem{
			IP:        e.IP,
			Mbps:      e.Mbps,
			ExpiresAt: e.ExpiresAt,
			ClientID:  e.ClientID,
		})
		incoming[e.IP] = struct{}{}
	}

	if len(items) > 0 {
		out, errs := s.RateLimit.SetBatch(items)
		applied = len(out)
		invalid += len(errs)
	}

	// Diff: всё что есть в локальном state, но нет в payload — снимаем.
	var stale []string
	for _, l := range s.RateLimit.All() {
		if _, ok := incoming[l.IP]; !ok {
			stale = append(stale, l.IP)
		}
	}
	if len(stale) > 0 {
		s.RateLimit.RemoveBatch(stale)
		removed = len(stale)
	}
	return applied, removed, invalid
}

func (s *Server) handleWhitelistList(w http.ResponseWriter, r *http.Request) {
	members, err := ipsetgo.Members(s.Cfg.IpsetName)
	if err != nil {
		writeJSON(w, 200, map[string]interface{}{"ips": []string{}, "error": err.Error()})
		return
	}
	ips := make([]string, 0, len(members))
	for ip := range members {
		ips = append(ips, ip)
	}
	writeJSON(w, 200, map[string]interface{}{"ips": ips, "count": len(ips)})
}
