package servermin

import (
	"net/http"
	"os"
)

func (s *Server) handleSelfUpdate(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat(s.Cfg.RepoDir + "/.git"); err != nil {
		writeJSON(w, 200, map[string]interface{}{
			"accepted": false,
			"error":    "Git repo not found at " + s.Cfg.RepoDir,
			"hint":     "Install via: git clone <repo> /opt/warp-relay-panel",
		})
		return
	}
	go s.Updater.Run()
	writeJSON(w, 200, map[string]interface{}{
		"accepted":     true,
		"message":      "Update started in background",
		"check_status": "GET /health → last_update",
	})
}
