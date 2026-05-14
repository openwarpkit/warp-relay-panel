// Package selfupdate — git pull репозитория, сборка нового бинаря,
// атомарная замена и рестарт через systemd.
package selfupdate

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/openwarpkit/warp-relay-agent/internal/shell"
)

type Status struct {
	OK         bool          `json:"ok"`
	NoChanges  bool          `json:"no_changes,omitempty"`
	Error      string        `json:"error,omitempty"`
	Details    string        `json:"details,omitempty"`
	OldVersion string        `json:"old_version,omitempty"`
	NewVersion string        `json:"new_version,omitempty"`
	StartedAt  string        `json:"started_at"`
	FinishedAt string        `json:"finished_at,omitempty"`
	Steps      []interface{} `json:"steps,omitempty"`
}

type Updater struct {
	RepoDir    string
	InstallDir string
	StatusPath string
	Version    string
}

func nowISO() string {
	return time.Now().In(time.FixedZone("MSK", 3*3600)).Format(time.RFC3339)
}

func (u *Updater) saveStatus(s Status) {
	if err := os.MkdirAll(filepath.Dir(u.StatusPath), 0o755); err != nil {
		log.Printf("selfupdate: mkdir error: %v", err)
		return
	}
	data, _ := json.MarshalIndent(s, "", "  ")
	os.WriteFile(u.StatusPath, data, 0o644)
}

func (u *Updater) LastStatus() *Status {
	data, err := os.ReadFile(u.StatusPath)
	if err != nil {
		return nil
	}
	var s Status
	if err := json.Unmarshal(data, &s); err != nil {
		return nil
	}
	return &s
}

// Run — git pull → make build → cp → systemctl restart.
// Возвращает ошибку только если что-то критичное; иначе всё в Status.
func (u *Updater) Run() {
	startedAt := nowISO()

	// 1. git pull
	lock := filepath.Join(u.RepoDir, ".git", "index.lock")
	os.Remove(lock)

	rc, out, errOut := shell.Run(
		fmt.Sprintf("cd %s && git pull --ff-only 2>&1", u.RepoDir),
		60*time.Second,
	)
	if rc != 0 {
		// retry без --ff-only
		rc, out, errOut = shell.Run(
			fmt.Sprintf("cd %s && git pull 2>&1", u.RepoDir),
			60*time.Second,
		)
	}
	if rc != 0 {
		details := out
		if details == "" {
			details = errOut
		}
		u.saveStatus(Status{
			OK: false, Error: "git pull failed",
			Details:    truncate(details, 500),
			StartedAt:  startedAt,
			FinishedAt: nowISO(),
		})
		log.Printf("Update failed: git pull: %s", details)
		return
	}

	noChanges := strings.Contains(out, "Already up to date") || strings.Contains(out, "Already up-to-date")
	if noChanges {
		u.saveStatus(Status{
			OK: true, NoChanges: true,
			OldVersion: u.Version,
			StartedAt:  startedAt,
			FinishedAt: nowISO(),
		})
		log.Println("No updates available")
		return
	}

	// 2. make build
	rc, _, errOut = shell.Run(
		fmt.Sprintf("cd %s/relay-agent-go && make build 2>&1", u.RepoDir),
		180*time.Second,
	)
	if rc != 0 {
		u.saveStatus(Status{
			OK: false, Error: "build failed",
			Details:    truncate(errOut, 500),
			StartedAt:  startedAt,
			FinishedAt: nowISO(),
		})
		log.Printf("Update failed: build: %s", errOut)
		return
	}

	// 3. atomic swap бинаря
	srcBin := fmt.Sprintf("%s/relay-agent-go/bin/warp-relay-agent", u.RepoDir)
	dstBin := fmt.Sprintf("%s/warp-relay-agent", u.InstallDir)
	tmpBin := dstBin + ".new"
	rc, _, errOut = shell.Run(
		fmt.Sprintf("cp %s %s && chmod +x %s && mv %s %s",
			srcBin, tmpBin, tmpBin, tmpBin, dstBin),
		15*time.Second,
	)
	if rc != 0 {
		u.saveStatus(Status{
			OK: false, Error: "binary swap failed",
			Details:    truncate(errOut, 500),
			StartedAt:  startedAt,
			FinishedAt: nowISO(),
		})
		log.Printf("Update failed: cp/mv: %s", errOut)
		return
	}

	// 4. ensure_rules.sh
	shell.Run(
		fmt.Sprintf("cp %s/relay-agent/ensure_rules.sh %s/ensure_rules.sh && chmod +x %s/ensure_rules.sh",
			u.RepoDir, u.InstallDir, u.InstallDir),
		5*time.Second,
	)

	u.saveStatus(Status{
		OK: true,
		OldVersion: u.Version,
		StartedAt:  startedAt,
		FinishedAt: nowISO(),
	})
	log.Println("Update complete, restarting via systemd...")

	// 5. systemctl restart (отложенный, чтобы успеть отдать ответ)
	cmd := exec.Command("bash", "-c", "sleep 2 && systemctl restart warp-relay-agent")
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Start()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
