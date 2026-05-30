// Package selfupdate — git pull репозитория для обновления конфигов/скриптов,
// скачивание свежего бинаря из GitHub Releases (slim VPS — без `make build`),
// атомарная замена и рестарт через systemd.
package selfupdate

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// DefaultReleaseRepo — owner/repo на GitHub, откуда тянем бинари.
// Override через env AGENT_RELEASE_REPO=user/repo.
const DefaultReleaseRepo = "nellimonix/warp-relay-panel"

type Status struct {
	OK         bool          `json:"ok"`
	NoChanges  bool          `json:"no_changes,omitempty"`
	Error      string        `json:"error,omitempty"`
	Details    string        `json:"details,omitempty"`
	OldVersion string        `json:"old_version,omitempty"`
	NewVersion string        `json:"new_version,omitempty"`
	ReleaseTag string        `json:"release_tag,omitempty"`
	BinaryName string        `json:"binary_name,omitempty"`
	StartedAt  string        `json:"started_at"`
	FinishedAt string        `json:"finished_at,omitempty"`
	Steps      []interface{} `json:"steps,omitempty"`
}

type Updater struct {
	RepoDir     string // /opt/warp-relay-panel — нужен только для git pull скриптов
	InstallDir  string // /opt/warp-relay-agent
	StatusPath  string
	Version     string
	BinaryName  string // "warp-relay-agent" или "warp-relay-agent-min"
	ReleaseRepo string // owner/repo, по умолчанию DefaultReleaseRepo
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func nowISO() string {
	return time.Now().In(time.FixedZone("MSK", 3*3600)).Format(time.RFC3339)
}

func (u *Updater) repo() string {
	if u.ReleaseRepo != "" {
		return u.ReleaseRepo
	}
	if env := os.Getenv("AGENT_RELEASE_REPO"); env != "" {
		return env
	}
	return DefaultReleaseRepo
}

func (u *Updater) binaryName() string {
	if u.BinaryName != "" {
		return u.BinaryName
	}
	return "warp-relay-agent"
}

func (u *Updater) saveStatus(s Status) {
	if err := os.MkdirAll(filepath.Dir(u.StatusPath), 0o755); err != nil {
		log.Printf("selfupdate: mkdir error: %v", err)
		return
	}
	data, _ := json.MarshalIndent(s, "", "  ")
	tmpPath := u.StatusPath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		log.Printf("selfupdate: saveStatus error (create tmp): %v", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		os.Remove(tmpPath)
		log.Printf("selfupdate: saveStatus error (write tmp): %v", err)
		return
	}
	if err := f.Sync(); err != nil {
		os.Remove(tmpPath)
		log.Printf("selfupdate: saveStatus error (sync tmp): %v", err)
		return
	}
	if err := os.Rename(tmpPath, u.StatusPath); err != nil {
		os.Remove(tmpPath)
		log.Printf("selfupdate: saveStatus error (rename): %v", err)
	}
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

// fetchLatestRelease — тянет latest release с GitHub API,
// возвращает asset URL для нашего бинаря.
func (u *Updater) fetchLatestRelease() (tag, assetURL string, err error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", u.repo())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("github api status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", "", fmt.Errorf("decode release: %w", err)
	}

	binName := u.binaryName()
	for _, a := range rel.Assets {
		if a.Name == binName {
			return rel.TagName, a.BrowserDownloadURL, nil
		}
	}
	return rel.TagName, "", fmt.Errorf("asset %q not found in release %s", binName, rel.TagName)
}

// downloadBinary — скачивает свежий бинарь во временный файл рядом с целевым.
func (u *Updater) downloadBinary(url, tmpPath string) error {
	req, _ := http.NewRequest("GET", url, nil)
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download status %d", resp.StatusCode)
	}

	out, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	defer out.Close()

	n, err := io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if n < 1024*1024 { // <1 MB — заведомо битый бинарь
		return fmt.Errorf("downloaded binary too small: %d bytes", n)
	}
	return nil
}

// runShell — лёгкий wrapper вместо отдельного shell пакета.
func runShell(cmd string, timeout time.Duration) (rc int, out string, errOut string) {
	c := exec.Command("bash", "-c", cmd)
	stdout, _ := c.StdoutPipe()
	stderr, _ := c.StderrPipe()
	if err := c.Start(); err != nil {
		return -1, "", err.Error()
	}
	done := make(chan struct{})
	var outB, errB strings.Builder
	go func() { io.Copy(&outB, stdout); close(done) }()
	go func() { io.Copy(&errB, stderr) }()

	timer := time.AfterFunc(timeout, func() { _ = c.Process.Kill() })
	err := c.Wait()
	timer.Stop()
	<-done
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), outB.String(), errB.String()
		}
		return -1, outB.String(), err.Error()
	}
	return 0, outB.String(), errB.String()
}

// Run — git pull (для скриптов/конфигов) → проверить latest release →
// скачать бинарь → atomic swap → restart.
func (u *Updater) Run() {
	startedAt := nowISO()

	// 1. git pull (ensure_rules.sh, deploy-скрипты, README) — даже если бинарь не обновится.
	lock := filepath.Join(u.RepoDir, ".git", "index.lock")
	os.Remove(lock)

	rc, out, errOut := runShell(
		fmt.Sprintf("cd %s && git pull --ff-only 2>&1", u.RepoDir),
		60*time.Second,
	)
	if rc != 0 {
		rc, out, errOut = runShell(
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

	// 2. Latest release.
	tag, assetURL, err := u.fetchLatestRelease()
	if err != nil {
		u.saveStatus(Status{
			OK: false, Error: "fetch release failed",
			Details:    truncate(err.Error(), 500),
			StartedAt:  startedAt,
			FinishedAt: nowISO(),
		})
		log.Printf("Update failed: fetch release: %v", err)
		return
	}

	// 3. Если tag совпадает с текущей версией — пропустить скачивание.
	tagVersion := strings.TrimPrefix(tag, "agent-v")
	if tagVersion == u.Version {
		u.saveStatus(Status{
			OK: true, NoChanges: true,
			OldVersion: u.Version,
			ReleaseTag: tag,
			BinaryName: u.binaryName(),
			StartedAt:  startedAt,
			FinishedAt: nowISO(),
		})
		log.Printf("No update needed: already on %s", tag)
		return
	}

	// 4. Скачать бинарь.
	dstBin := filepath.Join(u.InstallDir, u.binaryName())
	tmpBin := dstBin + ".new"
	if err := u.downloadBinary(assetURL, tmpBin); err != nil {
		os.Remove(tmpBin)
		u.saveStatus(Status{
			OK: false, Error: "download failed",
			Details:    truncate(err.Error(), 500),
			ReleaseTag: tag,
			StartedAt:  startedAt,
			FinishedAt: nowISO(),
		})
		log.Printf("Update failed: download: %v", err)
		return
	}

	// 5. Atomic swap.
	if err := os.Rename(tmpBin, dstBin); err != nil {
		os.Remove(tmpBin)
		u.saveStatus(Status{
			OK: false, Error: "binary swap failed",
			Details:    truncate(err.Error(), 500),
			ReleaseTag: tag,
			StartedAt:  startedAt,
			FinishedAt: nowISO(),
		})
		log.Printf("Update failed: rename: %v", err)
		return
	}

	// 6. ensure_rules.sh из свежего git pull.
	src := filepath.Join(u.RepoDir, "relay-agent", "deploy", "ensure_rules.sh")
	if u.binaryName() == "warp-relay-agent-min" {
		src = filepath.Join(u.RepoDir, "relay-agent", "deploy", "ensure_rules_min.sh")
	}
	runShell(
		fmt.Sprintf("cp %s %s/ensure_rules.sh && chmod +x %s/ensure_rules.sh",
			src, u.InstallDir, u.InstallDir),
		5*time.Second,
	)

	u.saveStatus(Status{
		OK:         true,
		OldVersion: u.Version,
		NewVersion: tagVersion,
		ReleaseTag: tag,
		BinaryName: u.binaryName(),
		StartedAt:  startedAt,
		FinishedAt: nowISO(),
	})
	log.Printf("Update complete: %s → %s, restarting via SIGTERM...", u.Version, tag)

	// 7. SIGTERM (отложенный, чтобы успеть отдать ответ).
	time.AfterFunc(2*time.Second, func() {
		syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
