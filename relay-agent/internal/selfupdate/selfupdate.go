// Package selfupdate - git pull repository to update configs/scripts,
// download fresh binary from GitHub Releases (slim VPS - no `make build`),
// atomic swap and restart via systemd.
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
	"sync"
	"syscall"
	"time"
)

// DefaultReleaseRepo - owner/repo on GitHub, from where we pull binaries.
// Override via env AGENT_RELEASE_REPO=user/repo.
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
	RepoDir     string // /opt/warp-relay-panel - only needed for git pull of scripts
	InstallDir  string // /opt/warp-relay-agent
	StatusPath  string
	Version     string
	BinaryName  string // "warp-relay-agent" or "warp-relay-agent-min"
	ReleaseRepo string // owner/repo, defaults to DefaultReleaseRepo
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
	if err := os.MkdirAll(filepath.Dir(u.StatusPath), 0o750); err != nil {
		log.Printf("selfupdate: mkdir error: %v", err)
		return
	}
	tmpPath := u.StatusPath + ".tmp"
	// #nosec G304 -- Status file path is controlled by config
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		log.Printf("selfupdate: saveStatus error (create tmp): %v", err)
		return
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		log.Printf("selfupdate: saveStatus error (write tmp): %v", err)
		return
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		log.Printf("selfupdate: saveStatus error (sync tmp): %v", err)
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		log.Printf("selfupdate: saveStatus error (close tmp): %v", err)
		return
	}
	if err := os.Rename(tmpPath, u.StatusPath); err != nil {
		_ = os.Remove(tmpPath)
		log.Printf("selfupdate: saveStatus error (rename): %v", err)
	}
}

func (u *Updater) LastStatus() *Status {
	// #nosec G304 -- Status file path is controlled by config
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

// fetchLatestRelease - pulls the latest release from GitHub API,
// returns asset URL for our binary.
func (u *Updater) fetchLatestRelease() (tag, assetURL string, err error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", u.repo())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("github api: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

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

// downloadBinary - downloads fresh binary to a temp file next to the target.
func (u *Updater) downloadBinary(url, tmpPath string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("invalid download url: %w", err)
	}
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download status %d", resp.StatusCode)
	}

	// #nosec G302,G304 -- Executable file needs run permissions, path is from config
	out, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	defer func() { _ = out.Close() }()

	n, err := io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if n < 1024*1024 { // <1 MB - certainly a corrupted binary
		return fmt.Errorf("downloaded binary too small: %d bytes", n)
	}
	return nil
}

// runShell - lightweight wrapper instead of a separate shell package.
func runShell(cmd string, timeout time.Duration) (rc int, out string, errOut string) {
	// #nosec G204 -- Intentional shell execution for updates
	c := exec.Command("bash", "-c", cmd)
	stdout, _ := c.StdoutPipe()
	stderr, _ := c.StderrPipe()
	if err := c.Start(); err != nil {
		return -1, "", err.Error()
	}
	var wg sync.WaitGroup
	var outB, errB strings.Builder
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(&outB, stdout) }()
	go func() { defer wg.Done(); _, _ = io.Copy(&errB, stderr) }()

	timer := time.AfterFunc(timeout, func() { _ = c.Process.Kill() })
	err := c.Wait()
	timer.Stop()
	wg.Wait()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), outB.String(), errB.String()
		}
		return -1, outB.String(), err.Error()
	}
	return 0, outB.String(), errB.String()
}

// Run - git pull (for scripts/configs) -> check latest release ->
// download binary -> atomic swap -> restart.
func (u *Updater) Run() {
	startedAt := nowISO()

	// 1. git pull (ensure_rules.sh, deploy scripts, README) - even if binary won't update.
	lock := filepath.Join(u.RepoDir, ".git", "index.lock")
	_ = os.Remove(lock)

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

	// 3. If tag matches current version - skip download.
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

	// 4. Download binary.
	dstBin := filepath.Join(u.InstallDir, u.binaryName())
	tmpBin := dstBin + ".new"
	if err := u.downloadBinary(assetURL, tmpBin); err != nil {
		_ = os.Remove(tmpBin)
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
		_ = os.Remove(tmpBin)
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

	// 6. ensure_rules.sh from fresh git pull.
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
	log.Printf("Update complete: %s -> %s, restarting via SIGTERM...", u.Version, tag)

	// 7. SIGTERM (delayed, to allow returning a response).
	time.AfterFunc(2*time.Second, func() {
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
