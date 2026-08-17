package selfupdate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readStatus(t *testing.T, path string) Status {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var status Status
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestReleaseVersion(t *testing.T) {
	full := &Updater{Version: "2.2.17"}
	min := &Updater{Version: "2.2.17-min"}
	if full.releaseVersion() != "2.2.17" || min.releaseVersion() != "2.2.17" {
		t.Fatalf("unexpected versions: full=%s min=%s", full.releaseVersion(), min.releaseVersion())
	}
}

func TestFinalizePending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update_status.json")
	u := &Updater{StatusPath: path, Version: "2.2.17-min"}
	u.saveStatus(Status{
		Restarting: true,
		OldVersion: "2.2.16-min",
		NewVersion: "2.2.17",
		StartedAt:  nowISO(),
	})

	u.FinalizePending()
	status := readStatus(t, path)
	if !status.OK || status.Restarting || status.FinishedAt == "" {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestFinalizePendingVersionMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update_status.json")
	u := &Updater{StatusPath: path, Version: "2.2.16"}
	u.saveStatus(Status{
		Restarting: true,
		NewVersion: "2.2.17",
		StartedAt:  nowISO(),
	})

	u.FinalizePending()
	status := readStatus(t, path)
	if status.OK || status.Restarting || status.Error != "restart verification failed" {
		t.Fatalf("unexpected status: %+v", status)
	}
}
