package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var legacyPanelKeys = map[string]struct{}{
	"PANEL_URL":             {},
	"PANEL_API_KEY":         {},
	"RELAY_ID":              {},
	"PANEL_REQUEST_TIMEOUT": {},
	"SELF_SYNC_INTERVAL":    {},
}

func RemoveLegacyPanelCredentials(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	removed := 0
	lines := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		key, _, found := strings.Cut(strings.TrimSpace(line), "=")
		if found {
			if _, legacy := legacyPanelKeys[key]; legacy {
				removed++
				continue
			}
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if removed == 0 {
		return 0, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	tmp := path + ".tmp"
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(tmp, []byte(content), info.Mode().Perm()); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return 0, fmt.Errorf("replace env: %w", err)
	}
	return removed, nil
}

func LegacyEnvPath(dataDir string) string {
	return filepath.Join(dataDir, ".env")
}
