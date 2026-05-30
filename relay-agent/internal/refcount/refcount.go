// Package refcount хранит, сколько клиентов сидят за одним IP.
// Persistent JSON на диске + thread-safe in-memory map.
package refcount

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

type Map struct {
	mu   sync.Mutex
	m    map[string]map[int64]struct{}
	path string
}

func New(path string) *Map {
	r := &Map{m: make(map[string]map[int64]struct{}), path: path}
	r.load()
	return r
}

func (r *Map) load() {
	data, err := os.ReadFile(r.path)
	if err != nil {
		return
	}
	var raw map[string][]int64
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Printf("refcount: load error: %v", err)
		return
	}
	for ip, cids := range raw {
		set := make(map[int64]struct{}, len(cids))
		for _, c := range cids {
			set[c] = struct{}{}
		}
		r.m[ip] = set
	}
	log.Printf("refcount loaded: %d IPs", len(r.m))
}

func (r *Map) save() {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		log.Printf("refcount: mkdir error: %v", err)
		return
	}
	out := make(map[string][]int64, len(r.m))
	for ip, set := range r.m {
		if len(set) == 0 {
			continue
		}
		ids := make([]int64, 0, len(set))
		for id := range set {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		out[ip] = ids
	}
	data, _ := json.MarshalIndent(out, "", "  ")

	tmpPath := r.path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		log.Printf("refcount: create tmp file error: %v", err)
		return
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		log.Printf("refcount: write tmp file error: %v", err)
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		log.Printf("refcount: sync tmp file error: %v", err)
		return
	}
	if err := f.Close(); err != nil {
		log.Printf("refcount: close tmp file error: %v", err)
		return
	}
	if err := os.Rename(tmpPath, r.path); err != nil {
		log.Printf("refcount: rename error: %v", err)
	}
}

// Add возвращает true, если для oldIP refcount упал до 0 (можно удалять из ipset).
func (r *Map) Add(ip string, clientID int64, oldIP string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	canRemoveOld := false
	if oldIP != "" {
		if set, ok := r.m[oldIP]; ok {
			delete(set, clientID)
			if len(set) == 0 {
				delete(r.m, oldIP)
				canRemoveOld = true
			}
		}
	}
	if _, ok := r.m[ip]; !ok {
		r.m[ip] = make(map[int64]struct{})
	}
	r.m[ip][clientID] = struct{}{}
	r.save()
	return canRemoveOld
}

// RemoveClient удаляет клиента (или всех, если clientID==0).
// Возвращает true, если для IP больше нет клиентов.
func (r *Map) RemoveClient(ip string, clientID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	set, ok := r.m[ip]
	if !ok || len(set) == 0 {
		delete(r.m, ip)
		r.save()
		return true
	}
	if clientID != 0 {
		delete(set, clientID)
	} else {
		for k := range set {
			delete(set, k)
		}
	}
	if len(set) == 0 {
		delete(r.m, ip)
		r.save()
		return true
	}
	r.save()
	return false
}

// SetAll полностью заменяет содержимое.
func (r *Map) SetAll(entries map[string][]int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m = make(map[string]map[int64]struct{}, len(entries))
	for ip, cids := range entries {
		set := make(map[int64]struct{}, len(cids))
		for _, c := range cids {
			set[c] = struct{}{}
		}
		r.m[ip] = set
	}
	r.save()
}

func (r *Map) Count(ip string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m[ip])
}

func (r *Map) ClientsFor(ip string) []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	set := r.m[ip]
	out := make([]int64, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// All возвращает копию всей карты для эндпоинта /refcount.
func (r *Map) All() map[string][]int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string][]int64, len(r.m))
	for ip, set := range r.m {
		if len(set) == 0 {
			continue
		}
		ids := make([]int64, 0, len(set))
		for id := range set {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		out[ip] = ids
	}
	return out
}

// IPs возвращает список всех IP (для пересборки ipset из refcount).
func (r *Map) IPs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.m))
	for ip, set := range r.m {
		if len(set) > 0 {
			out = append(out, ip)
		}
	}
	sort.Strings(out)
	return out
}
