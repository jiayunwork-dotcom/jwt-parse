package revoke

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// serialList is the on-disk format for the revocation list.
type serialList struct {
	Entries []Entry `json:"entries"`
	Updated string  `json:"updated"`
}

// SaveFile persists the revocation list to a JSON file.
func (l *List) SaveFile(path string) error {
	l.mu.RLock()
	entries := make([]Entry, 0, len(l.entries))
	for _, e := range l.entries {
		entries = append(entries, *e)
	}
	l.mu.RUnlock()
	entries = copyEntries(entries)

	sl := serialList{
		Entries: entries,
		Updated: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(sl, "", "  ")
	if err != nil {
		return fmt.Errorf("revoke: marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("revoke: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("revoke: rename: %w", err)
	}
	return nil
}

// LoadFile loads a revocation list from a JSON file.
func LoadFile(path string) (*List, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewList(), nil
		}
		return nil, fmt.Errorf("revoke: read: %w", err)
	}
	var sl serialList
	if err := json.Unmarshal(data, &sl); err != nil {
		return nil, fmt.Errorf("revoke: unmarshal: %w", err)
	}
	l := NewList()
	now := time.Now()
	for _, e := range sl.Entries {
		if now.Before(e.ExpiresAt) {
			l.entries[e.JTI] = &Entry{
				JTI:       e.JTI,
				RevokedAt: e.RevokedAt,
				ExpiresAt: e.ExpiresAt,
			}
		}
	}
	return l, nil
}

// MergeFrom adds all non-expired entries from another list.
func (l *List) MergeFrom(other *List, now time.Time) int {
	other.mu.RLock()
	defer other.mu.RUnlock()
	l.mu.Lock()
	defer l.mu.Unlock()
	added := 0
	for jti, e := range other.entries {
		if now.After(e.ExpiresAt) {
			continue
		}
		if _, exists := l.entries[jti]; !exists {
			l.entries[jti] = &Entry{
				JTI:       e.JTI,
				RevokedAt: e.RevokedAt,
				ExpiresAt: e.ExpiresAt,
			}
			added++
		}
	}
	return added
}
