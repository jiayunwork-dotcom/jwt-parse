// Package revoke provides a JTI-based token revocation list. It tracks
// revoked token IDs (jti claims) and supports time-based expiry of entries
// so the list does not grow unbounded.
package revoke

import (
	"sync"
	"time"
)

// Entry records a revoked JTI with its expiration time.
type Entry struct {
	JTI       string    `json:"jti"`
	RevokedAt time.Time `json:"revoked_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// List manages the revocation list in memory.
type List struct {
	mu      sync.RWMutex
	entries map[string]*Entry
}

// NewList creates an empty revocation list.
func NewList() *List {
	return &List{entries: make(map[string]*Entry)}
}

// Revoke adds a JTI to the revocation list. The entry expires at expiresAt
// (typically matching the token's exp claim so the entry is cleaned up after
// the token would have expired anyway).
func (l *List) Revoke(jti string, expiresAt time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries[jti] = &Entry{
		JTI:       jti,
		RevokedAt: time.Now(),
		ExpiresAt: expiresAt,
	}
}

// IsRevoked returns true if the given JTI is in the revocation list and
// has not yet expired.
func (l *List) IsRevoked(jti string, now time.Time) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	e, ok := l.entries[jti]
	if !ok {
		return false
	}
	// entry expired → no longer revoked (token itself expired)
	if now.After(e.ExpiresAt) {
		return false
	}
	return true
}

// Cleanup removes expired entries from the list.
func (l *List) Cleanup(now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	removed := 0
	for jti, e := range l.entries {
		if now.After(e.ExpiresAt) {
			delete(l.entries, jti)
			removed++
		}
	}
	return removed
}

// Len returns the current number of entries.
func (l *List) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

// All returns a copy of all current entries.
func (l *List) All() []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Entry, 0, len(l.entries))
	for _, e := range l.entries {
		out = append(out, *e)
	}
	return out
}

// RevokeIfPresent revokes the JTI only if it has a claims["jti"] field.
// Returns true if the token was revoked.
func RevokeIfPresent(l *List, claims map[string]any, tokenExp time.Time) bool {
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return false
	}
	l.Revoke(jti, tokenExp)
	return true
}

// CheckClaims checks if the token's jti claim is revoked.
func CheckClaims(l *List, claims map[string]any, now time.Time) bool {
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return false // no jti → cannot be revoked
	}
	return l.IsRevoked(jti, now)
}
