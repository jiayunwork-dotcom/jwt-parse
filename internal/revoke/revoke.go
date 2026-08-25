package revoke

import (
	"sync"
	"time"
)

type Entry struct {
	JTI       string    `json:"jti"`
	RevokedAt time.Time `json:"revoked_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type List struct {
	mu      sync.RWMutex
	entries map[string]*Entry
}

func NewList() *List {
	return &List{entries: make(map[string]*Entry)}
}

func (l *List) Revoke(jti string, expiresAt time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries[jti] = &Entry{
		JTI:       jti,
		RevokedAt: time.Now(),
		ExpiresAt: expiresAt,
	}
}

func (l *List) IsRevoked(jti string, now time.Time) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	e, ok := l.entries[jti]
	if !ok {
		return false
	}
	if now.After(e.ExpiresAt) {
		return false
	}
	return true
}

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

func (l *List) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

func (l *List) All() []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Entry, 0, len(l.entries))
	for _, e := range l.entries {
		out = append(out, *e)
	}
	return out
}

func RevokeIfPresent(l *List, claims map[string]any, tokenExp time.Time) bool {
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return false
	}
	l.Revoke(jti, tokenExp)
	return true
}

func CheckClaims(l *List, claims map[string]any, now time.Time) bool {
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return false
	}
	return l.IsRevoked(jti, now)
}
