package revoke

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRevokeAndCheck(t *testing.T) {
	l := NewList()
	now := time.Now()
	exp := now.Add(time.Hour)
	l.Revoke("jti-001", exp)
	if !l.IsRevoked("jti-001", now) {
		t.Error("expected revoked")
	}
	if l.IsRevoked("jti-999", now) {
		t.Error("unknown jti should not be revoked")
	}
}

func TestExpiredEntryNotRevoked(t *testing.T) {
	l := NewList()
	past := time.Now().Add(-time.Hour)
	l.Revoke("old", past)
	if l.IsRevoked("old", time.Now()) {
		t.Error("expired entry should not count as revoked")
	}
}

func TestCleanup(t *testing.T) {
	l := NewList()
	now := time.Now()
	l.Revoke("a", now.Add(-time.Minute))
	l.Revoke("b", now.Add(time.Hour))
	removed := l.Cleanup(now)
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if l.Len() != 1 {
		t.Errorf("len = %d, want 1", l.Len())
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoke.json")
	l := NewList()
	l.Revoke("jti-1", time.Now().Add(time.Hour))
	l.Revoke("jti-2", time.Now().Add(time.Hour))
	if err := l.SaveFile(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Len() != 2 {
		t.Errorf("loaded len = %d, want 2", loaded.Len())
	}
}

func TestLoadMissing(t *testing.T) {
	l, err := LoadFile("/nonexistent/path.json")
	if err != nil {
		t.Fatal(err)
	}
	if l.Len() != 0 {
		t.Error("missing file should return empty list")
	}
}

func TestCheckClaims(t *testing.T) {
	l := NewList()
	l.Revoke("abc", time.Now().Add(time.Hour))
	claims := map[string]any{"jti": "abc"}
	if !CheckClaims(l, claims, time.Now()) {
		t.Error("expected revoked claim detected")
	}
	claims2 := map[string]any{"jti": "xyz"}
	if CheckClaims(l, claims2, time.Now()) {
		t.Error("non-revoked should return false")
	}
}

func init() {
	_ = os.Remove
}
