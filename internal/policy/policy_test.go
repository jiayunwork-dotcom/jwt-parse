package policy

import (
	"testing"
	"time"
)

func TestDefaultPolicyRejectsNone(t *testing.T) {
	pol := DefaultPolicy()
	header := map[string]any{"alg": "none"}
	claims := map[string]any{"exp": float64(time.Now().Add(time.Hour).Unix())}
	viols := pol.Evaluate(header, claims, time.Now())
	if len(viols) == 0 {
		t.Error("expected none rejection")
	}
}

func TestDefaultPolicyAcceptsHS256(t *testing.T) {
	pol := DefaultPolicy()
	header := map[string]any{"alg": "HS256"}
	claims := map[string]any{"exp": float64(time.Now().Add(time.Hour).Unix())}
	viols := pol.Evaluate(header, claims, time.Now())
	if len(viols) != 0 {
		t.Errorf("unexpected violations: %+v", viols)
	}
}

func TestStrictPolicyRequiresClaims(t *testing.T) {
	pol := StrictPolicy()
	header := map[string]any{"alg": "HS256"}
	claims := map[string]any{}
	viols := pol.Evaluate(header, claims, time.Now())
	if len(viols) < 5 {
		t.Errorf("violations = %d, want >= 5", len(viols))
	}
}

func TestMaxAge(t *testing.T) {
	pol := &Policy{MaxAge: time.Hour, AllowedAlgs: []string{"HS256"}}
	header := map[string]any{"alg": "HS256"}
	now := time.Now()
	oldIat := float64(now.Add(-2 * time.Hour).Unix())
	claims := map[string]any{"iat": oldIat}
	viols := pol.Evaluate(header, claims, now)
	found := false
	for _, v := range viols {
		if v.Code == "TOO_OLD" {
			found = true
		}
	}
	if !found {
		t.Error("expected TOO_OLD violation")
	}
}

func TestIsAllowed(t *testing.T) {
	pol := DefaultPolicy()
	header := map[string]any{"alg": "HS256"}
	claims := map[string]any{"exp": float64(time.Now().Add(time.Hour).Unix())}
	if !pol.IsAllowed(header, claims, time.Now()) {
		t.Error("expected allowed")
	}
}
