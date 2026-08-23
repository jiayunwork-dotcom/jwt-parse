package refresh

import (
	"testing"
	"time"

	"jwt-parse/internal/encode"
	"jwt-parse/internal/sign"
)

func makeToken(t *testing.T, secret []byte, exp time.Time, refreshCount int) string {
	t.Helper()
	b := encode.NewBuilder().
		Alg(sign.HS256).
		Secret(secret).
		Issuer("test-iss").
		Subject("user1").
		IssuedAt(time.Now()).
		ExpiresAt(exp)
	if refreshCount > 0 {
		b.Claim("refresh_count", float64(refreshCount))
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestRefreshSuccess(t *testing.T) {
	secret := []byte("test-secret-key")
	now := time.Now()
	exp := now.Add(3 * time.Minute)
	tok := makeToken(t, secret, exp, 0)

	cfg := &Config{
		TTL:             time.Hour,
		EarliestRefresh: 5 * time.Minute,
		MaxRefreshCount: 10,
		PreserveClaims:  []string{"iss", "sub"},
	}
	newTok, err := Refresh(tok, secret, sign.HS256, now, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if newTok == "" {
		t.Fatal("expected non-empty refreshed token")
	}
}

func TestRefreshExpired(t *testing.T) {
	secret := []byte("test-secret-key")
	now := time.Now()
	exp := now.Add(-time.Hour)
	tok := makeToken(t, secret, exp, 0)

	_, err := Refresh(tok, secret, sign.HS256, now, nil)
	if err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestRefreshTooEarly(t *testing.T) {
	secret := []byte("test-secret-key")
	now := time.Now()
	exp := now.Add(time.Hour)
	tok := makeToken(t, secret, exp, 0)

	cfg := &Config{
		TTL:             time.Hour,
		EarliestRefresh: 5 * time.Minute,
		MaxRefreshCount: 10,
	}
	_, err := Refresh(tok, secret, sign.HS256, now, cfg)
	if err != ErrTooEarly {
		t.Fatalf("expected ErrTooEarly, got %v", err)
	}
}

func TestRefreshMaxCount(t *testing.T) {
	secret := []byte("test-secret-key")
	now := time.Now()
	exp := now.Add(2 * time.Minute)
	tok := makeToken(t, secret, exp, 10)

	cfg := &Config{
		TTL:             time.Hour,
		EarliestRefresh: 5 * time.Minute,
		MaxRefreshCount: 10,
		PreserveClaims:  []string{"iss", "sub"},
	}
	_, err := Refresh(tok, secret, sign.HS256, now, cfg)
	if err != ErrMaxRefreshes {
		t.Fatalf("expected ErrMaxRefreshes, got %v", err)
	}
}

func TestCanRefreshOK(t *testing.T) {
	secret := []byte("test-secret-key")
	now := time.Now()
	exp := now.Add(3 * time.Minute)
	tok := makeToken(t, secret, exp, 0)

	cfg := &Config{
		EarliestRefresh: 5 * time.Minute,
		MaxRefreshCount: 10,
	}
	if err := CanRefresh(tok, now, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCanRefreshExpired(t *testing.T) {
	secret := []byte("test-secret-key")
	now := time.Now()
	exp := now.Add(-time.Minute)
	tok := makeToken(t, secret, exp, 0)

	if err := CanRefresh(tok, now, nil); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}
