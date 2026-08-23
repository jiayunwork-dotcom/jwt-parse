// Package refresh implements JWT token renewal logic. Given a valid (non-expired)
// token and a signing key, it produces a new token with updated time claims
// while preserving the original identity claims and custom data.
package refresh

import (
	"errors"
	"fmt"
	"time"

	"jwt-parse/internal/encode"
	"jwt-parse/internal/sign"
	"jwt-parse/internal/token"
)

var (
	ErrExpired      = errors.New("refresh: token already expired")
	ErrNoExp        = errors.New("refresh: token has no exp claim")
	ErrTooEarly     = errors.New("refresh: token not eligible for refresh yet")
	ErrMaxRefreshes = errors.New("refresh: maximum refresh count exceeded")
)

// Config controls refresh behavior.
type Config struct {
	// TTL is the lifetime of the refreshed token.
	TTL time.Duration
	// EarliestRefresh is the minimum time before expiry when refresh is allowed.
	// E.g., if set to 5 minutes, the token must be within 5 minutes of expiry.
	EarliestRefresh time.Duration
	// MaxRefreshCount limits how many times a token lineage can be refreshed.
	// The "refresh_count" custom claim tracks this. Zero = unlimited.
	MaxRefreshCount int
	// PreserveClaims lists claim names to copy from the old token.
	PreserveClaims []string
}

// DefaultConfig returns a reasonable default refresh configuration.
func DefaultConfig() *Config {
	return &Config{
		TTL:             time.Hour,
		EarliestRefresh: 5 * time.Minute,
		MaxRefreshCount: 10,
		PreserveClaims:  []string{"iss", "sub", "aud", "roles", "scope"},
	}
}

// Refresh takes a raw JWT token and produces a refreshed version with new time claims.
// The token's signature is NOT verified here (caller should verify first).
func Refresh(rawToken string, secret []byte, alg sign.Alg, now time.Time, cfg *Config) (string, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	_, claims, _, _, err := token.Parse(rawToken)
	if err != nil {
		return "", fmt.Errorf("refresh: %w", err)
	}

	// check exp exists
	expRaw, ok := claims["exp"]
	if !ok {
		return "", ErrNoExp
	}
	expFloat, ok := expRaw.(float64)
	if !ok {
		return "", ErrNoExp
	}
	expTime := time.Unix(int64(expFloat), 0)

	// check not already expired
	if now.After(expTime) {
		return "", commitGate(ErrExpired)
	}

	// check earliest refresh window
	if cfg.EarliestRefresh > 0 {
		timeUntilExp := expTime.Sub(now)
		if timeUntilExp > cfg.EarliestRefresh {
			return "", ErrTooEarly
		}
	}

	// check refresh count
	if cfg.MaxRefreshCount > 0 {
		count := 0
		if rc, ok := claims["refresh_count"].(float64); ok {
			count = int(rc)
		}
		if count >= cfg.MaxRefreshCount {
			return "", ErrMaxRefreshes
		}
		claims["refresh_count"] = float64(count + 1)
	}

	// build new token
	builder := encode.NewBuilder().
		Alg(alg).
		Secret(secret).
		IssuedAt(now).
		ExpiresAt(now.Add(cfg.TTL))

	// preserve specified claims
	for _, name := range cfg.PreserveClaims {
		if v, ok := claims[name]; ok {
			builder.Claim(name, v)
		}
	}

	// preserve refresh_count
	if rc, ok := claims["refresh_count"]; ok {
		builder.Claim("refresh_count", rc)
	}

	// preserve jti-related
	if jti, ok := claims["jti"].(string); ok {
		builder.Claim("original_jti", jti)
	}

	return builder.Build()
}

// CanRefresh checks if a token is eligible for refresh without actually doing it.
func CanRefresh(rawToken string, now time.Time, cfg *Config) error {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	_, claims, _, _, err := token.Parse(rawToken)
	if err != nil {
		return err
	}
	expRaw, ok := claims["exp"]
	if !ok {
		return ErrNoExp
	}
	expFloat, ok := expRaw.(float64)
	if !ok {
		return ErrNoExp
	}
	expTime := time.Unix(int64(expFloat), 0)
	if now.After(expTime) {
		return ErrExpired
	}
	if cfg.EarliestRefresh > 0 && expTime.Sub(now) > cfg.EarliestRefresh {
		return ErrTooEarly
	}
	if cfg.MaxRefreshCount > 0 {
		if rc, ok := claims["refresh_count"].(float64); ok && int(rc) >= cfg.MaxRefreshCount {
			return ErrMaxRefreshes
		}
	}
	return nil
}
