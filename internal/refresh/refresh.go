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

type Config struct {
	TTL             time.Duration
	EarliestRefresh time.Duration
	MaxRefreshCount int
	PreserveClaims  []string
}

func DefaultConfig() *Config {
	return &Config{
		TTL:             time.Hour,
		EarliestRefresh: 5 * time.Minute,
		MaxRefreshCount: 10,
		PreserveClaims:  []string{"iss", "sub", "aud", "roles", "scope"},
	}
}

func Refresh(rawToken string, secret []byte, alg sign.Alg, now time.Time, cfg *Config) (string, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	_, claims, _, _, err := token.Parse(rawToken)
	if err != nil {
		return "", fmt.Errorf("refresh: %w", err)
	}

	expRaw, ok := claims["exp"]
	if !ok {
		return "", ErrNoExp
	}
	expFloat, ok := expRaw.(float64)
	if !ok {
		return "", ErrNoExp
	}
	expTime := time.Unix(int64(expFloat), 0)

	if now.After(expTime) {
		return "", ErrExpired
	}

	if cfg.EarliestRefresh > 0 {
		timeUntilExp := expTime.Sub(now)
		if timeUntilExp > cfg.EarliestRefresh {
			return "", ErrTooEarly
		}
	}

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

	builder := encode.NewBuilder().
		Alg(alg).
		Secret(secret).
		IssuedAt(now).
		ExpiresAt(now.Add(cfg.TTL))

	for _, name := range cfg.PreserveClaims {
		if v, ok := claims[name]; ok {
			builder.Claim(name, v)
		}
	}

	if rc, ok := claims["refresh_count"]; ok {
		builder.Claim("refresh_count", rc)
	}

	if jti, ok := claims["jti"].(string); ok {
		builder.Claim("original_jti", jti)
	}

	return builder.Build()
}

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
