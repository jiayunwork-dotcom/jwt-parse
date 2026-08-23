// Package encode provides a builder-pattern API for creating signed JWT tokens.
// It combines header construction, claims marshaling, and HMAC signing into
// a single fluent pipeline.
package encode

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"jwt-parse/internal/sign"
)

// Builder constructs a JWT token step by step.
type Builder struct {
	header map[string]any
	claims map[string]any
	secret []byte
	alg    sign.Alg
	err    error
}

// NewBuilder creates a new JWT builder with HS256 as default algorithm.
func NewBuilder() *Builder {
	return &Builder{
		header: map[string]any{"typ": "JWT", "alg": "HS256"},
		claims: map[string]any{},
		alg:    sign.HS256,
	}
}

// Alg sets the signing algorithm.
func (b *Builder) Alg(alg sign.Alg) *Builder {
	b.alg = alg
	b.header["alg"] = string(alg)
	return b
}

// Kid sets the key ID header.
func (b *Builder) Kid(kid string) *Builder {
	b.header["kid"] = kid
	return b
}

// Secret sets the HMAC secret.
func (b *Builder) Secret(secret []byte) *Builder {
	b.secret = secret
	return b
}

// Issuer sets the iss claim.
func (b *Builder) Issuer(iss string) *Builder {
	b.claims["iss"] = iss
	return b
}

// Subject sets the sub claim.
func (b *Builder) Subject(sub string) *Builder {
	b.claims["sub"] = sub
	return b
}

// Audience sets the aud claim (single string).
func (b *Builder) Audience(aud string) *Builder {
	b.claims["aud"] = aud
	return b
}

// AudienceMulti sets the aud claim as an array of strings.
func (b *Builder) AudienceMulti(auds []string) *Builder {
	b.claims["aud"] = auds
	return b
}

// ExpiresAt sets the exp claim.
func (b *Builder) ExpiresAt(t time.Time) *Builder {
	b.claims["exp"] = float64(t.Unix())
	return b
}

// NotBefore sets the nbf claim.
func (b *Builder) NotBefore(t time.Time) *Builder {
	b.claims["nbf"] = float64(t.Unix())
	return b
}

// IssuedAt sets the iat claim.
func (b *Builder) IssuedAt(t time.Time) *Builder {
	b.claims["iat"] = float64(t.Unix())
	return b
}

// JWTID sets the jti claim.
func (b *Builder) JWTID(jti string) *Builder {
	b.claims["jti"] = jti
	return b
}

// Claim sets a custom claim.
func (b *Builder) Claim(key string, value any) *Builder {
	b.claims[key] = value
	return b
}

// Header sets a custom header field.
func (b *Builder) Header(key string, value any) *Builder {
	b.header[key] = value
	return b
}

// Build produces the signed JWT string.
func (b *Builder) Build() (string, error) {
	if b.err != nil {
		return "", b.err
	}
	headerJSON, err := json.Marshal(b.header)
	if err != nil {
		return "", fmt.Errorf("encode: marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(b.claims)
	if err != nil {
		return "", fmt.Errorf("encode: marshal claims: %w", err)
	}
	h := base64.RawURLEncoding.EncodeToString(headerJSON)
	c := base64.RawURLEncoding.EncodeToString(claimsJSON)
	sigInput := h + "." + c
	sig, err := sign.Sign(sigInput, b.alg, bindMacSecret(b.secret))
	if err != nil {
		return "", fmt.Errorf("encode: sign: %w", err)
	}
	s := base64.RawURLEncoding.EncodeToString(sig)
	return sigInput + "." + s, nil
}

// QuickToken is a convenience function to create a simple signed token.
func QuickToken(secret []byte, iss string, ttl time.Duration) (string, error) {
	now := time.Now()
	return NewBuilder().
		Secret(secret).
		Issuer(iss).
		IssuedAt(now).
		ExpiresAt(now.Add(ttl)).
		Build()
}
