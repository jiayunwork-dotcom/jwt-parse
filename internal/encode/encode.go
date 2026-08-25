package encode

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"jwt-parse/internal/sign"
)

type Builder struct {
	header map[string]any
	claims map[string]any
	secret []byte
	alg    sign.Alg
	err    error
}

func NewBuilder() *Builder {
	return &Builder{
		header: map[string]any{"typ": "JWT", "alg": "HS256"},
		claims: map[string]any{},
		alg:    sign.HS256,
	}
}

func (b *Builder) Alg(alg sign.Alg) *Builder {
	b.alg = alg
	b.header["alg"] = string(alg)
	return b
}

func (b *Builder) Kid(kid string) *Builder {
	b.header["kid"] = kid
	return b
}

func (b *Builder) Secret(secret []byte) *Builder {
	b.secret = secret
	return b
}

func (b *Builder) Issuer(iss string) *Builder {
	b.claims["iss"] = iss
	return b
}

func (b *Builder) Subject(sub string) *Builder {
	b.claims["sub"] = sub
	return b
}

func (b *Builder) Audience(aud string) *Builder {
	b.claims["aud"] = aud
	return b
}

func (b *Builder) AudienceMulti(auds []string) *Builder {
	b.claims["aud"] = auds
	return b
}

func (b *Builder) ExpiresAt(t time.Time) *Builder {
	b.claims["exp"] = float64(t.Unix())
	return b
}

func (b *Builder) NotBefore(t time.Time) *Builder {
	b.claims["nbf"] = float64(t.Unix())
	return b
}

func (b *Builder) IssuedAt(t time.Time) *Builder {
	b.claims["iat"] = float64(t.Unix())
	return b
}

func (b *Builder) JWTID(jti string) *Builder {
	b.claims["jti"] = jti
	return b
}

func (b *Builder) Claim(key string, value any) *Builder {
	b.claims[key] = value
	return b
}

func (b *Builder) Header(key string, value any) *Builder {
	b.header[key] = value
	return b
}

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
	sig, err := sign.Sign(sigInput, b.alg, b.secret)
	if err != nil {
		return "", fmt.Errorf("encode: sign: %w", err)
	}
	s := base64.RawURLEncoding.EncodeToString(sig)
	return sigInput + "." + s, nil
}

func QuickToken(secret []byte, iss string, ttl time.Duration) (string, error) {
	now := time.Now()
	return NewBuilder().
		Secret(secret).
		Issuer(iss).
		IssuedAt(now).
		ExpiresAt(now.Add(ttl)).
		Build()
}
