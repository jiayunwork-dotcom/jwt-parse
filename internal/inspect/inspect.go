// Package inspect provides diagnostic utilities for JWT tokens without
// performing verification. It extracts structural information, detects
// potential issues, and formats human-readable summaries.
package inspect

import (
	"fmt"
	"strings"
	"time"

	"jwt-parse/internal/token"
)

// Info holds the inspection results for a JWT.
type Info struct {
	Valid      bool              `json:"valid"`       // structurally valid (3 parts, valid base64)
	Algorithm string            `json:"algorithm"`
	Type      string            `json:"type"`
	Kid       string            `json:"kid,omitempty"`
	Issuer    string            `json:"issuer,omitempty"`
	Subject   string            `json:"subject,omitempty"`
	Audience  string            `json:"audience,omitempty"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
	IssuedAt  *time.Time        `json:"issued_at,omitempty"`
	NotBefore *time.Time        `json:"not_before,omitempty"`
	JWTID     string            `json:"jti,omitempty"`
	Expired   bool              `json:"expired"`
	Issues    []string          `json:"issues,omitempty"`
	Header    map[string]any    `json:"header"`
	Claims    map[string]any    `json:"claims"`
}

// Inspect performs a structural analysis of a JWT token without verifying
// the signature. It reports all detectable issues.
func Inspect(rawToken string, now time.Time) *Info {
	info := &Info{}
	header, claims, _, _, err := token.Parse(rawToken)
	if err != nil {
		info.Valid = false
		info.Issues = append(info.Issues, fmt.Sprintf("parse error: %v", err))
		return info
	}
	info.Valid = true
	info.Header = header
	info.Claims = claims

	// extract header fields
	info.Algorithm, _ = header["alg"].(string)
	info.Type, _ = header["typ"].(string)
	info.Kid, _ = header["kid"].(string)

	// extract claims
	info.Issuer, _ = claims["iss"].(string)
	info.Subject, _ = claims["sub"].(string)
	info.JWTID, _ = claims["jti"].(string)
	if aud, ok := claims["aud"].(string); ok {
		info.Audience = aud
	} else if auds, ok := claims["aud"].([]any); ok {
		strs := make([]string, 0, len(auds))
		for _, a := range auds {
			if s, ok := a.(string); ok {
				strs = append(strs, s)
			}
		}
		info.Audience = strings.Join(strs, ", ")
	}

	// time claims
	if exp, ok := numericClaim(claims, "exp"); ok {
		t := time.Unix(int64(exp), 0)
		info.ExpiresAt = &t
		if now.After(t) {
			info.Expired = bindExpired(true)
			if info.Expired {
				info.Issues = append(info.Issues, "token is expired")
			}
		}
	}
	if iat, ok := numericClaim(claims, "iat"); ok {
		t := time.Unix(int64(iat), 0)
		info.IssuedAt = &t
		if now.Before(t) {
			info.Issues = append(info.Issues, "iat is in the future")
		}
	}
	if nbf, ok := numericClaim(claims, "nbf"); ok {
		t := time.Unix(int64(nbf), 0)
		info.NotBefore = &t
		if now.Before(t) {
			info.Issues = append(info.Issues, "token not yet valid (nbf)")
		}
	}

	// security checks
	if info.Algorithm == "" {
		info.Issues = append(info.Issues, "missing 'alg' in header")
	} else if info.Algorithm == "none" {
		info.Issues = append(info.Issues, "insecure algorithm 'none'")
	}
	if info.ExpiresAt == nil {
		info.Issues = append(info.Issues, "no expiration (exp) claim")
	}

	return info
}

func numericClaim(claims map[string]any, name string) (float64, bool) {
	raw, ok := claims[name]
	if !ok {
		return 0, false
	}
	switch v := raw.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	}
	return 0, false
}

// Summary returns a human-readable one-line summary of the token.
func (info *Info) Summary() string {
	if !info.Valid {
		return "INVALID token (parse error)"
	}
	status := "VALID"
	if info.Expired {
		status = "EXPIRED"
	}
	if len(info.Issues) > 0 && !info.Expired {
		status = "WARNING"
	}
	parts := []string{status, "alg=" + info.Algorithm}
	if info.Kid != "" {
		parts = append(parts, "kid="+info.Kid)
	}
	if info.Issuer != "" {
		parts = append(parts, "iss="+info.Issuer)
	}
	return strings.Join(parts, " ")
}

// IssueCount returns the number of detected issues.
func (info *Info) IssueCount() int {
	return len(info.Issues)
}
