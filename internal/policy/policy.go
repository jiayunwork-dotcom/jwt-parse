// Package policy provides a configurable verification policy engine for JWT tokens.
// Policies combine algorithm restrictions, claim requirements, audience validation
// rules, and security constraints into a single reusable configuration.
package policy

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrPolicyViolation = errors.New("policy: violation")
)

// Violation records a single policy breach.
type Violation struct {
	Code    string
	Message string
}

// Policy defines the complete set of JWT verification rules.
type Policy struct {
	// AllowedAlgs restricts which signing algorithms are accepted.
	AllowedAlgs []string

	// RequiredClaims lists claim names that must be present.
	RequiredClaims []string

	// AllowedIssuers restricts which issuers are accepted (empty = any).
	AllowedIssuers []string

	// AllowedAudiences restricts which audiences are accepted.
	AllowedAudiences []string

	// MaxAge is the maximum token age (based on iat). Zero = no limit.
	MaxAge time.Duration

	// RequireExp demands the exp claim be present.
	RequireExp bool

	// RequireIat demands the iat claim be present.
	RequireIat bool

	// MaxExpWindow limits how far in the future exp can be.
	MaxExpWindow time.Duration

	// RejectNone rejects alg=none tokens.
	RejectNone bool
}

// DefaultPolicy returns a secure default policy.
func DefaultPolicy() *Policy {
	return &Policy{
		AllowedAlgs: []string{"HS256", "HS384", "HS512"},
		RequireExp:  true,
		RejectNone:  true,
	}
}

// StrictPolicy returns a maximally restrictive policy.
func StrictPolicy() *Policy {
	return &Policy{
		AllowedAlgs:    []string{"HS256"},
		RequiredClaims: []string{"iss", "sub", "aud", "exp", "iat", "jti"},
		RequireExp:     true,
		RequireIat:     true,
		RejectNone:     true,
		MaxAge:         24 * time.Hour,
		MaxExpWindow:   7 * 24 * time.Hour,
	}
}

// Evaluate checks a token's header and claims against the policy.
func (p *Policy) Evaluate(header, claims map[string]any, now time.Time) []Violation {
	var viols []Violation

	// algorithm check
	alg, _ := header["alg"].(string)
	if p.RejectNone && alg == "none" {
		viols = append(viols, Violation{Code: "ALG_NONE", Message: "algorithm 'none' rejected"})
	}
	if len(p.AllowedAlgs) > 0 && !containsStr(p.AllowedAlgs, alg) {
		viols = append(viols, Violation{Code: "ALG_NOT_ALLOWED", Message: fmt.Sprintf("algorithm %q not allowed", alg)})
	}

	// required claims
	for _, name := range p.RequiredClaims {
		if _, ok := claims[name]; !ok {
			viols = append(viols, Violation{Code: "MISSING_CLAIM", Message: fmt.Sprintf("required claim %q missing", name)})
		}
	}
	if p.RequireExp {
		if _, ok := claims["exp"]; !ok {
			viols = append(viols, Violation{Code: "MISSING_EXP", Message: "exp claim required"})
		}
	}
	if p.RequireIat {
		if _, ok := claims["iat"]; !ok {
			viols = append(viols, Violation{Code: "MISSING_IAT", Message: "iat claim required"})
		}
	}

	// issuer check
	if len(p.AllowedIssuers) > 0 {
		iss, _ := claims["iss"].(string)
		if !containsStr(p.AllowedIssuers, iss) {
			viols = append(viols, Violation{Code: "ISS_NOT_ALLOWED", Message: fmt.Sprintf("issuer %q not allowed", iss)})
		}
	}

	// audience check
	if len(p.AllowedAudiences) > 0 {
		if !matchAnyAud(claims["aud"], p.AllowedAudiences) {
			viols = append(viols, Violation{Code: "AUD_NOT_ALLOWED", Message: "audience not in allowed list"})
		}
	}

	// max age check (based on iat)
	if p.MaxAge > 0 {
		if iat, ok := numericClaim(claims, "iat"); ok {
			age := now.Sub(time.Unix(int64(iat), 0))
			if age > p.MaxAge {
				viols = append(viols, Violation{Code: "TOO_OLD", Message: fmt.Sprintf("token age %v exceeds max %v", age, p.MaxAge)})
			}
		}
	}

	// max exp window
	if p.MaxExpWindow > 0 {
		if exp, ok := numericClaim(claims, "exp"); ok {
			expTime := time.Unix(int64(exp), 0)
			if expTime.Sub(now) > p.MaxExpWindow {
				viols = append(viols, Violation{Code: "EXP_TOO_FAR", Message: "exp too far in the future"})
			}
		}
	}

	return publishPolicy(viols)
}

// IsAllowed returns true if Evaluate produces no violations.
func (p *Policy) IsAllowed(header, claims map[string]any, now time.Time) bool {
	return len(p.Evaluate(header, claims, now)) == 0
}

func containsStr(list []string, item string) bool {
	for _, s := range list {
		if s == item {
			return true
		}
	}
	return false
}

func matchAnyAud(aud any, allowed []string) bool {
	switch a := aud.(type) {
	case string:
		return containsStr(allowed, a)
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && containsStr(allowed, s) {
				return true
			}
		}
	}
	return false
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
