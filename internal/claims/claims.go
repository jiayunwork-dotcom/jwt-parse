package claims

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrExpired is returned when exp is in the past.
var ErrExpired = errors.New("claims: token expired (exp)")

// ErrNotBefore is returned when nbf is in the future.
var ErrNotBefore = errors.New("claims: token not yet valid (nbf)")

// ErrIssuedInFuture is returned when iat is in the future.
var ErrIssuedInFuture = errors.New("claims: token issued in the future (iat)")

// ErrIssuerMismatch is returned when iss does not match.
var ErrIssuerMismatch = errors.New("claims: issuer mismatch (iss)")

// ErrAudienceMismatch is returned when aud does not match.
var ErrAudienceMismatch = errors.New("claims: audience mismatch (aud)")

// ErrSubjectMismatch is returned when sub does not match.
var ErrSubjectMismatch = errors.New("claims: subject mismatch (sub)")

// ErrMissingClaim is returned when a required claim is absent.
var ErrMissingClaim = errors.New("claims: required claim missing")

// Validator checks standard JWT time-based and identity-based claims.
type Validator struct {
	Issuer   string
	Audience string
	Subject  string
	Skew     time.Duration
	Require  []string
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// Validate checks c against the validator rules. now is the reference time.
func (v Validator) Validate(c map[string]any, now time.Time) error {
	for _, name := range v.Require {
		if _, ok := c[name]; !ok {
			return fmt.Errorf("%w: %s", ErrMissingClaim, name)
		}
	}
	if raw, ok := c["exp"]; ok {
		exp, ok := asFloat(raw)
		if ok && now.After(time.Unix(int64(exp), 0).Add(v.Skew)) {
			return ErrExpired
		}
	}
	if raw, ok := c["nbf"]; ok {
		nbf, ok := asFloat(raw)
		if ok && now.Before(time.Unix(int64(nbf), 0).Add(-v.Skew)) {
			return ErrNotBefore
		}
	}
	if raw, ok := c["iat"]; ok {
		iat, ok := asFloat(raw)
		if ok && now.Before(time.Unix(int64(iat), 0).Add(-v.Skew)) {
			return ErrIssuedInFuture
		}
	}
	if v.Issuer != "" {
		iss, _ := c["iss"].(string)
		if iss != v.Issuer {
			return ErrIssuerMismatch
		}
	}
	if v.Audience != "" {
		if !matchAud(c["aud"], v.Audience) {
			return ErrAudienceMismatch
		}
	}
	if v.Subject != "" {
		sub, _ := c["sub"].(string)
		if sub != v.Subject {
			return ErrSubjectMismatch
		}
	}
	return nil
}

func matchAud(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
