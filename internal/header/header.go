package header

import (
	"errors"
	"fmt"
)

var (
	ErrMissingAlg    = errors.New("header: missing 'alg' field")
	ErrAlgNotAllowed = errors.New("header: algorithm not in allowlist")
	ErrAlgNoneReject = errors.New("header: 'none' algorithm rejected by policy")
	ErrTypMismatch   = errors.New("header: unexpected 'typ' value")
	ErrCritUnknown   = errors.New("header: unknown critical extension")
)

type Parsed struct {
	Alg   string
	Typ   string
	Kid   string
	Cty   string
	Crit  []string
	Extra map[string]any
}

func Parse(raw map[string]any) *Parsed {
	p := &Parsed{Extra: make(map[string]any)}
	if alg, ok := raw["alg"].(string); ok {
		p.Alg = alg
	}
	if typ, ok := raw["typ"].(string); ok {
		p.Typ = typ
	}
	if kid, ok := raw["kid"].(string); ok {
		p.Kid = kid
	}
	if cty, ok := raw["cty"].(string); ok {
		p.Cty = cty
	}
	if crit, ok := raw["crit"].([]any); ok {
		for _, c := range crit {
			if s, ok := c.(string); ok {
				p.Crit = append(p.Crit, s)
			}
		}
	}
	for k, v := range raw {
		switch k {
		case "alg", "typ", "kid", "cty", "crit":
		default:
			p.Extra[k] = v
		}
	}
	return p
}

type Policy struct {
	AllowedAlgs   []string
	RequireKid    bool
	RequireTyp    bool
	RejectNone    bool
	KnownCritExts []string
}

func DefaultPolicy() *Policy {
	return &Policy{
		AllowedAlgs: []string{"HS256", "HS384", "HS512"},
		RejectNone:  true,
		RequireKid:  false,
		RequireTyp:  false,
	}
}

func (pol *Policy) Validate(h *Parsed) error {
	if h.Alg == "" {
		return ErrMissingAlg
	}
	if pol.RejectNone && h.Alg == "none" {
		return ErrAlgNoneReject
	}
	if len(pol.AllowedAlgs) > 0 && !contains(pol.AllowedAlgs, h.Alg) {
		return fmt.Errorf("%w: %s", ErrAlgNotAllowed, h.Alg)
	}
	if pol.RequireKid && h.Kid == "" {
		return errors.New("header: kid required but missing")
	}
	if pol.RequireTyp && h.Typ != "JWT" {
		return fmt.Errorf("%w: got %q", ErrTypMismatch, h.Typ)
	}
	for _, ext := range h.Crit {
		if !contains(pol.KnownCritExts, ext) {
			return fmt.Errorf("%w: %s", ErrCritUnknown, ext)
		}
	}
	return nil
}

func contains(list []string, item string) bool {
	for _, s := range list {
		if s == item {
			return true
		}
	}
	return false
}

func IsSymmetric(alg string) bool {
	switch alg {
	case "HS256", "HS384", "HS512":
		return true
	}
	return false
}

func IsAsymmetric(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512":
		return true
	}
	return false
}
