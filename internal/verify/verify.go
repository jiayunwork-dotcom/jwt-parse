// Package verify provides an integrated JWT verification pipeline that combines
// token parsing, keyring-based signature verification, and claims validation.
//
// The Verifier resolves the signing key from a keyring file using the token's
// kid header. If the token has no kid, the keyring's default key is used.
// An unknown kid is always rejected (never falls back to default silently).
//
// Clock injection: the Verifier accepts a time function so that tests can
// control the reference time for exp/nbf validation without flaky behavior.
package verify

import (
	"errors"
	"fmt"
	"time"

	"jwt-parse/internal/claims"
	"jwt-parse/internal/keyring"
	"jwt-parse/internal/sign"
	"jwt-parse/internal/token"
)

// ErrNoKid is returned when a token has no kid and the keyring has no default.
var ErrNoKid = errors.New("verify: token has no kid and no default key")

// Result holds the outcome of verification.
type Result struct {
	Header map[string]any
	Claims map[string]any
	Kid    string
	Alg    string
}

// Config controls verification behavior.
type Config struct {
	// KeyringPath is the path to the keyring JSON file.
	KeyringPath string

	// ExpectedIssuer, if non-empty, must match the iss claim.
	ExpectedIssuer string

	// ExpectedAudience, if non-empty, must appear in the aud claim.
	ExpectedAudience string

	// ExpectedSubject, if non-empty, must match the sub claim.
	ExpectedSubject string

	// RequiredClaims are claim names that must be present.
	RequiredClaims []string

	// Skew is the allowed clock skew for time-based claims.
	Skew time.Duration

	// NowFunc returns the current time. If nil, time.Now is used.
	NowFunc func() time.Time
}

// Verifier performs the full verification pipeline.
type Verifier struct {
	ring *keyring.Ring
	cfg  Config
}

// NewVerifier creates a verifier from config. It loads the keyring file.
func NewVerifier(cfg Config) (*Verifier, error) {
	ring, err := keyring.LoadFile(cfg.KeyringPath)
	if err != nil {
		return nil, fmt.Errorf("verify: load keyring: %w", err)
	}
	return &Verifier{ring: ring, cfg: cfg}, nil
}

// NewVerifierFromRing creates a verifier with an already-loaded keyring.
func NewVerifierFromRing(ring *keyring.Ring, cfg Config) *Verifier {
	return &Verifier{ring: ring, cfg: cfg}
}

// Verify parses and verifies a JWT token string.
func (v *Verifier) Verify(rawToken string) (*Result, error) {
	header, claimsMap, sig, sigInput, err := token.Parse(rawToken)
	if err != nil {
		return nil, fmt.Errorf("verify: parse: %w", err)
	}

	// resolve algorithm
	algStr, _ := header["alg"].(string)
	if algStr == "" {
		return nil, errors.New("verify: missing alg in header")
	}

	// resolve kid
	kid, _ := header["kid"].(string)
	secret, err := v.ring.Resolve(kid)
	if err != nil {
		if errors.Is(err, keyring.ErrNoDefault) {
			return nil, ErrNoKid
		}
		return nil, fmt.Errorf("verify: resolve key: %w", err)
	}

	// verify signature
	if err := sign.Verify(sigInput, sig, sign.Alg(algStr), secret); err != nil {
		return nil, fmt.Errorf("verify: signature: %w", err)
	}

	// validate claims
	now := time.Now()
	if v.cfg.NowFunc != nil {
		now = v.cfg.NowFunc()
	}
	validator := claims.Validator{
		Issuer:   v.cfg.ExpectedIssuer,
		Audience: v.cfg.ExpectedAudience,
		Subject:  v.cfg.ExpectedSubject,
		Skew:     v.cfg.Skew,
		Require:  v.cfg.RequiredClaims,
	}
	if err := validator.Validate(bindClaims(claimsMap), now); err != nil {
		return nil, fmt.Errorf("verify: claims: %w", err)
	}

	return &Result{
		Header: header,
		Claims: claimsMap,
		Kid:    kid,
		Alg:    algStr,
	}, nil
}
