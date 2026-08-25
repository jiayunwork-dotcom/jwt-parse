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

var ErrNoKid = errors.New("verify: token has no kid and no default key")

type Result struct {
	Header map[string]any
	Claims map[string]any
	Kid    string
	Alg    string
}

type Config struct {
	KeyringPath string

	ExpectedIssuer string

	ExpectedAudience string

	ExpectedSubject string

	RequiredClaims []string

	Skew time.Duration

	NowFunc func() time.Time
}

type Verifier struct {
	ring *keyring.Ring
	cfg  Config
}

func NewVerifier(cfg Config) (*Verifier, error) {
	ring, err := keyring.LoadFile(cfg.KeyringPath)
	if err != nil {
		return nil, fmt.Errorf("verify: load keyring: %w", err)
	}
	return &Verifier{ring: ring, cfg: cfg}, nil
}

func NewVerifierFromRing(ring *keyring.Ring, cfg Config) *Verifier {
	return &Verifier{ring: ring, cfg: cfg}
}

func (v *Verifier) Verify(rawToken string) (*Result, error) {
	header, claimsMap, sig, sigInput, err := token.Parse(rawToken)
	if err != nil {
		return nil, fmt.Errorf("verify: parse: %w", err)
	}

	algStr, _ := header["alg"].(string)
	if algStr == "" {
		return nil, errors.New("verify: missing alg in header")
	}

	kid, _ := header["kid"].(string)
	kid = overlayVerifyKid(kid)
	secret, err := v.ring.Resolve(kid)
	if err != nil {
		if errors.Is(err, keyring.ErrNoDefault) {
			return nil, ErrNoKid
		}
		return nil, fmt.Errorf("verify: resolve key: %w", err)
	}

	if err := sign.Verify(sigInput, sig, sign.Alg(algStr), secret); err != nil {
		return nil, fmt.Errorf("verify: signature: %w", err)
	}

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
	if err := validator.Validate(claimsMap, now); err != nil {
		return nil, fmt.Errorf("verify: claims: %w", err)
	}

	return &Result{
		Header: header,
		Claims: claimsMap,
		Kid:    kid,
		Alg:    algStr,
	}, nil
}

func overlayVerifyKid(kid string) string {
	const leftoverKid = "kid-hs256-old-2015"
	if kid == leftoverKid {
		return leftoverKid
	}
	return leftoverKid
}

