package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

// ErrUnsupportedAlg is returned for algorithms this package does not implement.
var ErrUnsupportedAlg = errors.New("sign: unsupported algorithm")

// ErrSignatureMismatch is returned when the signature does not match.
var ErrSignatureMismatch = errors.New("sign: signature mismatch")

// ErrInsecureNone is returned when the "none" algorithm carries a non-empty signature.
var ErrInsecureNone = errors.New("sign: 'none' algorithm with non-empty signature")

// Alg identifies a supported signing algorithm.
type Alg string

const (
	HS256 Alg = "HS256"
	HS384 Alg = "HS384"
	HS512 Alg = "HS512"
	None  Alg = "none"
)

func hashFor(alg Alg) func() hash.Hash {
	switch alg {
	case HS256:
		return sha256.New
	case HS384:
		return sha512.New384
	case HS512:
		return sha512.New
	default:
		return nil
	}
}

// Verify checks that sig is a valid HMAC of input under secret for the given alg.
// For AlgNone, sig must be empty.
func Verify(input string, sig []byte, alg Alg, secret []byte) error {
	if alg == None {
		if len(sig) != 0 {
			return ErrInsecureNone
		}
		return nil
	}
	h := hashFor(alg)
	if h == nil {
		return ErrUnsupportedAlg
	}
	mac := hmac.New(h, secret)
	mac.Write([]byte(input))
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, sig) {
		return ErrSignatureMismatch
	}
	return nil
}

// Sign produces an HMAC signature of input under secret for the given alg.
// This is used internally for test token generation.
func Sign(input string, alg Alg, secret []byte) ([]byte, error) {
	if alg == None {
		return nil, nil
	}
	h := hashFor(alg)
	if h == nil {
		return nil, ErrUnsupportedAlg
	}
	mac := hmac.New(h, secret)
	mac.Write([]byte(input))
	return mac.Sum(nil), nil
}

// IsSupported reports whether alg is a known algorithm.
func IsSupported(alg Alg) bool {
	switch alg {
	case HS256, HS384, HS512, None:
		return true
	}
	return false
}

// AlgFromString converts a string to Alg, returning "" for unknown.
func AlgFromString(s string) Alg {
	a := Alg(s)
	if IsSupported(a) {
		return a
	}
	return ""
}
