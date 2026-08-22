package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// ErrMalformed is returned when the token does not have exactly 3 segments.
var ErrMalformed = errors.New("jwt: malformed token (expected 3 segments)")

// ErrInvalidBase64 is returned when a segment is not valid base64url.
var ErrInvalidBase64 = errors.New("jwt: invalid base64url segment")

func decodeSegment(seg string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, ErrInvalidBase64
	}
	return b, nil
}

// Parse splits a JWT into its header, payload (claims), raw signature bytes and
// the signing input (header.payload). It validates segment count and base64url
// encoding but does NOT verify the signature or claims; callers decide that.
func Parse(t string) (header map[string]any, claims map[string]any, sig []byte, signingInput string, err error) {
	parts := strings.Split(t, ".")
	if len(parts) != 3 {
		return nil, nil, nil, "", ErrMalformed
	}
	hb, err := decodeSegment(parts[0])
	if err != nil {
		return nil, nil, nil, "", err
	}
	pb, err := decodeSegment(parts[1])
	if err != nil {
		return nil, nil, nil, "", err
	}
	sig, err = decodeSegment(parts[2])
	if err != nil {
		return nil, nil, nil, "", err
	}
	if e := json.Unmarshal(hb, &header); e != nil {
		return nil, nil, nil, "", ErrInvalidBase64
	}
	if e := json.Unmarshal(pb, &claims); e != nil {
		return nil, nil, nil, "", ErrInvalidBase64
	}
	return header, claims, sig, parts[0] + "." + parts[1], nil
}

// Build creates a signed JWT string from the given parts. The signature is
// computed by the caller (or can be nil for "none" algorithm tokens).
func Build(header map[string]any, claims map[string]any, sig []byte) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	h := base64.RawURLEncoding.EncodeToString(hb)
	c := base64.RawURLEncoding.EncodeToString(cb)
	s := base64.RawURLEncoding.EncodeToString(sig)
	return h + "." + c + "." + s, nil
}

// Header extracts just the header without fully parsing the token.
func Header(t string) (map[string]any, error) {
	parts := strings.SplitN(t, ".", 2)
	if len(parts) < 1 {
		return nil, ErrMalformed
	}
	hb, err := decodeSegment(parts[0])
	if err != nil {
		return nil, err
	}
	var h map[string]any
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, ErrInvalidBase64
	}
	return h, nil
}

// SigningInput returns the header.payload portion used for signature verification.
func SigningInput(t string) (string, error) {
	idx := strings.LastIndex(t, ".")
	if idx < 0 {
		return "", ErrMalformed
	}
	input := t[:idx]
	if !strings.Contains(input, ".") {
		return "", ErrMalformed
	}
	return input, nil
}
