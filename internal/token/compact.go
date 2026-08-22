package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// CompactSerialize produces the JWS Compact Serialization (header.payload.signature)
// from individual components. This is an alternative to Build() that takes raw bytes.
func CompactSerialize(headerJSON, payloadJSON, signature []byte) string {
	h := base64.RawURLEncoding.EncodeToString(headerJSON)
	p := base64.RawURLEncoding.EncodeToString(payloadJSON)
	s := base64.RawURLEncoding.EncodeToString(signature)
	return h + "." + p + "." + s
}

// CompactDeserialize splits a JWS Compact Serialization into its raw components.
func CompactDeserialize(compact string) (headerJSON, payloadJSON, signature []byte, err error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, nil, nil, ErrMalformed
	}
	headerJSON, err = base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, ErrInvalidBase64
	}
	payloadJSON, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, ErrInvalidBase64
	}
	signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, ErrInvalidBase64
	}
	return
}

// Segments returns the three dot-separated segments without decoding.
func Segments(compact string) (header, payload, sig string, err error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return "", "", "", ErrMalformed
	}
	return parts[0], parts[1], parts[2], nil
}

// UnsafeClaims extracts claims without verifying the signature.
// This is useful for inspecting a token's claims before deciding which key to use.
func UnsafeClaims(compact string) (map[string]any, error) {
	parts := strings.SplitN(compact, ".", 3)
	if len(parts) < 2 {
		return nil, ErrMalformed
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidBase64
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, errors.New("jwt: invalid claims JSON")
	}
	return claims, nil
}

// UnsafeHeader extracts the header without verifying the token.
func UnsafeHeader(compact string) (map[string]any, error) {
	return Header(compact)
}

// PayloadSize returns the decoded payload size in bytes.
func PayloadSize(compact string) (int, error) {
	parts := strings.SplitN(compact, ".", 3)
	if len(parts) < 2 {
		return 0, ErrMalformed
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, ErrInvalidBase64
	}
	return len(payload), nil
}

// SignatureSize returns the decoded signature size in bytes.
func SignatureSize(compact string) (int, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return 0, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, ErrInvalidBase64
	}
	return len(sig), nil
}
