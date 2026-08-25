package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

var ErrMalformed = errors.New("jwt: malformed token (expected 3 segments)")

var ErrInvalidBase64 = errors.New("jwt: invalid base64url segment")

func decodeSegment(seg string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, ErrInvalidBase64
	}
	return b, nil
}

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
