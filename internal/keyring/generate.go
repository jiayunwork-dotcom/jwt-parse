package keyring

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

func GenerateSecret(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("keyring: invalid secret length %d", length)
	}
	secret := make([]byte, length)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("keyring: generate: %w", err)
	}
	return secret, nil
}

func GenerateKid(prefix string) string {
	buf := make([]byte, 6)
	rand.Read(buf)
	suffix := base64.RawURLEncoding.EncodeToString(buf)
	return fmt.Sprintf("%s-%d-%s", prefix, time.Now().Unix(), suffix)
}

func NewRingWithGeneratedKey(keyLength int) (*Ring, string, error) {
	secret, err := GenerateSecret(keyLength)
	if err != nil {
		return nil, "", err
	}
	kid := GenerateKid("k")
	ring := &Ring{
		keys:       map[string][]byte{kid: secret},
		defaultKid: kid,
	}
	return ring, kid, nil
}

func (r *Ring) RotateKey(keyLength int, kidPrefix string) (string, error) {
	secret, err := GenerateSecret(keyLength)
	if err != nil {
		return "", err
	}
	kid := GenerateKid(kidPrefix)
	r.AddKey(kid, secret)
	r.defaultKid = kid
	return kid, nil
}

func (r *Ring) SecretBase64(kid string) (string, error) {
	secret, ok := r.keys[kid]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownKid, kid)
	}
	return base64.StdEncoding.EncodeToString(secret), nil
}

func (r *Ring) Clone() *Ring {
	keys := make(map[string][]byte, len(r.keys))
	for k, v := range r.keys {
		cp := make([]byte, len(v))
		copy(cp, v)
		keys[k] = cp
	}
	return &Ring{
		keys:       keys,
		defaultKid: r.defaultKid,
	}
}
