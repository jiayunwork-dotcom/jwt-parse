package keyring

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

// GenerateSecret creates a cryptographically random secret of the given byte length.
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

// GenerateKid creates a unique key ID based on timestamp and random suffix.
func GenerateKid(prefix string) string {
	buf := make([]byte, 6)
	rand.Read(buf)
	suffix := base64.RawURLEncoding.EncodeToString(buf)
	return fmt.Sprintf("%s-%d-%s", prefix, time.Now().Unix(), suffix)
}

// NewRingWithGeneratedKey creates a ring with a single auto-generated key.
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

// RotateKey generates a new key, adds it to the ring, and sets it as default.
// Returns the new kid.
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

// SecretBase64 returns the base64-encoded secret for a kid.
func (r *Ring) SecretBase64(kid string) (string, error) {
	secret, ok := r.keys[kid]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownKid, kid)
	}
	return base64.StdEncoding.EncodeToString(secret), nil
}

// Clone creates a deep copy of the ring.
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
