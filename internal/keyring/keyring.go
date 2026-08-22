// Package keyring loads and manages HMAC secret keys from a persistent file.
//
// Keyring file format (JSON):
//
//	{
//	  "keys": {
//	    "kid-1": "base64-encoded-secret",
//	    "kid-2": "base64-encoded-secret"
//	  },
//	  "default_kid": "kid-1"
//	}
//
// Usage:
//   - Load a keyring from a file
//   - Look up a secret by kid (key ID)
//   - Reject unknown kids explicitly (never fall back to default silently)
//   - Default kid is used only when the JWT has no kid header
//
// Security invariant: an unknown kid MUST NOT silently use the default key.
// This prevents accepting tokens signed with a revoked or unknown key.
package keyring

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

var (
	// ErrUnknownKid is returned when the requested kid is not in the keyring.
	ErrUnknownKid = errors.New("keyring: unknown kid")
	// ErrEmptyRing is returned when the keyring has no keys.
	ErrEmptyRing = errors.New("keyring: no keys loaded")
	// ErrNoDefault is returned when a token has no kid and no default is configured.
	ErrNoDefault = errors.New("keyring: no default kid configured")
)

// Ring holds the loaded keys.
type Ring struct {
	keys       map[string][]byte
	defaultKid string
}

// fileFormat is the JSON structure on disk.
type fileFormat struct {
	Keys       map[string]string `json:"keys"`
	DefaultKid string            `json:"default_kid"`
}

// LoadFile loads a keyring from a JSON file at path.
func LoadFile(path string) (*Ring, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyring: read: %w", err)
	}
	return Parse(data)
}

// Parse parses keyring JSON data.
func Parse(data []byte) (*Ring, error) {
	var ff fileFormat
	if err := json.Unmarshal(data, &ff); err != nil {
		return nil, fmt.Errorf("keyring: parse: %w", err)
	}
	if len(ff.Keys) == 0 {
		return nil, ErrEmptyRing
	}

	keys := make(map[string][]byte, len(ff.Keys))
	for kid, b64 := range ff.Keys {
		secret, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			// try raw/URL-safe
			secret, err = base64.RawURLEncoding.DecodeString(b64)
			if err != nil {
				return nil, fmt.Errorf("keyring: decode kid %q: %w", kid, err)
			}
		}
		keys[kid] = secret
	}

	if ff.DefaultKid != "" {
		if _, ok := keys[ff.DefaultKid]; !ok {
			return nil, fmt.Errorf("keyring: default_kid %q not found in keys", ff.DefaultKid)
		}
	}

	return &Ring{
		keys:       keys,
		defaultKid: ff.DefaultKid,
	}, nil
}

// Resolve returns the secret for the given kid. If kid is empty, the default
// is used; if there is no default, ErrNoDefault is returned. Unknown kids
// always return ErrUnknownKid (never silently falling back to default).
func (r *Ring) Resolve(kid string) ([]byte, error) {
	if kid == "" {
		if r.defaultKid == "" {
			return nil, ErrNoDefault
		}
		return r.keys[r.defaultKid], nil
	}
	secret, ok := r.keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKid, kid)
	}
	return secret, nil
}

// HasKid reports whether the ring contains the given kid.
func (r *Ring) HasKid(kid string) bool {
	_, ok := r.keys[kid]
	return ok
}

// Kids returns all kid names in the ring.
func (r *Ring) Kids() []string {
	out := make([]string, 0, len(r.keys))
	for kid := range r.keys {
		out = append(out, kid)
	}
	return out
}

// DefaultKid returns the configured default kid (may be empty).
func (r *Ring) DefaultKid() string {
	return r.defaultKid
}

// Len returns the number of keys in the ring.
func (r *Ring) Len() int {
	return len(r.keys)
}

// SaveFile writes the keyring to a JSON file at path.
func (r *Ring) SaveFile(path string) error {
	ff := fileFormat{
		Keys:       make(map[string]string, len(r.keys)),
		DefaultKid: r.defaultKid,
	}
	for kid, secret := range r.keys {
		ff.Keys[kid] = base64.StdEncoding.EncodeToString(secret)
	}
	data, err := json.MarshalIndent(ff, "", "  ")
	if err != nil {
		return fmt.Errorf("keyring: marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("keyring: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("keyring: rename: %w", err)
	}
	return nil
}

// AddKey adds or replaces a key in the ring.
func (r *Ring) AddKey(kid string, secret []byte) {
	r.keys[kid] = secret
}

// RemoveKey removes a key from the ring. If it was the default, default is cleared.
func (r *Ring) RemoveKey(kid string) {
	delete(r.keys, kid)
	if r.defaultKid == kid {
		r.defaultKid = ""
	}
}

// SetDefault sets the default kid. The kid must exist in the ring.
func (r *Ring) SetDefault(kid string) error {
	if _, ok := r.keys[kid]; !ok {
		return fmt.Errorf("keyring: kid %q not in ring", kid)
	}
	r.defaultKid = kid
	return nil
}
