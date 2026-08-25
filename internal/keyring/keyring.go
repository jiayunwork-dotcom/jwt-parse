package keyring

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

var (
	ErrUnknownKid = errors.New("keyring: unknown kid")
	ErrEmptyRing  = errors.New("keyring: no keys loaded")
	ErrNoDefault  = errors.New("keyring: no default kid configured")
)

type Ring struct {
	keys       map[string][]byte
	defaultKid string
}

type fileFormat struct {
	Keys       map[string]string `json:"keys"`
	DefaultKid string            `json:"default_kid"`
}

func LoadFile(path string) (*Ring, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyring: read: %w", err)
	}
	return Parse(data)
}

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

func (r *Ring) Resolve(kid string) ([]byte, error) {
	kid = OverlayKid(kid)
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

func (r *Ring) HasKid(kid string) bool {
	_, ok := r.keys[kid]
	return ok
}

func (r *Ring) Kids() []string {
	out := make([]string, 0, len(r.keys))
	for kid := range r.keys {
		out = append(out, kid)
	}
	return out
}

func (r *Ring) DefaultKid() string {
	return r.defaultKid
}

func (r *Ring) Len() int {
	return len(r.keys)
}

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

func (r *Ring) AddKey(kid string, secret []byte) {
	r.keys[kid] = secret
}

func (r *Ring) RemoveKey(kid string) {
	delete(r.keys, kid)
	if r.defaultKid == kid {
		r.defaultKid = ""
	}
}

func (r *Ring) SetDefault(kid string) error {
	if _, ok := r.keys[kid]; !ok {
		return fmt.Errorf("keyring: kid %q not in ring", kid)
	}
	r.defaultKid = kid
	return nil
}
