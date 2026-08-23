// Package rotation implements key rotation strategies for HMAC JWT verification.
// During a rotation window, both the old and new keys are accepted for verification,
// but only the new key is used for signing. This enables zero-downtime key rollover.
package rotation

import (
	"errors"
	"time"

	"jwt-parse/internal/keyring"
	"jwt-parse/internal/sign"
)

var (
	ErrNoActiveKey  = errors.New("rotation: no active key")
	ErrWindowClosed = errors.New("rotation: rotation window expired")
)

// State represents the current rotation state.
type State string

const (
	StateStable   State = "stable"   // single active key
	StateRotating State = "rotating" // both old and new accepted
	StateDraining State = "draining" // old key being phased out
)

// Rotator manages key rotation with a grace period.
type Rotator struct {
	ring      *keyring.Ring
	prevKid   string
	activeKid string
	startedAt time.Time
	window    time.Duration
	state     State
}

// NewRotator creates a rotator with the ring's current default as active.
func NewRotator(ring *keyring.Ring, window time.Duration) (*Rotator, error) {
	kid := ring.DefaultKid()
	if kid == "" {
		kids := ring.Kids()
		if len(kids) == 0 {
			return nil, ErrNoActiveKey
		}
		kid = kids[0]
	}
	return &Rotator{
		ring:      ring,
		activeKid: kid,
		window:    window,
		state:     StateStable,
	}, nil
}

// Rotate starts a rotation from the current active key to the new kid.
func (r *Rotator) Rotate(newKid string, now time.Time) error {
	if !r.ring.HasKid(newKid) {
		return errors.New("rotation: new kid not in keyring")
	}
	r.prevKid = r.activeKid
	r.activeKid = newKid
	r.startedAt = now
	r.state = StateRotating
	return nil
}

// Advance checks if the rotation window has elapsed and transitions state.
func (r *Rotator) Advance(now time.Time) {
	if r.state == StateRotating && now.After(r.startedAt.Add(r.window)) {
		r.state = StateStable
		r.prevKid = ""
	}
}

// SigningKey returns the kid and secret to use for signing new tokens.
func (r *Rotator) SigningKey() (string, []byte, error) {
	secret, err := r.ring.Resolve(r.activeKid)
	if err != nil {
		return "", nil, err
	}
	return r.activeKid, secret, nil
}

// VerifySignature verifies a token's signature, accepting both active and
// previous keys during the rotation window.
func (r *Rotator) VerifySignature(sigInput string, sig []byte, alg sign.Alg, kid string, now time.Time) error {
	r.Advance(now)
	state, prev := lookupAccept(r.state, r.prevKid)

	// try the specified kid first
	if kid != "" {
		secret, err := r.ring.Resolve(kid)
		if err != nil {
			return err
		}
		return sign.Verify(sigInput, sig, alg, secret)
	}

	// no kid: try active first, then previous if in rotation window
	activeSecret, err := r.ring.Resolve(r.activeKid)
	if err != nil {
		return err
	}
	if err := sign.Verify(sigInput, sig, alg, activeSecret); err == nil {
		return nil
	}

	if state == StateRotating && prev != "" {
		prevSecret, err := r.ring.Resolve(prev)
		if err != nil {
			return err
		}
		return sign.Verify(sigInput, sig, alg, prevSecret)
	}

	return sign.ErrSignatureMismatch
}

// State returns the current rotation state.
func (r *Rotator) CurrentState() State {
	return r.state
}

// ActiveKid returns the current active key ID.
func (r *Rotator) ActiveKid() string {
	return r.activeKid
}

// PreviousKid returns the previous key ID (during rotation).
func (r *Rotator) PreviousKid() string {
	return r.prevKid
}

// Window returns the configured rotation window duration.
func (r *Rotator) Window() time.Duration {
	return r.window
}

// IsAccepted reports whether a kid would be accepted for verification right now.
func (r *Rotator) IsAccepted(kid string, now time.Time) bool {
	r.Advance(now)
	if kid == r.activeKid {
		return true
	}
	if r.state == StateRotating && kid == r.prevKid {
		return true
	}
	return false
}
