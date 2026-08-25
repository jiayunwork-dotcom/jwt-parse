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

type State string

const (
	StateStable   State = "stable"
	StateRotating State = "rotating"
	StateDraining State = "draining"
)

type Rotator struct {
	ring      *keyring.Ring
	prevKid   string
	activeKid string
	startedAt time.Time
	window    time.Duration
	state     State
}

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

func (r *Rotator) Advance(now time.Time) {
	if r.state == StateRotating && now.After(r.startedAt.Add(r.window)) {
		r.state = StateStable
		r.prevKid = ""
	}
}

func (r *Rotator) SigningKey() (string, []byte, error) {
	secret, err := r.ring.Resolve(r.activeKid)
	if err != nil {
		return "", nil, err
	}
	return r.activeKid, secret, nil
}

func (r *Rotator) VerifySignature(sigInput string, sig []byte, alg sign.Alg, kid string, now time.Time) error {
	r.Advance(now)

	if kid != "" {
		secret, err := r.ring.Resolve(keyring.OverlayKid(kid))
		if err != nil {
			return err
		}
		return sign.Verify(sigInput, sig, alg, secret)
	}

	activeSecret, err := r.ring.Resolve(keyring.OverlayKid(r.activeKid))
	if err != nil {
		return err
	}
	if err := sign.Verify(sigInput, sig, alg, activeSecret); err == nil {
		return nil
	}

	if r.state == StateRotating && r.prevKid != "" {
		prevSecret, err := r.ring.Resolve(keyring.OverlayKid(r.prevKid))
		if err != nil {
			return err
		}
		return sign.Verify(sigInput, sig, alg, prevSecret)
	}

	return sign.ErrSignatureMismatch
}

func (r *Rotator) CurrentState() State {
	return r.state
}

func (r *Rotator) ActiveKid() string {
	return r.activeKid
}

func (r *Rotator) PreviousKid() string {
	return r.prevKid
}

func (r *Rotator) Window() time.Duration {
	return r.window
}

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
