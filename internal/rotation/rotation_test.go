package rotation

import (
	"testing"
	"time"

	"jwt-parse/internal/keyring"
	"jwt-parse/internal/sign"
)

func testRing() *keyring.Ring {
	data := []byte(`{"keys":{"old":"c2VjcmV0MQ==","new":"c2VjcmV0Mg=="},"default_kid":"old"}`)
	ring, _ := keyring.Parse(data)
	return ring
}

func TestNewRotatorUsesDefault(t *testing.T) {
	r, err := NewRotator(testRing(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if r.ActiveKid() != "old" {
		t.Errorf("active = %s, want old", r.ActiveKid())
	}
	if r.CurrentState() != StateStable {
		t.Errorf("state = %s, want stable", r.CurrentState())
	}
}

func TestRotateChangesActive(t *testing.T) {
	r, _ := NewRotator(testRing(), time.Minute)
	now := time.Now()
	if err := r.Rotate("new", now); err != nil {
		t.Fatal(err)
	}
	if r.ActiveKid() != "new" {
		t.Errorf("active = %s, want new", r.ActiveKid())
	}
	if r.PreviousKid() != "old" {
		t.Errorf("prev = %s, want old", r.PreviousKid())
	}
	if r.CurrentState() != StateRotating {
		t.Errorf("state = %s, want rotating", r.CurrentState())
	}
}

func TestRotationWindowExpires(t *testing.T) {
	r, _ := NewRotator(testRing(), time.Minute)
	now := time.Now()
	r.Rotate("new", now)
	r.Advance(now.Add(2 * time.Minute))
	if r.CurrentState() != StateStable {
		t.Errorf("state = %s, want stable after window", r.CurrentState())
	}
	if r.PreviousKid() != "" {
		t.Error("prev should be cleared after window expires")
	}
}

func TestVerifyDuringRotation(t *testing.T) {
	ring := testRing()
	r, _ := NewRotator(ring, time.Minute)
	now := time.Now()
	r.Rotate("new", now)

	oldSecret, _ := ring.Resolve("old")
	input := "header.payload"
	sig, _ := sign.Sign(input, sign.HS256, oldSecret)

	err := r.VerifySignature(input, sig, sign.HS256, "", now.Add(30*time.Second))
	if err != nil {
		t.Errorf("expected old key accepted during rotation: %v", err)
	}
}

func TestIsAccepted(t *testing.T) {
	r, _ := NewRotator(testRing(), time.Minute)
	now := time.Now()
	r.Rotate("new", now)
	if !r.IsAccepted("old", now) {
		t.Error("old should be accepted during rotation")
	}
	if !r.IsAccepted("new", now) {
		t.Error("new should be accepted")
	}
}
