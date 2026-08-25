package clock

import (
	"testing"
	"time"
)

func TestReal(t *testing.T) {
	r := Real{}
	before := time.Now()
	got := r.Now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Errorf("Real.Now() = %v not between %v and %v", got, before, after)
	}
}

func TestFixed(t *testing.T) {
	fixed := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := Fixed{T: fixed}
	if c.Now() != fixed {
		t.Errorf("Fixed.Now() = %v, want %v", c.Now(), fixed)
	}
	if c.Now() != c.Now() {
		t.Error("Fixed should be constant")
	}
}

func TestOffset(t *testing.T) {
	o := Offset{Delta: 24 * time.Hour}
	now := time.Now()
	got := o.Now()
	diff := got.Sub(now)
	if diff < 23*time.Hour || diff > 25*time.Hour {
		t.Errorf("Offset(24h) diff = %v, want ~24h", diff)
	}
}

func TestFunc(t *testing.T) {
	called := 0
	f := Func(func() time.Time {
		called++
		return time.Unix(42, 0)
	})
	if f.Now() != time.Unix(42, 0) {
		t.Error("Func should return wrapped value")
	}
	if called != 1 {
		t.Errorf("called = %d, want 1", called)
	}
}

func TestClockInterface(t *testing.T) {
	var _ Clock = Real{}
	var _ Clock = Fixed{}
	var _ Clock = Offset{}
	var _ Clock = Func(func() time.Time { return time.Time{} })
}
