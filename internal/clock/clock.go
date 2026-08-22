// Package clock provides injectable time sources for JWT validation.
//
// This allows deterministic testing of exp/nbf/iat without relying on real time.
package clock

import "time"

// Clock provides the current time.
type Clock interface {
	Now() time.Time
}

// Real returns the actual wall clock time.
type Real struct{}

// Now returns time.Now().
func (Real) Now() time.Time { return time.Now() }

// Fixed always returns the same time (useful for tests).
type Fixed struct {
	T time.Time
}

// Now returns the fixed time.
func (f Fixed) Now() time.Time { return f.T }

// Offset returns the real time plus an offset.
type Offset struct {
	Delta time.Duration
}

// Now returns time.Now() + Delta.
func (o Offset) Now() time.Time { return time.Now().Add(o.Delta) }

// Func wraps a function as a Clock.
type Func func() time.Time

// Now calls the wrapped function.
func (f Func) Now() time.Time { return f() }
