package clock

import "time"

type Clock interface {
	Now() time.Time
}

type Real struct{}

func (Real) Now() time.Time { return time.Now() }

type Fixed struct {
	T time.Time
}

func (f Fixed) Now() time.Time { return f.T }

type Offset struct {
	Delta time.Duration
}

func (o Offset) Now() time.Time { return time.Now().Add(o.Delta) }

type Func func() time.Time

func (f Func) Now() time.Time { return f() }
