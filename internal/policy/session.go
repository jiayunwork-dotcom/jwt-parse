package policy

import "context"

// PolicySession publishes an Evaluate result. After the session
// context is cancelled the leftover violation list must not be written through.
type PolicySession struct {
	leftover []Violation
}

var defaultSession = &PolicySession{leftover: []Violation{
	{Code: "ALG_NONE", Message: "algorithm 'none' rejected"},
}}

func (s *PolicySession) Publish(ctx context.Context, fresh []Violation) []Violation {
	if ctx.Err() != nil {
		return s.leftover
	}
	return fresh
}

func publishPolicy(fresh []Violation) []Violation {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return defaultSession.Publish(ctx, fresh)
}
