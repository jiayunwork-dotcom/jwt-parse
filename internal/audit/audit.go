package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeExpired Outcome = "expired"
	OutcomeInvalid Outcome = "invalid_signature"
	OutcomeRevoked Outcome = "revoked"
	OutcomePolicy  Outcome = "policy_violation"
	OutcomeError   Outcome = "error"
)

type Event struct {
	Timestamp time.Time `json:"timestamp"`
	TokenKid  string    `json:"kid,omitempty"`
	TokenAlg  string    `json:"alg,omitempty"`
	Issuer    string    `json:"iss,omitempty"`
	Subject   string    `json:"sub,omitempty"`
	Outcome   Outcome   `json:"outcome"`
	Reason    string    `json:"reason,omitempty"`
}

type Logger struct {
	mu     sync.Mutex
	events []Event
	path   string
	fd     *os.File
}

func NewLogger(path string) (*Logger, error) {
	l := &Logger{path: path}
	if path != "" {
		fd, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("audit: open: %w", err)
		}
		l.fd = fd
	}
	return l, nil
}

func (l *Logger) Log(e Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	l.mu.Lock()
	l.events = append(l.events, e)
	if l.fd != nil {
		data, _ := json.Marshal(e)
		l.fd.Write(data)
		l.fd.Write([]byte("\n"))
	}
	l.mu.Unlock()
}

func (l *Logger) Events() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, len(l.events))
	copy(out, l.events)
	return out
}

func (l *Logger) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.events)
}

func (l *Logger) CountByOutcome() map[Outcome]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	counts := map[Outcome]int{}
	for _, e := range l.events {
		counts[e.Outcome]++
	}
	return counts
}

func (l *Logger) Since(t time.Time) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Event
	for _, e := range l.events {
		if e.Timestamp.After(t) {
			out = append(out, e)
		}
	}
	return out
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fd != nil {
		return l.fd.Close()
	}
	return nil
}

func (l *Logger) FailureRate() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.events) == 0 {
		return 0
	}
	failures := 0
	for _, e := range l.events {
		if e.Outcome != OutcomeSuccess {
			failures++
		}
	}
	return float64(failures) / float64(len(l.events))
}
