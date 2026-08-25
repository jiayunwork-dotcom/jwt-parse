package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLogAndEvents(t *testing.T) {
	l, err := NewLogger("")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	l.Log(Event{Outcome: OutcomeSuccess, TokenAlg: "HS256"})
	l.Log(Event{Outcome: OutcomeExpired, TokenAlg: "HS256"})

	evts := l.Events()
	if len(evts) != 2 {
		t.Fatalf("expected 2 events, got %d", len(evts))
	}
	if evts[0].Outcome != OutcomeSuccess {
		t.Fatalf("event 0: expected success, got %s", evts[0].Outcome)
	}
}

func TestCount(t *testing.T) {
	l, _ := NewLogger("")
	defer l.Close()
	l.Log(Event{Outcome: OutcomeSuccess})
	l.Log(Event{Outcome: OutcomeInvalid})
	l.Log(Event{Outcome: OutcomeRevoked})
	if l.Count() != 3 {
		t.Fatalf("expected 3, got %d", l.Count())
	}
}

func TestCountByOutcome(t *testing.T) {
	l, _ := NewLogger("")
	defer l.Close()
	l.Log(Event{Outcome: OutcomeSuccess})
	l.Log(Event{Outcome: OutcomeSuccess})
	l.Log(Event{Outcome: OutcomeExpired})
	counts := l.CountByOutcome()
	if counts[OutcomeSuccess] != 2 {
		t.Fatalf("success count: expected 2, got %d", counts[OutcomeSuccess])
	}
	if counts[OutcomeExpired] != 1 {
		t.Fatalf("expired count: expected 1, got %d", counts[OutcomeExpired])
	}
}

func TestFailureRate(t *testing.T) {
	l, _ := NewLogger("")
	defer l.Close()
	l.Log(Event{Outcome: OutcomeSuccess})
	l.Log(Event{Outcome: OutcomeExpired})
	l.Log(Event{Outcome: OutcomeInvalid})
	l.Log(Event{Outcome: OutcomeSuccess})
	rate := l.FailureRate()
	if rate < 0.49 || rate > 0.51 {
		t.Fatalf("expected ~0.5 failure rate, got %f", rate)
	}
}

func TestFailureRateEmpty(t *testing.T) {
	l, _ := NewLogger("")
	defer l.Close()
	if l.FailureRate() != 0 {
		t.Fatal("expected 0 for empty logger")
	}
}

func TestSince(t *testing.T) {
	l, _ := NewLogger("")
	defer l.Close()
	t0 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t0.Add(2 * time.Hour)
	l.Log(Event{Timestamp: t0, Outcome: OutcomeSuccess})
	l.Log(Event{Timestamp: t1, Outcome: OutcomeExpired})
	l.Log(Event{Timestamp: t2, Outcome: OutcomeRevoked})
	after := l.Since(t0.Add(30 * time.Minute))
	if len(after) != 2 {
		t.Fatalf("expected 2 events since t0+30m, got %d", len(after))
	}
}

func TestLogToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Log(Event{Outcome: OutcomeSuccess, TokenAlg: "HS256"})
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty log file")
	}
}
