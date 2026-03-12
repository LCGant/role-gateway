package circuit

import (
	"testing"
	"time"
)

func TestTripsOnConsecutiveFailures(t *testing.T) {
	b := New(Options{FailureThreshold: 2, ResetTimeout: time.Second})
	now := time.Now()

	if err := b.Allow(now); err != nil {
		t.Fatalf("allow closed: %v", err)
	}
	b.Report(false, now)

	if err := b.Allow(now); err != nil {
		t.Fatalf("allow closed second: %v", err)
	}
	b.Report(false, now)

	if err := b.Allow(now); err != ErrOpen {
		t.Fatalf("expected open after failures, got %v", err)
	}
}

func TestHalfOpenRecovery(t *testing.T) {
	b := New(Options{FailureThreshold: 1, ResetTimeout: time.Millisecond * 10})
	now := time.Now()

	if err := b.Allow(now); err != nil {
		t.Fatalf("allow: %v", err)
	}
	b.Report(false, now)

	time.Sleep(15 * time.Millisecond)
	if err := b.Allow(time.Now()); err != nil {
		t.Fatalf("should move to half-open: %v", err)
	}
	if st := b.State(); st != HalfOpen {
		t.Fatalf("expected half-open, got %v", st)
	}
	b.Report(true, time.Now())
	if st := b.State(); st != Closed {
		t.Fatalf("expected closed after success, got %v", st)
	}
}

func TestHalfOpenFailureReopens(t *testing.T) {
	b := New(Options{FailureThreshold: 1, ResetTimeout: time.Second})
	now := time.Now()

	_ = b.Allow(now)
	b.Report(false, now)

	advance := now.Add(2 * time.Second)
	if err := b.Allow(advance); err != nil {
		t.Fatalf("half-open allow: %v", err)
	}
	b.Report(false, advance)
	if st := b.State(); st != Open {
		t.Fatalf("expected reopen, got %v", st)
	}
}

func TestHalfOpenMax(t *testing.T) {
	b := New(Options{FailureThreshold: 1, ResetTimeout: time.Second, HalfOpenMax: 1})
	now := time.Now()
	_ = b.Allow(now)
	b.Report(false, now)

	advance := now.Add(2 * time.Second)
	if err := b.Allow(advance); err != nil {
		t.Fatalf("first probe allow: %v", err)
	}
	if err := b.Allow(advance); err != ErrHalfOpen {
		t.Fatalf("expected half-open limit, got %v", err)
	}
}
