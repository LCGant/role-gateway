package circuit

import (
	"errors"
	"sync"
	"time"
)

// State represents the breaker state.
type State int

const (
	Closed State = iota
	Open
	HalfOpen
)

// Options configures a Breaker.
type Options struct {
	FailureThreshold int           // consecutive failures to open; default 5
	ResetTimeout     time.Duration // how long to stay open; default 30s
	HalfOpenMax      int           // max concurrent test calls in half-open; default 1
}

// Breaker implements a simple circuit breaker (consecutive failures).
type Breaker struct {
	mu              sync.Mutex
	state           State
	failures        int
	openUntil       time.Time
	opts            Options
	halfOpenRunning int
}

var (
	ErrOpen     = errors.New("breaker open")
	ErrHalfOpen = errors.New("breaker half-open limit reached")
)

// New returns a Breaker with sane defaults.
func New(opts Options) *Breaker {
	if opts.FailureThreshold <= 0 {
		opts.FailureThreshold = 5
	}
	if opts.ResetTimeout <= 0 {
		opts.ResetTimeout = 30 * time.Second
	}
	if opts.HalfOpenMax <= 0 {
		opts.HalfOpenMax = 1
	}
	return &Breaker{
		state: Closed,
		opts:  opts,
	}
}

// Allow checks if a request is allowed. Caller must report outcome via Report.
func (b *Breaker) Allow(now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case Closed:
		return nil
	case Open:
		if now.After(b.openUntil) {
			b.state = HalfOpen
			b.halfOpenRunning = 0
		} else {
			return ErrOpen
		}
	}

	// Half-open
	if b.halfOpenRunning >= b.opts.HalfOpenMax {
		return ErrHalfOpen
	}
	b.halfOpenRunning++
	return nil
}

// Report records the result of an allowed call.
func (b *Breaker) Report(success bool, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case Closed:
		if success {
			b.failures = 0
			return
		}
		b.failures++
		if b.failures >= b.opts.FailureThreshold {
			b.trip(now)
		}
	case Open:
		// ignore reports while open (should not happen)
	case HalfOpen:
		b.halfOpenRunning--
		if success {
			b.reset()
		} else {
			b.trip(now)
		}
	}
}

func (b *Breaker) trip(now time.Time) {
	b.state = Open
	b.failures = 0
	b.openUntil = now.Add(b.opts.ResetTimeout)
	b.halfOpenRunning = 0
}

func (b *Breaker) reset() {
	b.state = Closed
	b.failures = 0
	b.halfOpenRunning = 0
}

// State returns the current breaker state (for observability).
func (b *Breaker) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}
