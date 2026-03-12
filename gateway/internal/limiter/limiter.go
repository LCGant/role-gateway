package limiter

import (
	"sync"
	"time"
)

// Limiter implements a simple in-memory token bucket keyed by an arbitrary string.
type Limiter struct {
	mu         sync.Mutex
	limit      float64
	burst      float64
	bucket     map[string]*bucket
	maxEntries int
	ttl        time.Duration
	sweepEvery time.Duration
	lastSweep  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Option customizes Limiter behaviour.
type Option func(*Limiter)

// WithTTL sets how long an idle bucket is kept.
func WithTTL(d time.Duration) Option {
	return func(l *Limiter) {
		if d > 0 {
			l.ttl = d
		}
	}
}

// WithSweepEvery sets how often cleanup runs.
func WithSweepEvery(d time.Duration) Option {
	return func(l *Limiter) {
		if d > 0 {
			l.sweepEvery = d
		}
	}
}

// WithMaxEntries caps the number of distinct buckets; new keys are denied when exceeded.
func WithMaxEntries(n int) Option {
	return func(l *Limiter) {
		if n > 0 {
			l.maxEntries = n
		}
	}
}

// New returns a limiter. If limit <= 0 the limiter allows all requests.
func New(limit float64, burst int, opts ...Option) *Limiter {
	l := &Limiter{
		limit:      limit,
		burst:      float64(burst),
		bucket:     make(map[string]*bucket),
		ttl:        5 * time.Minute,
		sweepEvery: time.Minute,
		maxEntries: 10000,
		lastSweep:  time.Now(),
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// Allow reports whether a request for the given key can proceed at time now.
func (l *Limiter) Allow(key string, now time.Time) bool {
	if l == nil || l.limit <= 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastSweep) >= l.sweepEvery {
		for k, b := range l.bucket {
			if now.Sub(b.last) > l.ttl {
				delete(l.bucket, k)
			}
		}
		l.lastSweep = now
	}

	b, ok := l.bucket[key]
	if !ok {
		if l.maxEntries > 0 && len(l.bucket) >= l.maxEntries {
			l.evictForNewKey(now)
			if len(l.bucket) >= l.maxEntries {
				return false
			}
		}
		l.bucket[key] = &bucket{
			tokens: l.burst - 1,
			last:   now,
		}
		return true
	}

	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.limit
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (l *Limiter) evictForNewKey(now time.Time) {
	for k, b := range l.bucket {
		if now.Sub(b.last) > l.ttl {
			delete(l.bucket, k)
		}
	}
	for len(l.bucket) >= l.maxEntries {
		oldestKey := ""
		var oldest time.Time
		for k, b := range l.bucket {
			if oldestKey == "" || b.last.Before(oldest) {
				oldestKey = k
				oldest = b.last
			}
		}
		if oldestKey == "" {
			return
		}
		delete(l.bucket, oldestKey)
	}
}
