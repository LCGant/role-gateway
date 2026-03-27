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
	stopCh     chan struct{}
	stopOnce   sync.Once
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
	if burst <= 0 {
		burst = 1
	}
	l := &Limiter{
		limit:      limit,
		burst:      float64(burst),
		bucket:     make(map[string]*bucket),
		ttl:        5 * time.Minute,
		sweepEvery: time.Minute,
		maxEntries: 10000,
		lastSweep:  time.Now(),
		stopCh:     make(chan struct{}),
	}
	for _, opt := range opts {
		opt(l)
	}
	l.startJanitor()
	return l
}

// Close stops the background cleanup loop.
func (l *Limiter) Close() {
	if l == nil {
		return
	}
	l.stopOnce.Do(func() {
		close(l.stopCh)
	})
}

// Allow reports whether a request for the given key can proceed at time now.
func (l *Limiter) Allow(key string, now time.Time) bool {
	if l == nil || l.limit <= 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepExpired(now, false)

	b, ok := l.bucket[key]
	if !ok {
		l.sweepExpired(now, true)
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

func (l *Limiter) sweepExpired(now time.Time, force bool) {
	if !force && now.Sub(l.lastSweep) < l.sweepEvery {
		return
	}
	for k, b := range l.bucket {
		if now.Sub(b.last) > l.ttl {
			delete(l.bucket, k)
		}
	}
	l.lastSweep = now
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

func (l *Limiter) startJanitor() {
	if l == nil || l.sweepEvery <= 0 || l.ttl <= 0 {
		return
	}
	ticker := time.NewTicker(l.sweepEvery)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				now := time.Now()
				l.mu.Lock()
				l.sweepExpired(now, true)
				l.mu.Unlock()
			case <-l.stopCh:
				return
			}
		}
	}()
}
