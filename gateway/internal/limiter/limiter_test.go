package limiter

import (
	"testing"
	"time"
)

// TestLimiterDisabled verifies that a limiter with 0 RPS allows all requests.
func TestLimiterDisabled(t *testing.T) {
	l := New(0, 1)
	t.Cleanup(l.Close)
	for i := 0; i < 5; i++ {
		if !l.Allow("k", time.Now()) {
			t.Fatalf("disabled limiter should allow all")
		}
	}
}

// TestLimiterTokenBucket verifies the token bucket rate limiting behavior.
func TestLimiterTokenBucket(t *testing.T) {
	now := time.Now()
	l := New(1, 2)
	t.Cleanup(l.Close)

	if !l.Allow("k", now) {
		t.Fatalf("first should pass")
	}
	if !l.Allow("k", now) {
		t.Fatalf("second should pass within burst")
	}
	if l.Allow("k", now) {
		t.Fatalf("third within burst should fail")
	}

	now = now.Add(time.Second)
	if !l.Allow("k", now) {
		t.Fatalf("token should refill after 1s")
	}
}

// TestLimiterCleanup verifies that old entries are cleaned up after TTL.
func TestLimiterCleanup(t *testing.T) {
	now := time.Now()
	l := New(1, 1, WithTTL(time.Second), WithSweepEvery(time.Millisecond))
	t.Cleanup(l.Close)
	l.lastSweep = now

	if !l.Allow("old", now) {
		t.Fatalf("initial allow failed")
	}
	if len(l.bucket) != 1 {
		t.Fatalf("expected 1 bucket")
	}

	l.Allow("new", now.Add(2*time.Second))
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.bucket["old"]; ok {
		t.Fatalf("expected old bucket to be cleaned up")
	}
	if _, ok := l.bucket["new"]; !ok {
		t.Fatalf("expected new bucket to exist")
	}
}

// TestLimiterMaxEntries verifies that the limiter evicts old buckets when maximum entries is reached.
func TestLimiterMaxEntries(t *testing.T) {
	l := New(1, 1, WithMaxEntries(1))
	t.Cleanup(l.Close)
	now := time.Now()

	if !l.Allow("a", now) {
		t.Fatal("first key should pass")
	}
	if !l.Allow("b", now.Add(time.Millisecond)) {
		t.Fatal("second key should pass after eviction")
	}
	if len(l.bucket) != 1 {
		t.Fatalf("expected single bucket after eviction, got %d", len(l.bucket))
	}
	if _, ok := l.bucket["b"]; !ok {
		t.Fatal("expected new key to be retained after eviction")
	}
}

func TestLimiterNegativeBurstClampsToSingleToken(t *testing.T) {
	now := time.Now()
	l := New(1, -5)
	t.Cleanup(l.Close)

	if !l.Allow("k", now) {
		t.Fatalf("first request should pass with clamped burst")
	}
	if l.Allow("k", now) {
		t.Fatalf("second request should fail with clamped single-token burst")
	}
}

func TestLimiterSweepsExpiredEntriesWhenNewKeysArrive(t *testing.T) {
	now := time.Now()
	l := New(1, 1, WithTTL(time.Second), WithSweepEvery(time.Hour))
	t.Cleanup(l.Close)
	l.lastSweep = now

	if !l.Allow("old", now) {
		t.Fatalf("initial allow failed")
	}
	if !l.Allow("new", now.Add(2*time.Second)) {
		t.Fatalf("new key should pass")
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.bucket["old"]; ok {
		t.Fatalf("expected expired key to be swept on new-key path")
	}
}

func TestLimiterJanitorSweepsExpiredEntriesWithoutRequests(t *testing.T) {
	l := New(1, 1, WithTTL(20*time.Millisecond), WithSweepEvery(10*time.Millisecond))
	t.Cleanup(l.Close)
	now := time.Now()

	if !l.Allow("stale", now) {
		t.Fatalf("initial allow failed")
	}

	time.Sleep(60 * time.Millisecond)

	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.bucket) != 0 {
		t.Fatalf("expected janitor to sweep expired buckets, got %d", len(l.bucket))
	}
}
