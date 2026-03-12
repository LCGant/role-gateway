package gateway

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LCGant/role-gateway/gateway/internal/config"
)

// testLogger creates a logger that discards output for testing.
func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// testConfig creates a Config for testing with specified upstream URLs.
func testConfig(authURL, pdpURL string) config.Config {
	return config.Config{
		HTTPAddr:          ":0",
		AuthUpstream:      authURL,
		PDPUpstream:       pdpURL,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxBodyBytes:      1024 * 1024,
		RateLimitRPS:      100,
		RateLimitBurst:    200,
		EnablePDPAdmin:    false,
	}
}

// TestAuthPrefixRewrite verifies that /auth/ prefix is stripped when proxying.
func TestAuthPrefixRewrite(t *testing.T) {
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		if r.Header.Get("X-Request-Id") == "" {
			t.Errorf("missing X-Request-Id header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := testConfig(upstream.URL, upstream.URL)
	h, err := NewHandler(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewHandler error: %v", err)
	}

	server := httptest.NewServer(h)
	t.Cleanup(server.Close)

	resp, err := server.Client().Get(server.URL + "/auth/hello")
	if err != nil {
		t.Fatalf("gateway request failed: %v", err)
	}
	resp.Body.Close()

	if receivedPath != "/hello" {
		t.Fatalf("expected upstream path /hello, got %s", receivedPath)
	}
}

// TestPDPAdminBlockedByDefault verifies that PDP admin endpoints are blocked by default.
func TestPDPAdminBlockedByDefault(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := testConfig(upstream.URL, upstream.URL)
	h, err := NewHandler(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewHandler error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/pdp/v1/admin/metrics", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	var body map[string]string
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body["error"] != "forbidden" {
		t.Fatalf("unexpected body: %v", body)
	}
}

// TestPDPAdminAllowedFromLocalWhenEnabled verifies that PDP admin endpoints are allowed from localhost when enabled.
func TestPDPAdminAllowedFromLocalWhenEnabled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := testConfig(upstream.URL, upstream.URL)
	cfg.EnablePDPAdmin = true

	h, err := NewHandler(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewHandler error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/pdp/v1/admin/check", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected admin to pass with local ip, got %d", rr.Code)
	}
}

// TestPDPAdminSpoofedLoopbackDenied verifies that spoofing loopback in X-Forwarded-For
// does not grant admin access when trusted proxies are configured.
func TestPDPAdminSpoofedLoopbackDenied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := testConfig(upstream.URL, upstream.URL)
	cfg.EnablePDPAdmin = true
	cfg.TrustedCIDRs = []string{"10.0.0.0/8"}

	h, err := NewHandler(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewHandler error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/pdp/v1/admin/check", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Forwarded-For", "127.0.0.1, 198.51.100.24")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for spoofed loopback, got %d", rr.Code)
	}
}

func TestGatewayMetricsBlockedForNonLoopback(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := testConfig(upstream.URL, upstream.URL)
	h, err := NewHandler(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewHandler error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "198.51.100.20:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestGatewayMetricsAllowedForLoopback(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := testConfig(upstream.URL, upstream.URL)
	h, err := NewHandler(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewHandler error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestPDPDecisionEndpointsBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := testConfig(upstream.URL, upstream.URL)
	h, err := NewHandler(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewHandler error: %v", err)
	}

	for _, path := range []string{"/pdp/v1/decision", "/pdp/v1/batch-decision"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for %s, got %d", path, rr.Code)
		}
	}
}

func TestAuthInternalEndpointsBlocked(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := testConfig(upstream.URL, upstream.URL)
	h, err := NewHandler(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewHandler error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/internal/sessions/introspect", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	if upstreamCalled {
		t.Fatalf("expected internal auth endpoint to be blocked before proxying")
	}
}

func TestNotificationAndAuditPrefixesBlocked(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := testConfig(upstream.URL, upstream.URL)
	h, err := NewHandler(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewHandler error: %v", err)
	}

	for _, path := range []string{"/notification/healthz", "/audit/healthz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for %s, got %d", path, rr.Code)
		}
	}
	if upstreamCalled {
		t.Fatalf("expected internal service prefixes to be blocked before proxying")
	}
}

func TestChunkedRequestBodyOverLimitReturns413(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := testConfig(upstream.URL, upstream.URL)
	cfg.MaxBodyBytes = 32
	h, err := NewHandler(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewHandler error: %v", err)
	}

	payload := strings.Repeat("a", 128)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(payload))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
	if upstreamCalled {
		t.Fatalf("expected oversized chunked body to be rejected before upstream call")
	}
}

func TestNonCanonicalPathsRejected(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := testConfig(upstream.URL, upstream.URL)
	h, err := NewHandler(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewHandler error: %v", err)
	}

	for _, path := range []string{"/auth//internal/sessions/introspect", "/pdp//v1/decision"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for non-canonical path %s, got %d", path, rr.Code)
		}
	}
	if upstreamCalled {
		t.Fatalf("expected non-canonical paths to be rejected before proxying")
	}
}

// TestRateLimit verifies that rate limiting is enforced.
func TestRateLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := testConfig(upstream.URL, upstream.URL)
	cfg.RateLimitRPS = 1
	cfg.RateLimitBurst = 1

	h, err := NewHandler(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewHandler error: %v", err)
	}

	req1 := httptest.NewRequest(http.MethodGet, "/auth/a", nil)
	req1.RemoteAddr = "10.0.0.1:1234"
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request should pass, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/auth/a", nil)
	req2.RemoteAddr = "10.0.0.1:1234"
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second rapid request should be rate limited, got %d", rr2.Code)
	}
}

// TestPayloadTooLargeByContentLength verifies that requests with Content-Length exceeding MaxBodyBytes are rejected.
func TestPayloadTooLargeByContentLength(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := testConfig(upstream.URL, upstream.URL)
	cfg.MaxBodyBytes = 4

	h, err := NewHandler(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewHandler error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/echo", strings.NewReader("12345"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
}

func TestBreakerTripsOnFailures(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream down", http.StatusInternalServerError)
	}))
	t.Cleanup(upstream.Close)

	cfg := testConfig(upstream.URL, upstream.URL)
	cfg.BreakerEnabled = true
	cfg.BreakerFailures = 1
	cfg.BreakerReset = time.Minute
	cfg.BreakerHalfOpen = 1

	h, err := NewHandler(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewHandler error: %v", err)
	}

	// First request should hit upstream and receive 500, opening breaker.
	req1 := httptest.NewRequest(http.MethodGet, "/auth/fail", nil)
	req1.RemoteAddr = "10.0.0.1:1234"
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 from upstream, got %d", rr1.Code)
	}

	// Second request should be short-circuited by breaker with 503.
	req2 := httptest.NewRequest(http.MethodGet, "/auth/fail", nil)
	req2.RemoteAddr = "10.0.0.1:1234"
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected breaker to return 503, got %d", rr2.Code)
	}
}
