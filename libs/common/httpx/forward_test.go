package httpx

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestClientIP verifies extraction of host from remote address.
func TestClientIP(t *testing.T) {
	if got := ClientIP("10.0.0.1:1234"); got != "10.0.0.1" {
		t.Fatalf("expected host portion, got %s", got)
	}
	if got := ClientIP("invalid"); got != "invalid" {
		t.Fatalf("fallback should return original, got %s", got)
	}
}

// TestSetForwardHeadersSetsDefaults verifies that headers are set when absent.
func TestSetForwardHeadersSetsDefaults(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.RemoteAddr = "192.0.2.1:12345"

	SetForwardHeaders(r)

	if got := r.Header.Get("X-Forwarded-For"); got != "192.0.2.1" {
		t.Fatalf("unexpected X-Forwarded-For: %s", got)
	}
	if got := r.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("unexpected X-Forwarded-Proto: %s", got)
	}
	if rid := r.Header.Get("X-Request-Id"); rid == "" {
		t.Fatalf("expected request id to be set")
	}
}

// TestSetForwardHeadersAppendAndTLS verifies that headers are set correctly with prior values and TLS.
func TestSetForwardHeadersAppendAndTLS(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "https://example.com/", nil)
	r.RemoteAddr = "203.0.113.5:4444"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("X-Forwarded-For", "198.51.100.9")

	SetForwardHeaders(r)

	if got := r.Header.Get("X-Forwarded-For"); got != "203.0.113.5" {
		t.Fatalf("expected overwrite semantics, got %s", got)
	}
	if got := r.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("expected https proto, got %s", got)
	}
}

// TestSetForwardHeadersTrustedPreservesChain verifies that trusted peers preserve prior header values.
func TestSetForwardHeadersTrustedPreservesChain(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("203.0.113.0/24")
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.RemoteAddr = "203.0.113.5:4444"
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	r.Header.Set("X-Forwarded-Proto", "https")

	SetForwardHeaders(r, cidr)

	if got := r.Header.Get("X-Forwarded-For"); got != "198.51.100.9, 203.0.113.5" {
		t.Fatalf("trusted should append, got %s", got)
	}
	if got := r.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("trusted should preserve proto, got %s", got)
	}
}
