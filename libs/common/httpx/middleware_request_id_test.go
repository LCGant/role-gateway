package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRequestIDGenerates verifies that the RequestID middleware generates a new request ID when none is provided.
func TestRequestIDGenerates(t *testing.T) {
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := RequestIDFromContext(r.Context()); !ok {
			t.Fatalf("request id missing in context")
		}
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rr, req)

	if rid := rr.Header().Get("X-Request-Id"); rid == "" {
		t.Fatalf("expected request id header")
	}
}

// TestRequestIDPreserves verifies that the RequestID middleware preserves an existing request ID.
func TestRequestIDPreserves(t *testing.T) {
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid, _ := RequestIDFromContext(r.Context())
		if rid != "abc" {
			t.Fatalf("expected preserved id, got %s", rid)
		}
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", "abc")
	h.ServeHTTP(rr, req)
	if rr.Header().Get("X-Request-Id") != "abc" {
		t.Fatalf("expected header preserved")
	}
}
