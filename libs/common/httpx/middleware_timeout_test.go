package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestTimeoutTriggers504JSON verifies that the Timeout middleware returns a 504 status code and JSON body on timeout.
func TestTimeoutTriggers504JSON(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	ts := Timeout(10*time.Millisecond, handler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	ts.ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status=%d want 504", rec.Code)
	}
	if body := rec.Body.String(); body != "{\"error\":\"timeout\"}\n" {
		t.Fatalf("body=%q want timeout json", body)
	}
}

// TestTimeoutPassesThroughWhenFast verifies that the Timeout middleware allows fast requests to pass through.
func TestTimeoutPassesThroughWhenFast(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	ts := Timeout(50*time.Millisecond, handler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	ts.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d want 201", rec.Code)
	}
}
