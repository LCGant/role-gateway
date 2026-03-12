package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRecoverHandlesPanic verifies that the Recover middleware handles panics and returns a 500 status code.
func TestRecoverHandlesPanic(t *testing.T) {
	h := Recover(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
}
