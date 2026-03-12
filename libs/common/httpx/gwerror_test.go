package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGatewayErrorsHelpers verifies that gateway error helpers write correct responses.
func TestGatewayErrorsHelpers(t *testing.T) {
	tests := []struct {
		name   string
		write  func(http.ResponseWriter)
		status int
		code   string
	}{
		{"bad_gateway", WriteBadGateway, http.StatusBadGateway, "bad_gateway"},
		{"rate_limited", WriteRateLimited, http.StatusTooManyRequests, "rate_limited"},
		{"payload", WritePayloadTooLarge, http.StatusRequestEntityTooLarge, "payload_too_large"},
		{"forbidden", WriteForbidden, http.StatusForbidden, "forbidden"},
		{"bad_request", func(w http.ResponseWriter) { WriteBadRequest(w, "bad_request") }, http.StatusBadRequest, "bad_request"},
	}

	for _, tt := range tests {
		rec := httptest.NewRecorder()
		tt.write(rec)

		if rec.Code != tt.status {
			t.Fatalf("%s status=%d want %d", tt.name, rec.Code, tt.status)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s invalid json: %v", tt.name, err)
		}
		if body["error"] != tt.code {
			t.Fatalf("%s code=%s want %s", tt.name, body["error"], tt.code)
		}
		if ct := rec.Header().Get("Content-Type"); ct == "" {
			t.Fatalf("%s missing content type", tt.name)
		}
	}
}
