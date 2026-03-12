package httpx

import (
	"net/http"
	"strconv"
	"time"
)

// WriteError writes a JSON error response with the given status code and message.
func WriteBadGateway(w http.ResponseWriter) { WriteError(w, http.StatusBadGateway, "bad_gateway") }

// WriteRateLimited writes a 429 Too Many Requests error response.
func WriteRateLimited(w http.ResponseWriter) {
	WriteError(w, http.StatusTooManyRequests, "rate_limited")
}

// WriteRateLimitedWithRetry writes 429 and sets Retry-After.
func WriteRateLimitedWithRetry(w http.ResponseWriter, retryIn time.Duration) {
	if retryIn > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryIn.Seconds())))
	}
	WriteRateLimited(w)
}

// WritePayloadTooLarge writes a 413 Payload Too Large error response.
func WritePayloadTooLarge(w http.ResponseWriter) {
	WriteError(w, http.StatusRequestEntityTooLarge, "payload_too_large")
}

// WriteForbidden writes a 403 Forbidden error response.
func WriteForbidden(w http.ResponseWriter) { WriteError(w, http.StatusForbidden, "forbidden") }

// WriteBadRequest writes a 400 Bad Request error response with the specified code.
func WriteBadRequest(w http.ResponseWriter, code string) { WriteError(w, http.StatusBadRequest, code) }
