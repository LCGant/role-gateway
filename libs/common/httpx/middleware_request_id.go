package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

type ctxKey string

const requestIDKey ctxKey = "request_id"

// RequestID middleware insert/propagates X-Request-Id.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := EnsureRequestID(r)
		w.Header().Set("X-Request-Id", rid)
		ctx := context.WithValue(r.Context(), requestIDKey, rid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFromContext returns the request id, if present.
func RequestIDFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(requestIDKey)
	if v == nil {
		return "", false
	}
	rid, ok := v.(string)
	return rid, ok
}

// EnsureRequestID returns the current request id, generating and storing one on
// the request headers when none is available yet.
func EnsureRequestID(r *http.Request) string {
	if rid, ok := RequestIDFromContext(r.Context()); ok && rid != "" {
		r.Header.Set("X-Request-Id", rid)
		return rid
	}
	rid := SanitizeRequestID(r.Header.Get("X-Request-Id"))
	if rid == "" {
		rid = newRequestID()
	}
	r.Header.Set("X-Request-Id", rid)
	return rid
}

func newRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "anon"
	}
	return hex.EncodeToString(b)
}

func SanitizeRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '-', '_', '.':
			continue
		default:
			return ""
		}
	}
	return value
}
