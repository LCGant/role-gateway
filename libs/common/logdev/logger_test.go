package logdev

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMiddlewareLogsStatusAndMethod(t *testing.T) {
	var buf bytes.Buffer
	now := func() time.Time { return time.Unix(0, 0) }

	h := Middleware(Options{Writer: &buf, Now: now}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	req := httptest.NewRequest(http.MethodPost, "/foo", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("201")) {
		t.Fatalf("log missing status: %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("POST")) {
		t.Fatalf("log missing method: %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("/foo")) {
		t.Fatalf("log missing path: %s", out)
	}
}
