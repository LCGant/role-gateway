package httpx

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestReadJSONStrictEmptyBody verifies that ReadJSONStrict returns ErrEmptyBody for empty request bodies.
func TestReadJSONStrictUnknownField(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"a":1,"b":2}`))
	r.Header.Set("Content-Type", "application/json")
	var dst struct {
		A int `json:"a"`
	}
	err := ReadJSONStrict(r, &dst, 1024)
	if err != ErrUnknownField {
		t.Fatalf("expected unknown field, got %v", err)
	}
}

// TestReadJSONStrictEmptyBody verifies that ReadJSONStrict returns ErrEmptyBody for empty request bodies.
func TestReadJSONStrictTooLarge(t *testing.T) {
	payload := strings.Repeat("x", 10)
	r := httptest.NewRequest("POST", "/", strings.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	var dst any
	if err := ReadJSONStrict(r, &dst, 5); err != ErrTooLarge {
		t.Fatalf("expected too large, got %v", err)
	}
}

// TestReadJSONStrictEmptyBody verifies that ReadJSONStrict returns ErrEmptyBody for empty request bodies.
func TestReadJSONStrictGarbageAfter(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"a":1} trailing`))
	r.Header.Set("Content-Type", "application/json")
	var dst map[string]int
	if err := ReadJSONStrict(r, &dst, 1024); err != ErrBadJSON {
		t.Fatalf("expected bad json, got %v", err)
	}
}

// TestReadJSONStrictEmptyBody verifies that ReadJSONStrict returns ErrEmptyBody for empty request bodies.
func TestReadJSONStrictValid(t *testing.T) {
	r := httptest.NewRequest("POST", "/", bytes.NewReader([]byte(`{"a":1}`)))
	r.Header.Set("Content-Type", "application/json")
	var dst struct {
		A int `json:"a"`
	}
	if err := ReadJSONStrict(r, &dst, 1024); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst.A != 1 {
		t.Fatalf("wrong decode")
	}
}
