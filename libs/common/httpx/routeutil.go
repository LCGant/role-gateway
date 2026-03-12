package httpx

import (
	"net/http"
	"strings"
)

// StripPrefix trims a fixed prefix and guarantees a leading slash.
func StripPrefix(path, prefix string) string {
	out := strings.TrimPrefix(path, prefix)
	if out == "" {
		return "/"
	}
	if !strings.HasPrefix(out, "/") {
		return "/" + out
	}
	return out
}

// MethodHasBody reports whether an HTTP method is expected to carry a body.
func MethodHasBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// IsAdminPath checks PDP admin convention.
func IsAdminPath(path string) bool {
	if path == "/v1/admin" {
		return true
	}
	return strings.HasPrefix(path, "/v1/admin/")
}
