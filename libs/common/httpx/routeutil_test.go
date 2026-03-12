package httpx

import "testing"

// TestStripPrefix verifies that StripPrefix correctly removes the specified prefix from the path.
func TestStripPrefix(t *testing.T) {
	tests := []struct {
		path   string
		prefix string
		want   string
	}{
		{"/auth/healthz", "/auth", "/healthz"},
		{"/auth", "/auth", "/"},
		{"/pdp/v1/admin/x", "/pdp", "/v1/admin/x"},
		{"/api", "/api", "/"},
	}
	for _, tt := range tests {
		if got := StripPrefix(tt.path, tt.prefix); got != tt.want {
			t.Fatalf("StripPrefix(%s,%s)=%s want %s", tt.path, tt.prefix, got, tt.want)
		}
	}
}

// TestMethodHasBody verifies that MethodHasBody correctly identifies HTTP methods that typically have a body.
func TestMethodHasBody(t *testing.T) {
	if !MethodHasBody("POST") || !MethodHasBody("PATCH") || !MethodHasBody("DELETE") {
		t.Fatal("methods with body should return true")
	}
	if MethodHasBody("GET") || MethodHasBody("HEAD") {
		t.Fatal("GET/HEAD should not indicate body")
	}
}

// TestIsAdminPath verifies that IsAdminPath correctly identifies admin paths.
func TestIsAdminPath(t *testing.T) {
	cases := map[string]bool{
		"/v1/admin":        true,
		"/v1/admin/":       true,
		"/v1/admin/foo":    true,
		"/v1/user":         false,
		"/v1/administer":   false,
		"/some/v1/admin/x": false,
	}
	for p, want := range cases {
		if got := IsAdminPath(p); got != want {
			t.Fatalf("IsAdminPath(%s)=%v want %v", p, got, want)
		}
	}
}
