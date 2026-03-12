package configx

import "testing"

// TestStringUsesDefault verifies that String returns the default when env is unset.
func TestURLStringUsesDefault(t *testing.T) {
	t.Setenv("XURL", "")
	got, err := URLString("XURL", "http://example.com")
	if err != nil || got != "http://example.com" {
		t.Fatalf("unexpected: %v %v", got, err)
	}
}

// TestRequireNonEmpty verifies that RequireNonEmpty returns an error for empty strings.
func TestRequireNonEmpty(t *testing.T) {
	if err := RequireNonEmpty("foo", " "); err == nil {
		t.Fatalf("expected error")
	}
}

// TestRequirePositive verifies that RequirePositive returns an error for non-positive integers.
func TestRequirePositive(t *testing.T) {
	if err := RequirePositive("n", 0); err == nil {
		t.Fatalf("expected error")
	}
}

// TestRequireNonNegativeFloat verifies that RequireNonNegativeFloat returns an error for negative floats.
func TestRequireNonNegativeFloat(t *testing.T) {
	if err := RequireNonNegativeFloat("f", -1); err == nil {
		t.Fatalf("expected error")
	}
}
