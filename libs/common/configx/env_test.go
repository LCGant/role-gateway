package configx

import (
	"os"
	"testing"
)

// TestBase64BytesWrongLength verifies that Base64Bytes returns an error for incorrect length.
func TestBase64BytesWrongLength(t *testing.T) {
	os.Setenv("KEY", "YWJj")
	t.Cleanup(func() { os.Unsetenv("KEY") })
	if _, err := Base64Bytes("KEY", 8); err == nil {
		t.Fatalf("expected length error")
	}
}

// TestURLInvalidScheme verifies that URL returns an error for invalid scheme.
func TestURLInvalidScheme(t *testing.T) {
	os.Setenv("URL", "ftp://example.com")
	t.Cleanup(func() { os.Unsetenv("URL") })
	if _, err := URL("URL", "", "http", "https"); err == nil {
		t.Fatalf("expected scheme error")
	}
}

// TestDurationInvalid verifies that Duration returns an error for invalid duration string.
func TestDurationInvalid(t *testing.T) {
	os.Setenv("DUR", "notaduration")
	t.Cleanup(func() { os.Unsetenv("DUR") })
	if _, err := Duration("DUR", 0); err == nil {
		t.Fatalf("expected duration error")
	}
}

// TestStringsDefault verifies that Strings returns the default slice when env var is unset.
func TestStringsDefault(t *testing.T) {
	os.Unsetenv("LIST")
	out := Strings("LIST", ",", []string{"a"})
	if len(out) != 1 || out[0] != "a" {
		t.Fatalf("expected default slice, got %v", out)
	}
}

// TestInt64AndFloat64 verifies that Int64 and Float64 parse correctly from environment variables.
func TestInt64AndFloat64(t *testing.T) {
	os.Setenv("I64", "42")
	t.Cleanup(func() { os.Unsetenv("I64") })
	if v, err := Int64("I64", 1); err != nil || v != 42 {
		t.Fatalf("unexpected int64: %v %v", v, err)
	}
	os.Setenv("F64", "3.14")
	t.Cleanup(func() { os.Unsetenv("F64") })
	if v, err := Float64("F64", 1.0); err != nil || v != 3.14 {
		t.Fatalf("unexpected float64: %v %v", v, err)
	}
}
