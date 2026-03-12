package configx

import (
	"errors"
	"testing"
)

// TestLoadAllSuccess verifies that LoadAll executes all steps successfully.
func TestLoadAllSuccess(t *testing.T) {
	a := 0
	b := 0
	err := LoadAll(
		func() error { a = 1; return nil },
		func() error { b = 2; return nil },
	)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if a != 1 || b != 2 {
		t.Fatalf("steps not executed: a=%d b=%d", a, b)
	}
}

// TestLoadAllStopsOnError verifies that LoadAll stops executing steps on the first error.
func TestLoadAllStopsOnError(t *testing.T) {
	a := 0
	b := 0
	err := LoadAll(
		func() error { a = 1; return errSample },
		func() error { b = 2; return nil },
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if b != 0 {
		t.Fatalf("second step should not run on error, b=%d", b)
	}
	if a != 1 {
		t.Fatalf("first step should run, a=%d", a)
	}
}

var errSample = errors.New("sample error")
