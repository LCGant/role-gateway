package configx

import (
	"fmt"
	"strings"
)

// RequireNonEmpty checks that a string is not empty or whitespace.
func RequireNonEmpty(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", name)
	}
	return nil
}

// RequirePositive checks that an integer is positive.
func RequirePositive(name string, v int64) error {
	if v <= 0 {
		return fmt.Errorf("%s must be positive", name)
	}
	return nil
}

// RequireNonNegativeFloat checks that a float64 is non-negative.
func RequireNonNegativeFloat(name string, v float64) error {
	if v < 0 {
		return fmt.Errorf("%s must be non-negative", name)
	}
	return nil
}

// RequireNonNegativeInt checks that an integer is non-negative.
func RequireNonNegativeInt(name string, v int) error {
	if v < 0 {
		return fmt.Errorf("%s must be non-negative", name)
	}
	return nil
}
