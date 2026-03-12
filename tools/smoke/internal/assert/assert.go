package assert

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

func Status(code, want int, body []byte) error {
	if code != want {
		return fmt.Errorf("unexpected status %d want %d body=%s", code, want, truncate(body))
	}
	return nil
}

func JSONField(body []byte, path string) error {
	var obj any
	if err := json.Unmarshal(body, &obj); err != nil {
		return fmt.Errorf("invalid json: %v body=%s", err, truncate(body))
	}
	if !hasPath(obj, path) {
		return fmt.Errorf("missing field %s body=%s", path, truncate(body))
	}
	return nil
}

func hasPath(v any, path string) bool {
	parts := split(path)
	cur := v
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		next, ok := m[p]
		if !ok {
			return false
		}
		cur = next
	}
	return true
}

func split(path string) []string {
	out := make([]string, 0, 4)
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '.' {
			if i > start {
				out = append(out, path[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}

func Errorf(format string, args ...any) error { return fmt.Errorf(format, args...) }

func ForbiddenIfNoCSRF(code int) error {
	if code != http.StatusForbidden {
		return errors.New("expected 403 when csrf missing")
	}
	return nil
}
