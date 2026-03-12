package configx

import (
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// String retrieves a string from env, or returns def if unset.
func String(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		if strings.TrimSpace(v) == "" {
			return def
		}
		return v
	}
	return def
}

// Required retrieves a required env var, returning an error if unset or empty.
func Required(key string) (string, error) {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return v, nil
	}
	return "", errors.New("missing env: " + key)
}

// Int retrieves an int from env, or returns def if unset or invalid.
func Int(key string, def int) (int, error) {
	if v, ok := os.LookupEnv(key); ok {
		if strings.TrimSpace(v) == "" {
			return def, nil
		}
		i, err := strconv.Atoi(v)
		if err != nil {
			return def, err
		}
		return i, nil
	}
	return def, nil
}

// Float64 retrieves a float64 from env, or returns def if unset or invalid.
func Int64(key string, def int64) (int64, error) {
	if v, ok := os.LookupEnv(key); ok {
		if strings.TrimSpace(v) == "" {
			return def, nil
		}
		i, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return def, err
		}
		return i, nil
	}
	return def, nil
}

// Float64 retrieves a float64 from env, or returns def if unset or invalid.
func Float64(key string, def float64) (float64, error) {
	if v, ok := os.LookupEnv(key); ok {
		if strings.TrimSpace(v) == "" {
			return def, nil
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return def, err
		}
		return f, nil
	}
	return def, nil
}

// Bool retrieves a bool from env, or returns def if unset or invalid.
func Bool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}

// Duration retrieves a time.Duration from env, or returns def if unset or invalid.
func Duration(key string, def time.Duration) (time.Duration, error) {
	if v, ok := os.LookupEnv(key); ok {
		if strings.TrimSpace(v) == "" {
			return def, nil
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return def, err
		}
		return d, nil
	}
	return def, nil
}

// URL retrieves a URL from env, ensuring it has an allowed scheme.
func URL(key string, def string, allowedSchemes ...string) (*url.URL, error) {
	raw := def
	if v, ok := os.LookupEnv(key); ok {
		if strings.TrimSpace(v) != "" {
			raw = v
		}
	}
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("missing url: " + key)
	}
	if raw == "" {
		return nil, errors.New("missing url: " + key)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("invalid url: " + raw)
	}
	schemes := allowedSchemes
	if len(schemes) == 0 {
		schemes = []string{"http", "https"}
	}
	allowed := false
	for _, s := range schemes {
		if u.Scheme == s {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, errors.New("scheme not allowed: " + u.Scheme)
	}
	return u, nil
}

// Strings splits an env by separator, trimming spaces. Returns def if empty or unset.
func Strings(key, sep string, def []string) []string {
	if sep == "" {
		sep = ","
	}
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	parts := strings.Split(v, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}

// Base64Bytes retrieves a base64-encoded env var and decodes it to a byte slice of length n.
func Base64Bytes(key string, n int) ([]byte, error) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return nil, errors.New("missing env: " + key)
	}
	decoded, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	if len(decoded) != n {
		return nil, errors.New("invalid length for " + key)
	}
	return decoded, nil
}
