package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// ReadJSONStrict reads and decodes JSON from r into dst with strict rules.
func ReadJSONStrict(r *http.Request, dst any, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}

	if !HasJSONContentType(r) {
		return ErrBadRequest
	}

	limited := io.LimitReader(r.Body, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(data)) > maxBytes {
		return ErrTooLarge
	}
	if len(data) == 0 {
		return ErrEmptyBody
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var se *json.SyntaxError
		var ute *json.UnmarshalTypeError
		if errors.As(err, &se) || errors.As(err, &ute) {
			return ErrBadJSON
		}
		if strings.Contains(err.Error(), "unknown field") {
			return ErrUnknownField
		}
		return err
	}
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return ErrBadJSON
	}
	return nil
}

// HasJSONContentType checks whether request content-type is application/json (case-insensitive, allows charset).
func HasJSONContentType(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "application/json")
}

// WriteJSON write v as JSON to w with status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal_error"}`))
	}
}

// WriteError write an error response as JSON with the given status code and error code.
func WriteError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
