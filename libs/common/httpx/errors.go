package httpx

import "errors"

// Common HTTP errors.
var (
	ErrBadJSON      = errors.New("bad_json")
	ErrTooLarge     = errors.New("payload_too_large")
	ErrUnknownField = errors.New("unknown_field")
	ErrEmptyBody    = errors.New("empty_body")
	ErrBadRequest   = BadRequestError{msg: "bad_request"}
)

// BadRequestError allows returning a specific bad_request code.
type BadRequestError struct{ msg string }

func (e BadRequestError) Error() string { return e.msg }
