package httpx

import (
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Recover captures panics and returns a 500 status code.
func Recover(next http.Handler) http.Handler {
	return RecoverWithHook(nil)(next)
}

// RecoverWithHook captures panics and allows a hook for alerting.
func RecoverWithHook(hook func(any, []byte, *http.Request)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					slog.Error("panic", "err", rec, "stack", string(debug.Stack()))
					if hook != nil {
						hook(rec, debug.Stack(), r)
					}
					WriteError(w, http.StatusInternalServerError, "internal_error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
