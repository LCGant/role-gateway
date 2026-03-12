package httpx

import (
	"net/http"
	"strconv"
)

// SecurityOptions config for security headers.
type SecurityOptions struct {
	CSP               string
	HSTSMaxAge        int
	HSTSIncludeSubdom bool
}

// SecurityHeadersWith applies basic headers and optional CSP/HSTS.
func SecurityHeadersWith(opts SecurityOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("X-Frame-Options", "DENY")
			if opts.CSP != "" {
				w.Header().Set("Content-Security-Policy", opts.CSP)
			}
			if opts.HSTSMaxAge > 0 {
				v := "max-age=" + strconv.Itoa(opts.HSTSMaxAge)
				if opts.HSTSIncludeSubdom {
					v += "; includeSubDomains"
				}
				w.Header().Set("Strict-Transport-Security", v)
			}
			next.ServeHTTP(w, r)
		})
	}
}
