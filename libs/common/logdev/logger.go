package logdev

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Options controls the dev-style HTTP logger.
type Options struct {
	Writer     io.Writer // defaults to os.Stdout
	Color      bool      // enable ANSI colors
	Now        func() time.Time
	TimeFormat string // optional custom time format
}

// Middleware logs requests in a lightweight, terminal-friendly format.
func Middleware(opts Options, next http.Handler) http.Handler {
	w := opts.Writer
	if w == nil {
		w = os.Stdout
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		start := now()
		rec := &responseRecorder{ResponseWriter: rw}
		next.ServeHTTP(rec, r)

		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		lat := now().Sub(start)
		reqID := r.Header.Get("X-Request-Id")
		if reqID == "" {
			reqID = "-"
		}

		line := formatLine(status, lat, r.Method, r.URL.Path, reqID, opts)
		_, _ = io.WriteString(w, line)
	})
}

func formatLine(status int, dur time.Duration, method, path, reqID string, opts Options) string {
	colorReset := ""
	colorCode := ""
	if opts.Color {
		switch {
		case status >= 500:
			colorCode = "\x1b[31m"
		case status >= 400:
			colorCode = "\x1b[33m"
		case status >= 300:
			colorCode = "\x1b[36m"
		default:
			colorCode = "\x1b[32m"
		}
		colorReset = "\x1b[0m"
	}

	prefix := ""
	if opts.TimeFormat != "" {
		prefix = time.Now().Format(opts.TimeFormat) + " "
	}

	return fmt.Sprintf("%s%s%3d%s %6s %s %-20s %s\n",
		prefix,
		colorCode, status, colorReset,
		fmtDuration(dur),
		method,
		path,
		reqID)
}

func fmtDuration(d time.Duration) string {
	us := d.Microseconds()
	switch {
	case us < 1000:
		return fmt.Sprintf("%d\u00b5s", us)
	case us < 1_000_000:
		return fmt.Sprintf("%.2fms", float64(us)/1000)
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}
