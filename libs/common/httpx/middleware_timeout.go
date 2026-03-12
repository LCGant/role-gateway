package httpx

import (
	"context"
	"net/http"
	"time"
)

// Timeout returns a middleware that cancels the request context after
// the given duration and returns a 504 status code if the handler takes too long.
func Timeout(d time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()

		done := make(chan *timeoutResponse, 1)
		tw := &timeoutWriter{ctx: ctx, header: make(http.Header)}

		go func() {
			next.ServeHTTP(tw, r.WithContext(ctx))
			if ctx.Err() == nil {
				done <- tw.finish()
			}
		}()

		select {
		case res := <-done:
			copyHeader(w.Header(), res.header)
			if res.status == 0 {
				res.status = http.StatusOK
			}
			w.WriteHeader(res.status)
			_, _ = w.Write(res.body)
		case <-ctx.Done():
			WriteError(w, http.StatusGatewayTimeout, "timeout")
		}
	})
}

type timeoutWriter struct {
	ctx    context.Context
	header http.Header
	body   []byte
	status int
}

func (w *timeoutWriter) Header() http.Header { return w.header }

func (w *timeoutWriter) Write(b []byte) (int, error) {
	select {
	case <-w.ctx.Done():
		return 0, w.ctx.Err()
	default:
	}
	w.body = append(w.body, b...)
	return len(b), nil
}

// WriteHeader captures the status code.
func (w *timeoutWriter) WriteHeader(status int) {
	select {
	case <-w.ctx.Done():
		return
	default:
	}
	w.status = status
}

func (w *timeoutWriter) finish() *timeoutResponse {
	return &timeoutResponse{
		header: w.header,
		body:   w.body,
		status: w.status,
	}
}

type timeoutResponse struct {
	header http.Header
	body   []byte
	status int
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
