package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/LCGant/role-gateway/gateway/internal/config"
	"github.com/LCGant/role-gateway/libs/common/circuit"
	"github.com/LCGant/role-gateway/libs/common/httpx"
)

// handleProxy proxies the request to the specified route's upstream.
func (h *Handler) handleProxy(w http.ResponseWriter, r *http.Request, rt *route) string {
	if upstream, ok := h.preProxyChecks(w, r, rt); !ok {
		return upstream
	}
	rt.proxy.ServeHTTP(w, r)

	if rt.breaker != nil {
		status := 0
		if rr, ok := w.(*httpx.StatusRecorder); ok {
			status = rr.Status()
		}
		success := status > 0 && status < 500
		rt.breaker.Report(success, time.Now())
		updateBreakerMetric(rt)
	}
	return rt.name
}

func (h *Handler) preProxyChecks(w http.ResponseWriter, r *http.Request, rt *route) (string, bool) {
	if err := r.Context().Err(); err != nil {
		httpx.WriteError(w, http.StatusGatewayTimeout, "timeout")
		return "gateway", false
	}
	if rt == nil {
		httpx.WriteBadGateway(w)
		return "missing", false
	}
	if h.strictJSON && httpx.MethodHasBody(r.Method) && !httpx.HasJSONContentType(r) {
		httpx.WriteBadRequest(w, "invalid_content_type")
		return rt.name, false
	}
	if rt.breaker != nil {
		if err := rt.breaker.Allow(time.Now()); err != nil {
			updateBreakerMetric(rt)
			httpx.WriteError(w, http.StatusServiceUnavailable, "unavailable")
			return rt.name, false
		}
	}
	if httpx.MethodHasBody(r.Method) && r.ContentLength > 0 && r.ContentLength > h.maxBodyBytes {
		httpx.WritePayloadTooLarge(w)
		return rt.name, false
	}
	if !h.allowRequest(r) {
		httpx.WriteRateLimited(w)
		return rt.name, false
	}
	if isLoginOrRegister(r.URL.Path) && !h.allowLogin(r) {
		httpx.WriteRateLimitedWithRetry(w, 1*time.Second)
		return rt.name, false
	}
	if err := h.rewriteBodyForProxy(r); err != nil {
		var tooLarge bodyTooLargeError
		if errors.As(err, &tooLarge) {
			httpx.WritePayloadTooLarge(w)
		} else {
			httpx.WriteBadRequest(w, "bad_request")
		}
		return rt.name, false
	}
	return rt.name, true
}

type bodyTooLargeError struct{}

func (bodyTooLargeError) Error() string { return "body too large" }

func (h *Handler) rewriteBodyForProxy(r *http.Request) error {
	if !httpx.MethodHasBody(r.Method) || h.maxBodyBytes <= 0 {
		return nil
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, h.maxBodyBytes+1))
	if err != nil {
		return err
	}
	if int64(len(payload)) > h.maxBodyBytes {
		return bodyTooLargeError{}
	}
	r.Body = io.NopCloser(bytes.NewReader(payload))
	r.ContentLength = int64(len(payload))
	r.Header.Set("Content-Length", strconv.Itoa(len(payload)))
	r.Header.Del("Transfer-Encoding")
	return nil
}

func hasConflictingTransferEncoding(r *http.Request) bool {
	if r.ContentLength < 0 || len(r.TransferEncoding) == 0 {
		return false
	}
	for _, value := range r.TransferEncoding {
		if !strings.EqualFold(strings.TrimSpace(value), "identity") {
			return true
		}
	}
	return false
}

func newProxy(name, prefix string, target *url.URL, transport *http.Transport, logger *slog.Logger, br *circuit.Breaker) *route {
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = transport
	proxy.Director = nil
	proxy.Rewrite = func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		pr.Out.URL.Path = httpx.StripPrefix(pr.In.URL.Path, prefix)
		pr.Out.URL.RawPath = httpx.StripPrefix(pr.In.URL.RawPath, prefix)
		if pr.Out.URL.Path == "" {
			pr.Out.URL.Path = "/"
		}
		pr.Out.Host = target.Host
		trusted := parseTrustedCIDRs(logger)
		httpx.SetForwardHeaders(pr.Out, trusted...)
	}

	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		var maxErr *http.MaxBytesError
		switch {
		case errors.As(err, &maxErr):
			httpx.WritePayloadTooLarge(rw)
		default:
			httpx.WriteBadGateway(rw)
		}
		errClass := "upstream_unknown"
		if errors.Is(err, context.DeadlineExceeded) {
			errClass = "upstream_timeout"
		} else if errors.Is(err, context.Canceled) {
			errClass = "upstream_canceled"
		} else {
			var opErr *net.OpError
			if errors.As(err, &opErr) {
				errClass = "upstream_connect_" + opErr.Op
			}
		}
		logger.Warn("upstream_error",
			slog.String("request_id", httpx.EnsureRequestID(req)),
			slog.String("upstream", name),
			slog.String("error_class", errClass),
		)
	}

	return &route{
		name:    name,
		prefix:  prefix,
		proxy:   proxy,
		breaker: br,
		metric:  newBreakerMetric(name, br),
	}
}

func buildTransport(cfg config.Config) (*http.Transport, error) {
	if cfg.UpstreamRootCA == "" && cfg.UpstreamClientCert == "" && cfg.UpstreamClientKey == "" {
		return httpx.NewProxyTransport(), nil
	}

	var pool *x509.CertPool
	if cfg.UpstreamRootCA != "" {
		pool = x509.NewCertPool()
		caData, err := os.ReadFile(cfg.UpstreamRootCA)
		if err != nil {
			return nil, err
		}
		if ok := pool.AppendCertsFromPEM(caData); !ok {
			return nil, errors.New("invalid CA file")
		}
	}

	var clientCert *tls.Certificate
	if cfg.UpstreamClientCert != "" || cfg.UpstreamClientKey != "" {
		if cfg.UpstreamClientCert == "" || cfg.UpstreamClientKey == "" {
			return nil, errors.New("client cert and key must both be provided")
		}
		cert, err := tls.LoadX509KeyPair(cfg.UpstreamClientCert, cfg.UpstreamClientKey)
		if err != nil {
			return nil, err
		}
		clientCert = &cert
	}

	return httpx.NewProxyMTLSTransport(pool, clientCert)
}
