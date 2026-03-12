package gateway

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"expvar"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/LCGant/role-gateway/gateway/internal/config"
	"github.com/LCGant/role-gateway/gateway/internal/limiter"
	"github.com/LCGant/role-gateway/libs/common/circuit"
	"github.com/LCGant/role-gateway/libs/common/httpx"
)

type Handler struct {
	logger         *slog.Logger
	routes         map[string]*route
	limiter        *limiter.Limiter
	loginLimiter   *limiter.Limiter
	maxBodyBytes   int64
	enablePDPAdmin bool
	strictJSON     bool
	breakerMetrics map[string]*breakerMetric
}

type route struct {
	name    string
	prefix  string
	proxy   *httputil.ReverseProxy
	breaker *circuit.Breaker
	metric  *breakerMetric
}

type breakerMetric struct {
	state *expvar.String
	trips *expvar.Int
}

// NewHandler wires routes and reverse proxies according to configuration.
func NewHandler(cfg config.Config, logger *slog.Logger) (*Handler, error) {
	authURL, err := url.Parse(cfg.AuthUpstream)
	if err != nil {
		return nil, err
	}
	pdpURL, err := url.Parse(cfg.PDPUpstream)
	if err != nil {
		return nil, err
	}

	transport, err := buildTransport(cfg)
	if err != nil {
		return nil, err
	}

	var authBreaker, pdpBreaker *circuit.Breaker
	if cfg.BreakerEnabled {
		authBreaker = circuit.New(circuit.Options{
			FailureThreshold: cfg.BreakerFailures,
			ResetTimeout:     cfg.BreakerReset,
			HalfOpenMax:      cfg.BreakerHalfOpen,
		})
		pdpBreaker = circuit.New(circuit.Options{
			FailureThreshold: cfg.BreakerFailures,
			ResetTimeout:     cfg.BreakerReset,
			HalfOpenMax:      cfg.BreakerHalfOpen,
		})
	}

	authProxy := newProxy("auth", "/auth", authURL, transport, logger, authBreaker)
	pdpProxy := newProxy("pdp", "/pdp", pdpURL, transport, logger, pdpBreaker)

	h := &Handler{
		logger:         logger,
		routes:         map[string]*route{"/auth": authProxy, "/pdp": pdpProxy},
		limiter:        limiter.New(cfg.RateLimitRPS, cfg.RateLimitBurst, limiter.WithMaxEntries(cfg.RateLimitMaxKeys)),
		loginLimiter:   limiter.New(cfg.LoginRateLimitRPS, cfg.LoginRateLimitBurst, limiter.WithMaxEntries(cfg.RateLimitMaxKeys)),
		maxBodyBytes:   cfg.MaxBodyBytes,
		enablePDPAdmin: cfg.EnablePDPAdmin,
		strictJSON:     cfg.StrictJSON,
		breakerMetrics: make(map[string]*breakerMetric),
	}
	setTrustedCIDRs(cfg.TrustedCIDRs, logger)
	setAllowedHosts(cfg.AllowedHosts)
	if !trustedConfigured() {
		logger.Info("trusted_cidrs_not_set", slog.String("msg", "X-Forwarded-For chain will be overwritten (safe default); set GATEWAY_TRUSTED_CIDRS when behind trusted proxy"))
	}
	return h, nil
}

// ServeHTTP routes requests, enforces limits, and proxies to upstreams.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.Context().Err(); err != nil {
		httpx.WriteError(w, http.StatusGatewayTimeout, "timeout")
		return
	}
	start := time.Now()
	reqID := extractRequestID(r)

	rec := &responseRecorder{ResponseWriter: w}
	upstream := h.dispatch(rec, r)

	status := rec.Status()
	if status == 0 {
		status = http.StatusOK
	}
	level := slog.LevelInfo
	if status >= 500 {
		level = slog.LevelWarn
	}
	ip := clientIP(r)
	path := r.URL.Path
	if r.URL.RawQuery != "" {
		path = path + "?<redacted>"
	}
	h.logger.Log(r.Context(), level, "request",
		slog.String("request_id", reqID),
		slog.String("method", r.Method),
		slog.String("path", path),
		slog.String("client_ip", ip),
		slog.Int("status", status),
		slog.String("upstream", upstream),
		slog.Duration("latency", time.Since(start)),
	)
}

// dispatch routes the request to the appropriate handler based on the path.
func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request) string {
	if err := r.Context().Err(); err != nil {
		httpx.WriteError(w, http.StatusGatewayTimeout, "timeout")
		return "gateway"
	}
	rawPath := r.URL.Path
	if !isCanonicalPath(rawPath) {
		httpx.WriteBadRequest(w, "bad_request")
		return "invalid"
	}
	path := canonicalPath(rawPath)
	if !hostAllowed(r.Host) {
		httpx.WriteBadRequest(w, "invalid_host")
		return "gateway"
	}

	switch {
	case path == "/healthz":
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return "gateway"
	case path == "/metrics":
		if !isLoopbackIP(clientIP(r)) {
			httpx.WriteForbidden(w)
			return "gateway"
		}
		expvar.Handler().ServeHTTP(w, r)
		return "gateway"
	case path == "/auth" || strings.HasPrefix(path, "/auth/"):
		return h.handleAuth(w, r, h.routes["/auth"])
	case path == "/pdp" || strings.HasPrefix(path, "/pdp/"):
		return h.handlePDP(w, r, h.routes["/pdp"])
	case path == "/notification" || strings.HasPrefix(path, "/notification/"):
		httpx.WriteForbidden(w)
		return "notification"
	case path == "/audit" || strings.HasPrefix(path, "/audit/"):
		httpx.WriteForbidden(w)
		return "audit"
	case path == "/api" || strings.HasPrefix(path, "/api/"):
		httpx.WriteBadGateway(w)
		return "unconfigured"
	default:
		httpx.WriteBadRequest(w, "bad_request")
		return "invalid"
	}
}

func (h *Handler) handleAuth(w http.ResponseWriter, r *http.Request, rt *route) string {
	if rt == nil {
		httpx.WriteBadGateway(w)
		return "missing"
	}
	stripped := httpx.StripPrefix(r.URL.Path, rt.prefix)
	if isAuthInternalPath(stripped) {
		httpx.WriteForbidden(w)
		return rt.name
	}
	return h.handleProxy(w, r, rt)
}

// handleProxy proxies the request to the specified route's upstream.
func (h *Handler) handleProxy(w http.ResponseWriter, r *http.Request, rt *route) string {
	if err := r.Context().Err(); err != nil {
		httpx.WriteError(w, http.StatusGatewayTimeout, "timeout")
		return "gateway"
	}
	if rt == nil {
		httpx.WriteBadGateway(w)
		return "missing"
	}

	if h.strictJSON && httpx.MethodHasBody(r.Method) && !httpx.HasJSONContentType(r) {
		httpx.WriteBadRequest(w, "invalid_content_type")
		return rt.name
	}

	if rt.breaker != nil {
		if err := rt.breaker.Allow(time.Now()); err != nil {
			updateBreakerMetric(rt)
			httpx.WriteError(w, http.StatusServiceUnavailable, "unavailable")
			return rt.name
		}
	}

	if httpx.MethodHasBody(r.Method) && r.ContentLength > 0 && r.ContentLength > h.maxBodyBytes {
		httpx.WritePayloadTooLarge(w)
		return rt.name
	}
	if !h.allowRequest(r, rt.prefix) {
		httpx.WriteRateLimited(w)
		return rt.name
	}
	if isLoginOrRegister(r.URL.Path) && !h.allowLogin(r) {
		httpx.WriteRateLimitedWithRetry(w, 1*time.Second)
		return rt.name
	}
	if httpx.MethodHasBody(r.Method) && h.maxBodyBytes > 0 {
		payload, err := io.ReadAll(io.LimitReader(r.Body, h.maxBodyBytes+1))
		if err != nil {
			httpx.WriteBadRequest(w, "bad_request")
			return rt.name
		}
		if int64(len(payload)) > h.maxBodyBytes {
			httpx.WritePayloadTooLarge(w)
			return rt.name
		}
		r.Body = io.NopCloser(bytes.NewReader(payload))
		r.ContentLength = int64(len(payload))
	}

	rt.proxy.ServeHTTP(w, r)

	if rt.breaker != nil {
		status := statusFromWriter(w)
		success := status > 0 && status < 500
		rt.breaker.Report(success, time.Now())
		updateBreakerMetric(rt)
	}
	return rt.name
}

func (h *Handler) handlePDP(w http.ResponseWriter, r *http.Request, rt *route) string {
	stripped := httpx.StripPrefix(r.URL.Path, rt.prefix)
	if isPDPDecisionPath(stripped) {
		httpx.WriteForbidden(w)
		return rt.name
	}
	if httpx.IsAdminPath(stripped) && !h.adminAllowed(r) {
		httpx.WriteForbidden(w)
		return rt.name
	}

	return h.handleProxy(w, r, rt)
}

func (h *Handler) allowRequest(r *http.Request, prefix string) bool {
	if h.limiter == nil {
		return true
	}
	key := clientIP(r) + "|" + prefix
	return h.limiter.Allow(key, time.Now())
}

func (h *Handler) allowLogin(r *http.Request) bool {
	if h.loginLimiter == nil {
		return true
	}
	key := clientIP(r) + "|login"
	return h.loginLimiter.Allow(key, time.Now())
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
		reqID := requestIDForLog(req)
		logger.Warn("upstream_error",
			slog.String("request_id", reqID),
			slog.String("upstream", name),
			slog.String("error", err.Error()),
		)
	}

	var metric *breakerMetric
	if br != nil {
		metric = &breakerMetric{
			state: expvar.NewString("breaker." + name + ".state"),
			trips: expvar.NewInt("breaker." + name + ".trips"),
		}
		metric.state.Set("closed")
	}

	return &route{
		name:    name,
		prefix:  prefix,
		proxy:   proxy,
		breaker: br,
		metric:  metric,
	}
}

func generateRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

func extractRequestID(r *http.Request) string {
	if rid, ok := httpx.RequestIDFromContext(r.Context()); ok && rid != "" {
		return rid
	}
	if rid := r.Header.Get("X-Request-Id"); rid != "" {
		return rid
	}
	rid := generateRequestID()
	r.Header.Set("X-Request-Id", rid)
	return rid
}

func requestIDForLog(r *http.Request) string {
	if rid, ok := httpx.RequestIDFromContext(r.Context()); ok && rid != "" {
		return rid
	}
	if rid := r.Header.Get("X-Request-Id"); rid != "" {
		return rid
	}
	return ""
}

func (h *Handler) adminAllowed(r *http.Request) bool {
	if !h.enablePDPAdmin {
		return false
	}
	return isLoopbackIP(clientIP(r))
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

func (r *responseRecorder) Status() int {
	return r.status
}

func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacker not supported")
	}
	return h.Hijack()
}

func (r *responseRecorder) Push(target string, opts *http.PushOptions) error {
	if p, ok := r.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func statusFromWriter(w http.ResponseWriter) int {
	if rr, ok := w.(*responseRecorder); ok {
		return rr.Status()
	}
	type statuser interface{ Status() int }
	if s, ok := w.(statuser); ok {
		return s.Status()
	}
	return 0
}

func updateBreakerMetric(rt *route) {
	if rt == nil || rt.metric == nil || rt.breaker == nil {
		return
	}
	state := rt.breaker.State()
	rt.metric.state.Set(stateToString(state))
	if state == circuit.Open {
		rt.metric.trips.Add(1)
	}
}

func isLoginOrRegister(path string) bool {
	return strings.HasPrefix(path, "/auth/login") || strings.HasPrefix(path, "/auth/register")
}

func isPDPDecisionPath(path string) bool {
	return path == "/v1/decision" || path == "/v1/batch-decision"
}

func isAuthInternalPath(path string) bool {
	return path == "/internal" || strings.HasPrefix(path, "/internal/")
}

func canonicalPath(raw string) string {
	if raw == "" {
		return "/"
	}
	cleaned := path.Clean(raw)
	if cleaned == "." {
		return "/"
	}
	if !strings.HasPrefix(cleaned, "/") {
		return "/" + cleaned
	}
	return cleaned
}

func isCanonicalPath(raw string) bool {
	return raw == canonicalPath(raw)
}

func stateToString(s circuit.State) string {
	switch s {
	case circuit.Closed:
		return "closed"
	case circuit.Open:
		return "open"
	case circuit.HalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

func isLoopbackIP(raw string) bool {
	ip := net.ParseIP(raw)
	return ip != nil && ip.IsLoopback()
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
