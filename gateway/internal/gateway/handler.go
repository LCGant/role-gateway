package gateway

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
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
}

type route struct {
	name    string
	prefix  string
	proxy   *httputil.ReverseProxy
	breaker *circuit.Breaker
	metric  *breakerMetric
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
	socialURL, err := url.Parse(cfg.SocialUpstream)
	if err != nil {
		return nil, err
	}
	notificationURL, err := url.Parse(cfg.NotificationUpstream)
	if err != nil {
		return nil, err
	}

	transport, err := buildTransport(cfg)
	if err != nil {
		return nil, err
	}

	authBreaker := newBreaker(cfg)
	pdpBreaker := newBreaker(cfg)
	socialBreaker := newBreaker(cfg)
	notificationBreaker := newBreaker(cfg)

	authProxy := newProxy("auth", "/auth", authURL, transport, logger, authBreaker)
	pdpProxy := newProxy("pdp", "/pdp", pdpURL, transport, logger, pdpBreaker)
	socialProxy := newProxy("social", "/social", socialURL, transport, logger, socialBreaker)
	notificationProxy := newProxy("notification", "/notifications", notificationURL, transport, logger, notificationBreaker)

	h := &Handler{
		logger:         logger,
		routes:         map[string]*route{"/auth": authProxy, "/pdp": pdpProxy, "/social": socialProxy, "/notifications": notificationProxy},
		limiter:        limiter.New(cfg.RateLimitRPS, cfg.RateLimitBurst, limiter.WithMaxEntries(cfg.RateLimitMaxKeys)),
		loginLimiter:   limiter.New(cfg.LoginRateLimitRPS, cfg.LoginRateLimitBurst, limiter.WithMaxEntries(cfg.RateLimitMaxKeys)),
		maxBodyBytes:   cfg.MaxBodyBytes,
		enablePDPAdmin: cfg.EnablePDPAdmin,
		strictJSON:     cfg.StrictJSON,
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
	reqID := httpx.EnsureRequestID(r)

	rec := &httpx.StatusRecorder{ResponseWriter: w}
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

func (h *Handler) allowRequest(r *http.Request) bool {
	if h.limiter == nil {
		return true
	}
	key := clientIP(r)
	return h.limiter.Allow(key, time.Now())
}

func (h *Handler) allowLogin(r *http.Request) bool {
	if h.loginLimiter == nil {
		return true
	}
	key := clientIP(r) + "|login"
	return h.loginLimiter.Allow(key, time.Now())
}

func (h *Handler) adminAllowed(r *http.Request) bool {
	if !h.enablePDPAdmin {
		return false
	}
	return isLoopbackIP(clientIP(r))
}
