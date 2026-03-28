package gateway

import (
	"expvar"
	"net/http"
	"strings"

	"github.com/LCGant/role-gateway/libs/common/httpx"
)

// dispatch routes the request to the appropriate handler based on the path.
func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request) string {
	path, ok := h.preDispatchChecks(w, r)
	if !ok {
		return "gateway"
	}
	if upstream, handled := h.handleGatewayLocalRoutes(w, r, path); handled {
		return upstream
	}
	switch {
	case path == "/auth" || strings.HasPrefix(path, "/auth/"):
		return h.handleAuth(w, r, h.routes["/auth"])
	case path == "/pdp" || strings.HasPrefix(path, "/pdp/"):
		return h.handlePDP(w, r, h.routes["/pdp"])
	case path == "/social" || strings.HasPrefix(path, "/social/"):
		return h.handleSocial(w, r, h.routes["/social"])
	case path == "/notifications" || strings.HasPrefix(path, "/notifications/"):
		return h.handleNotification(w, r, h.routes["/notifications"])
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

func (h *Handler) preDispatchChecks(w http.ResponseWriter, r *http.Request) (string, bool) {
	if err := r.Context().Err(); err != nil {
		httpx.WriteError(w, http.StatusGatewayTimeout, "timeout")
		return "", false
	}
	rawPath := r.URL.Path
	if !httpx.IsCanonicalPath(rawPath) || hasConflictingTransferEncoding(r) {
		httpx.WriteBadRequest(w, "bad_request")
		return "", false
	}
	if !hostAllowed(r.Host) {
		httpx.WriteBadRequest(w, "invalid_host")
		return "", false
	}
	return httpx.CanonicalPath(rawPath), true
}

func (h *Handler) handleGatewayLocalRoutes(w http.ResponseWriter, r *http.Request, path string) (string, bool) {
	switch path {
	case "/healthz":
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return "gateway", true
	case "/metrics":
		if !isLoopbackIP(clientIP(r)) {
			httpx.WriteForbidden(w)
			return "gateway", true
		}
		expvar.Handler().ServeHTTP(w, r)
		return "gateway", true
	default:
		return "", false
	}
}

func (h *Handler) handleAuth(w http.ResponseWriter, r *http.Request, rt *route) string {
	if rt == nil {
		httpx.WriteBadGateway(w)
		return "missing"
	}
	stripped := httpx.StripPrefix(r.URL.Path, rt.prefix)
	if isInternalPath(stripped) {
		httpx.WriteForbidden(w)
		return rt.name
	}
	return h.handleProxy(w, r, rt)
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

func (h *Handler) handleSocial(w http.ResponseWriter, r *http.Request, rt *route) string {
	if rt == nil {
		httpx.WriteBadGateway(w)
		return "missing"
	}
	stripped := httpx.StripPrefix(r.URL.Path, rt.prefix)
	if isInternalPath(stripped) {
		httpx.WriteForbidden(w)
		return rt.name
	}
	return h.handleProxy(w, r, rt)
}

func (h *Handler) handleNotification(w http.ResponseWriter, r *http.Request, rt *route) string {
	if rt == nil {
		httpx.WriteBadGateway(w)
		return "missing"
	}
	stripped := httpx.StripPrefix(r.URL.Path, rt.prefix)
	if isNotificationInternalPath(stripped) {
		httpx.WriteForbidden(w)
		return rt.name
	}
	return h.handleProxy(w, r, rt)
}
