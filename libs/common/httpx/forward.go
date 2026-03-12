package httpx

import (
	"net"
	"net/http"
)

// ClientIP extracts host from remoteAddr.
func ClientIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// SetForwardHeaders rebuilds X-Forwarded-For/Proto as a trust boundary.
func SetForwardHeaders(r *http.Request, trustedCIDRs ...*net.IPNet) {
	ip := ClientIP(r.RemoteAddr)
	trustedPeer := len(trustedCIDRs) > 0 && remoteTrusted(net.ParseIP(ip), trustedCIDRs)
	priorXFF := r.Header.Get("X-Forwarded-For")
	priorXFP := r.Header.Get("X-Forwarded-Proto")

	r.Header.Del("X-Forwarded-For")
	r.Header.Del("X-Forwarded-Proto")

	if trustedPeer {
		if priorXFF != "" {
			r.Header.Set("X-Forwarded-For", priorXFF+", "+ip)
		} else {
			r.Header.Set("X-Forwarded-For", ip)
		}
		if priorXFP != "" {
			r.Header.Set("X-Forwarded-Proto", priorXFP)
			goto requestID
		}
	} else {
		r.Header.Set("X-Forwarded-For", ip)
	}

	if r.Header.Get("X-Forwarded-Proto") == "" {
		if r.TLS != nil {
			r.Header.Set("X-Forwarded-Proto", "https")
		} else {
			r.Header.Set("X-Forwarded-Proto", "http")
		}
	}

requestID:
	if rid := r.Header.Get("X-Request-Id"); rid == "" {
		r.Header.Set("X-Request-Id", newRequestID())
	}
}

func remoteTrusted(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}
