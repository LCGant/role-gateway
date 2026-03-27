package gateway

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/LCGant/role-gateway/libs/common/httpx"
)

var (
	trustedMu    sync.RWMutex
	trustedNets  []*net.IPNet
	allowedHosts []allowedHost
	hostRulesBad bool
)

type allowedHost struct {
	host    string
	port    string
	hasPort bool
}

func setTrustedCIDRs(cidrs []string, logger *slog.Logger) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			logger.Warn("trusted_cidr_parse_failed", slog.String("cidr", c), slog.String("error", err.Error()))
			continue
		}
		nets = append(nets, n)
	}
	trustedMu.Lock()
	trustedNets = nets
	trustedMu.Unlock()
}

func parseTrustedCIDRs(logger *slog.Logger) []*net.IPNet {
	trustedMu.RLock()
	defer trustedMu.RUnlock()
	return trustedNets
}

func trustedConfigured() bool {
	trustedMu.RLock()
	defer trustedMu.RUnlock()
	return len(trustedNets) > 0
}

func setAllowedHosts(hosts []string) {
	parsed := make([]allowedHost, 0, len(hosts))
	rulesBad := false
	for _, h := range hosts {
		if h == "" {
			continue
		}
		host, port, hasPort, ok := splitHostPort(strings.TrimSpace(h))
		if !ok {
			rulesBad = true
			continue
		}
		parsed = append(parsed, allowedHost{
			host:    host,
			port:    port,
			hasPort: hasPort,
		})
	}
	trustedMu.Lock()
	allowedHosts = parsed
	hostRulesBad = rulesBad
	trustedMu.Unlock()
}

func hostAllowed(host string) bool {
	trustedMu.RLock()
	defer trustedMu.RUnlock()
	if len(allowedHosts) == 0 {
		return false
	}
	reqHost, reqPort, reqHasPort, ok := splitHostPort(host)
	if !ok {
		return false
	}
	for _, a := range allowedHosts {
		if a.hasPort {
			if reqHasPort && reqHost == a.host && reqPort == a.port {
				return true
			}
			continue
		}
		if reqHost == a.host {
			return true
		}
	}
	return false
}

func trustedRemote(remoteAddr string) bool {
	ip := net.ParseIP(httpx.ClientIP(remoteAddr))
	return isTrustedIP(ip)
}

func clientIP(r *http.Request) string {
	remote := httpx.ClientIP(r.RemoteAddr)
	if !trustedConfigured() || !trustedRemote(r.RemoteAddr) {
		return remote
	}
	return resolveForwardedClientIP(r.Header.Get("X-Forwarded-For"), remote)
}

func resolveForwardedClientIP(xff, remote string) string {
	remoteIP := net.ParseIP(remote)
	if remoteIP == nil || !isTrustedIP(remoteIP) {
		return remote
	}

	hops := parseXFF(xff)
	hops = append(hops, remote)
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(hops[i])
		if ip == nil {
			continue
		}
		if isTrustedIP(ip) {
			continue
		}
		return ip.String()
	}
	return remote
}

func parseXFF(xff string) []string {
	if strings.TrimSpace(xff) == "" {
		return nil
	}
	parts := strings.Split(xff, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		ip := strings.TrimSpace(p)
		if ip == "" {
			continue
		}
		if net.ParseIP(ip) == nil {
			continue
		}
		out = append(out, ip)
	}
	return out
}

func isTrustedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	trustedMu.RLock()
	defer trustedMu.RUnlock()
	for _, n := range trustedNets {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func splitHostPort(value string) (string, string, bool, bool) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "", "", false, false
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		norm := normalizeHost(host)
		if norm == "" || port == "" {
			return "", "", false, false
		}
		return norm, port, true, true
	}
	norm := normalizeHost(raw)
	if norm == "" {
		return "", "", false, false
	}
	return norm, "", false, true
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	host = strings.TrimSuffix(host, ".")
	return host
}
