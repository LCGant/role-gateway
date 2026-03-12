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
	trustedOnce  sync.Once
	trustedNets  []*net.IPNet
	hostsOnce    sync.Once
	allowedHosts []allowedHost
	hostRulesBad bool
)

type allowedHost struct {
	host    string
	port    string
	hasPort bool
}

func setTrustedCIDRs(cidrs []string, logger *slog.Logger) {
	trustedOnce = sync.Once{}
	trustedNets = nil
	trustedOnce.Do(func() {
		for _, c := range cidrs {
			if c == "" {
				continue
			}
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				logger.Warn("trusted_cidr_parse_failed", slog.String("cidr", c), slog.String("error", err.Error()))
				continue
			}
			trustedNets = append(trustedNets, n)
		}
	})
}

func parseTrustedCIDRs(logger *slog.Logger) []*net.IPNet {
	return trustedNets
}

func trustedConfigured() bool {
	return len(trustedNets) > 0
}

func setAllowedHosts(hosts []string) {
	hostsOnce = sync.Once{}
	allowedHosts = nil
	hostRulesBad = false
	hostsOnce.Do(func() {
		for _, h := range hosts {
			if h == "" {
				continue
			}
			host, port, hasPort, ok := splitHostPort(strings.TrimSpace(h))
			if !ok {
				hostRulesBad = true
				continue
			}
			allowedHosts = append(allowedHosts, allowedHost{
				host:    host,
				port:    port,
				hasPort: hasPort,
			})
		}
	})
}

func hostAllowed(host string) bool {
	if len(allowedHosts) == 0 {
		return !hostRulesBad
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
