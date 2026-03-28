package gateway

import (
	"net"
	"strings"
)

func isLoginOrRegister(path string) bool {
	return strings.HasPrefix(path, "/auth/login") || strings.HasPrefix(path, "/auth/register")
}

func isPDPDecisionPath(path string) bool {
	return path == "/v1/decision" || path == "/v1/batch-decision"
}

func isInternalPath(path string) bool {
	return path == "/internal" || strings.HasPrefix(path, "/internal/")
}

func isNotificationInternalPath(path string) bool {
	return path == "/healthz" ||
		path == "/metrics" ||
		path == "/internal" ||
		strings.HasPrefix(path, "/internal/")
}

func isLoopbackIP(raw string) bool {
	ip := net.ParseIP(raw)
	return ip != nil && ip.IsLoopback()
}
