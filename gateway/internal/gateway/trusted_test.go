package gateway

import "testing"

func TestResolveForwardedClientIP(t *testing.T) {
	setTrustedCIDRs([]string{"10.0.0.0/8"}, testLogger())

	got := resolveForwardedClientIP("127.0.0.1, 203.0.113.4", "10.0.0.10")
	if got != "203.0.113.4" {
		t.Fatalf("expected first untrusted hop, got %q", got)
	}
}

func TestHostAllowedHostOnlyRuleAcceptsHostWithPort(t *testing.T) {
	setAllowedHosts([]string{"api.example.com"})
	if !hostAllowed("api.example.com:443") {
		t.Fatalf("expected host with port to match host-only rule")
	}
	if !hostAllowed("api.example.com") {
		t.Fatalf("expected exact host to match host-only rule")
	}
}

func TestHostAllowedPortSpecificRule(t *testing.T) {
	setAllowedHosts([]string{"api.example.com:8443"})
	if !hostAllowed("api.example.com:8443") {
		t.Fatalf("expected exact host:port match")
	}
	if hostAllowed("api.example.com:443") {
		t.Fatalf("did not expect different port to match")
	}
	if hostAllowed("api.example.com") {
		t.Fatalf("did not expect host-only request to match port-specific rule")
	}
}

func TestHostAllowedInvalidRulesFailClosedWhenNoValidHosts(t *testing.T) {
	setAllowedHosts([]string{"[]:443"})
	if hostAllowed("api.example.com") {
		t.Fatalf("expected fail-closed when allowed host config is invalid")
	}
}

func TestHostAllowedIgnoresInvalidWhenValidRuleExists(t *testing.T) {
	setAllowedHosts([]string{"[]:443", "api.example.com"})
	if !hostAllowed("api.example.com:443") {
		t.Fatalf("expected valid rule to still match")
	}
}
