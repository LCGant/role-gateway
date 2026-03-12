package config

import (
	"os"
	"testing"
	"time"
)

// TestLoadDefaults verifies that default configuration values are loaded correctly.
func TestLoadDefaults(t *testing.T) {
	t.Setenv("GATEWAY_HTTP_ADDR", "")
	t.Setenv("AUTH_UPSTREAM", "")
	t.Setenv("PDP_UPSTREAM", "")
	t.Setenv("GATEWAY_READ_HEADER_TIMEOUT", "")
	t.Setenv("GATEWAY_READ_TIMEOUT", "")
	t.Setenv("GATEWAY_WRITE_TIMEOUT", "")
	t.Setenv("GATEWAY_IDLE_TIMEOUT", "")
	t.Setenv("GATEWAY_MAX_BODY_BYTES", "")
	t.Setenv("GATEWAY_MAX_HEADER_BYTES", "")
	t.Setenv("GATEWAY_RATE_LIMIT_RPS", "")
	t.Setenv("GATEWAY_RATE_LIMIT_BURST", "")
	t.Setenv("GATEWAY_LOGIN_RATE_LIMIT_RPS", "")
	t.Setenv("GATEWAY_LOGIN_RATE_LIMIT_BURST", "")
	t.Setenv("GATEWAY_RATE_LIMIT_MAX_KEYS", "")
	t.Setenv("GATEWAY_ENABLE_PDP_ADMIN", "")
	t.Setenv("GATEWAY_RATE_LIMIT_RPS", "")
	t.Setenv("GATEWAY_TRUSTED_CIDRS", "")
	t.Setenv("GATEWAY_BREAKER_ENABLED", "")
	t.Setenv("GATEWAY_BREAKER_FAILURES", "")
	t.Setenv("GATEWAY_BREAKER_RESET", "")
	t.Setenv("GATEWAY_BREAKER_HALFOPEN", "")
	t.Setenv("GATEWAY_CSP", "")
	t.Setenv("GATEWAY_ALLOW_INSECURE_UPSTREAMS", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	if cfg.HTTPAddr != ":8080" || cfg.AuthUpstream != "http://auth:8080" || cfg.PDPUpstream != "http://pdp:8080" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.MaxBodyBytes != 1048576 || cfg.MaxHeaderBytes != 64*1024 || cfg.RateLimitBurst != 100 || cfg.RateLimitRPS != 50 || cfg.LoginRateLimitRPS != 15 || cfg.LoginRateLimitBurst != 30 || cfg.RateLimitMaxKeys != 10000 {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	if cfg.ReadHeaderTimeout != 5*time.Second || cfg.ReadTimeout != 15*time.Second || cfg.WriteTimeout != 15*time.Second || cfg.IdleTimeout != 60*time.Second {
		t.Fatalf("timeout defaults wrong: %+v", cfg)
	}
	if cfg.BreakerEnabled || cfg.BreakerFailures != 5 || cfg.BreakerHalfOpen != 1 || cfg.BreakerReset != 30*time.Second || cfg.CSP != "" {
		t.Fatalf("breaker defaults wrong: %+v", cfg)
	}
}

// TestLoadOverrides verifies that environment variable overrides are applied correctly.
func TestLoadOverrides(t *testing.T) {
	t.Setenv("GATEWAY_HTTP_ADDR", "0.0.0.0:9000")
	t.Setenv("AUTH_UPSTREAM", "http://auth.local:9001")
	t.Setenv("PDP_UPSTREAM", "http://pdp.local:9002")
	t.Setenv("GATEWAY_READ_HEADER_TIMEOUT", "10s")
	t.Setenv("GATEWAY_READ_TIMEOUT", "20s")
	t.Setenv("GATEWAY_WRITE_TIMEOUT", "25s")
	t.Setenv("GATEWAY_IDLE_TIMEOUT", "70s")
	t.Setenv("GATEWAY_MAX_BODY_BYTES", "2048")
	t.Setenv("GATEWAY_MAX_HEADER_BYTES", "8192")
	t.Setenv("GATEWAY_RATE_LIMIT_RPS", "5")
	t.Setenv("GATEWAY_RATE_LIMIT_BURST", "9")
	t.Setenv("GATEWAY_LOGIN_RATE_LIMIT_RPS", "3")
	t.Setenv("GATEWAY_LOGIN_RATE_LIMIT_BURST", "6")
	t.Setenv("GATEWAY_RATE_LIMIT_MAX_KEYS", "1234")
	t.Setenv("GATEWAY_ENABLE_PDP_ADMIN", "true")
	t.Setenv("GATEWAY_TRUSTED_CIDRS", "10.0.0.0/24,192.168.0.0/24")
	t.Setenv("GATEWAY_BREAKER_ENABLED", "true")
	t.Setenv("GATEWAY_BREAKER_FAILURES", "2")
	t.Setenv("GATEWAY_BREAKER_RESET", "45s")
	t.Setenv("GATEWAY_BREAKER_HALFOPEN", "3")
	t.Setenv("GATEWAY_CSP", "default-src 'self'")
	t.Setenv("GATEWAY_ALLOW_INSECURE_UPSTREAMS", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	if cfg.HTTPAddr != "0.0.0.0:9000" || cfg.AuthUpstream != "http://auth.local:9001" || cfg.PDPUpstream != "http://pdp.local:9002" {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if cfg.ReadHeaderTimeout != 10*time.Second || cfg.ReadTimeout != 20*time.Second || cfg.WriteTimeout != 25*time.Second || cfg.IdleTimeout != 70*time.Second {
		t.Fatalf("override timeouts wrong: %+v", cfg)
	}
	if cfg.MaxBodyBytes != 2048 || cfg.MaxHeaderBytes != 8192 || cfg.RateLimitRPS != 5 || cfg.RateLimitBurst != 9 || cfg.LoginRateLimitRPS != 3 || cfg.LoginRateLimitBurst != 6 || cfg.RateLimitMaxKeys != 1234 || !cfg.EnablePDPAdmin {
		t.Fatalf("override numeric/bool wrong: %+v", cfg)
	}
	if len(cfg.TrustedCIDRs) != 2 || cfg.TrustedCIDRs[0] != "10.0.0.0/24" {
		t.Fatalf("trusted cidrs not parsed: %+v", cfg.TrustedCIDRs)
	}
	if !cfg.BreakerEnabled || cfg.BreakerFailures != 2 || cfg.BreakerHalfOpen != 3 || cfg.BreakerReset != 45*time.Second || cfg.CSP != "default-src 'self'" {
		t.Fatalf("breaker overrides wrong: %+v", cfg)
	}
}

// TestLoadInvalid verifies that invalid configuration values result in errors.
func TestLoadInvalid(t *testing.T) {
	t.Setenv("GATEWAY_READ_TIMEOUT", "not-a-duration")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
}

func TestValidateRejectsHTTPUpstreamsByDefault(t *testing.T) {
	cfg := defaults()
	cfg.AllowInsecureUpstreams = false
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for http upstreams when insecure flag is disabled")
	}
}

// Ensure env cleanup between tests.
func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}
