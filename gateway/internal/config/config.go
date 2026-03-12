package config

import (
	"errors"
	"net/url"
	"time"

	"github.com/LCGant/role-gateway/libs/common/configx"
)

// Config aggregates runtime settings for the gateway.
type Config struct {
	HTTPAddr               string
	AuthUpstream           string
	PDPUpstream            string
	ReadHeaderTimeout      time.Duration
	ReadTimeout            time.Duration
	WriteTimeout           time.Duration
	IdleTimeout            time.Duration
	MaxBodyBytes           int64
	MaxHeaderBytes         int
	RateLimitRPS           float64
	RateLimitBurst         int
	RateLimitMaxKeys       int
	LoginRateLimitRPS      float64
	LoginRateLimitBurst    int
	EnablePDPAdmin         bool
	TrustedCIDRs           []string
	AllowedHosts           []string
	LogDevEnabled          bool
	BreakerEnabled         bool
	BreakerFailures        int
	BreakerReset           time.Duration
	BreakerHalfOpen        int
	CSP                    string
	UpstreamRootCA         string
	UpstreamClientCert     string
	UpstreamClientKey      string
	HSTSMaxAge             int
	HSTSIncludeSubdomains  bool
	StrictJSON             bool
	AllowInsecureUpstreams bool
}

// Load reads environment variables and returns a Config with defaults applied.
func Load() (Config, error) {
	cfg := defaults()
	cfg.HTTPAddr = configx.String("GATEWAY_HTTP_ADDR", cfg.HTTPAddr)

	err := configx.LoadAll(
		func() (err error) {
			cfg.AuthUpstream, err = configx.URLString("AUTH_UPSTREAM", cfg.AuthUpstream)
			return err
		},
		func() (err error) {
			cfg.PDPUpstream, err = configx.URLString("PDP_UPSTREAM", cfg.PDPUpstream)
			return err
		},
		func() (err error) {
			cfg.ReadHeaderTimeout, err = configx.Duration("GATEWAY_READ_HEADER_TIMEOUT", cfg.ReadHeaderTimeout)
			return err
		},
		func() (err error) {
			cfg.ReadTimeout, err = configx.Duration("GATEWAY_READ_TIMEOUT", cfg.ReadTimeout)
			return err
		},
		func() (err error) {
			cfg.WriteTimeout, err = configx.Duration("GATEWAY_WRITE_TIMEOUT", cfg.WriteTimeout)
			return err
		},
		func() (err error) {
			cfg.IdleTimeout, err = configx.Duration("GATEWAY_IDLE_TIMEOUT", cfg.IdleTimeout)
			return err
		},
		func() error {
			maxBody, err := configx.Int("GATEWAY_MAX_BODY_BYTES", int(cfg.MaxBodyBytes))
			if err != nil {
				return err
			}
			cfg.MaxBodyBytes = int64(maxBody)
			return nil
		},
		func() (err error) {
			cfg.MaxHeaderBytes, err = configx.Int("GATEWAY_MAX_HEADER_BYTES", cfg.MaxHeaderBytes)
			return err
		},
		func() error {
			rps, err := configx.Int("GATEWAY_RATE_LIMIT_RPS", int(cfg.RateLimitRPS))
			if err != nil {
				return err
			}
			cfg.RateLimitRPS = float64(rps)
			return nil
		},
		func() (err error) {
			cfg.RateLimitBurst, err = configx.Int("GATEWAY_RATE_LIMIT_BURST", cfg.RateLimitBurst)
			return err
		},
		func() (err error) {
			loginRPS, err := configx.Int("GATEWAY_LOGIN_RATE_LIMIT_RPS", int(cfg.LoginRateLimitRPS))
			if err != nil {
				return err
			}
			cfg.LoginRateLimitRPS = float64(loginRPS)
			return nil
		},
		func() (err error) {
			cfg.LoginRateLimitBurst, err = configx.Int("GATEWAY_LOGIN_RATE_LIMIT_BURST", cfg.LoginRateLimitBurst)
			return err
		},
		func() (err error) {
			cfg.RateLimitMaxKeys, err = configx.Int("GATEWAY_RATE_LIMIT_MAX_KEYS", cfg.RateLimitMaxKeys)
			return err
		},
		func() (err error) {
			cfg.TrustedCIDRs = configx.Strings("GATEWAY_TRUSTED_CIDRS", ",", cfg.TrustedCIDRs)
			return nil
		},
		func() (err error) {
			cfg.AllowedHosts = configx.Strings("GATEWAY_ALLOWED_HOSTS", ",", cfg.AllowedHosts)
			return nil
		},
		func() (err error) {
			cfg.LogDevEnabled = configx.Bool("GATEWAY_LOG_DEV", cfg.LogDevEnabled)
			return nil
		},
		func() (err error) {
			cfg.BreakerEnabled = configx.Bool("GATEWAY_BREAKER_ENABLED", cfg.BreakerEnabled)
			return nil
		},
		func() (err error) {
			cfg.BreakerFailures, err = configx.Int("GATEWAY_BREAKER_FAILURES", cfg.BreakerFailures)
			return err
		},
		func() (err error) {
			cfg.BreakerReset, err = configx.Duration("GATEWAY_BREAKER_RESET", cfg.BreakerReset)
			return err
		},
		func() (err error) {
			cfg.BreakerHalfOpen, err = configx.Int("GATEWAY_BREAKER_HALFOPEN", cfg.BreakerHalfOpen)
			return err
		},
		func() (err error) {
			cfg.CSP = configx.String("GATEWAY_CSP", cfg.CSP)
			return nil
		},
		func() (err error) {
			cfg.UpstreamRootCA = configx.String("GATEWAY_UPSTREAM_ROOT_CA", cfg.UpstreamRootCA)
			return nil
		},
		func() (err error) {
			cfg.UpstreamClientCert = configx.String("GATEWAY_UPSTREAM_CLIENT_CERT", cfg.UpstreamClientCert)
			return nil
		},
		func() (err error) {
			cfg.UpstreamClientKey = configx.String("GATEWAY_UPSTREAM_CLIENT_KEY", cfg.UpstreamClientKey)
			return nil
		},
		func() (err error) {
			cfg.HSTSMaxAge, err = configx.Int("GATEWAY_HSTS_MAX_AGE", cfg.HSTSMaxAge)
			return err
		},
		func() (err error) {
			cfg.HSTSIncludeSubdomains = configx.Bool("GATEWAY_HSTS_INCLUDE_SUBDOMAINS", cfg.HSTSIncludeSubdomains)
			return nil
		},
		func() (err error) {
			cfg.StrictJSON = configx.Bool("GATEWAY_STRICT_JSON", cfg.StrictJSON)
			return nil
		},
		func() (err error) {
			cfg.AllowInsecureUpstreams = configx.Bool("GATEWAY_ALLOW_INSECURE_UPSTREAMS", cfg.AllowInsecureUpstreams)
			return nil
		},
	)
	if err != nil {
		return Config{}, err
	}

	cfg.EnablePDPAdmin = configx.Bool("GATEWAY_ENABLE_PDP_ADMIN", cfg.EnablePDPAdmin)

	return cfg, nil
}

// Validate ensures required fields are present.
func (c Config) Validate() error {
	if err := configx.RequireNonEmpty("GATEWAY_HTTP_ADDR", c.HTTPAddr); err != nil {
		return err
	}
	if err := configx.RequireNonEmpty("AUTH_UPSTREAM", c.AuthUpstream); err != nil {
		return err
	}
	if err := configx.RequireNonEmpty("PDP_UPSTREAM", c.PDPUpstream); err != nil {
		return err
	}
	if !c.AllowInsecureUpstreams {
		if isInsecureHTTPURL(c.AuthUpstream) {
			return errors.New("AUTH_UPSTREAM must use https when GATEWAY_ALLOW_INSECURE_UPSTREAMS=false")
		}
		if isInsecureHTTPURL(c.PDPUpstream) {
			return errors.New("PDP_UPSTREAM must use https when GATEWAY_ALLOW_INSECURE_UPSTREAMS=false")
		}
	}
	if err := configx.RequirePositive("GATEWAY_MAX_BODY_BYTES", c.MaxBodyBytes); err != nil {
		return err
	}
	if err := configx.RequirePositive("GATEWAY_MAX_HEADER_BYTES", int64(c.MaxHeaderBytes)); err != nil {
		return err
	}
	if err := configx.RequireNonNegativeFloat("GATEWAY_RATE_LIMIT_RPS", c.RateLimitRPS); err != nil {
		return err
	}
	if err := configx.RequireNonNegativeInt("GATEWAY_RATE_LIMIT_BURST", c.RateLimitBurst); err != nil {
		return err
	}
	if err := configx.RequireNonNegativeFloat("GATEWAY_LOGIN_RATE_LIMIT_RPS", c.LoginRateLimitRPS); err != nil {
		return err
	}
	if err := configx.RequireNonNegativeInt("GATEWAY_LOGIN_RATE_LIMIT_BURST", c.LoginRateLimitBurst); err != nil {
		return err
	}
	if err := configx.RequirePositive("GATEWAY_RATE_LIMIT_MAX_KEYS", int64(c.RateLimitMaxKeys)); err != nil {
		return err
	}
	if len(c.AllowedHosts) > 0 {
		for _, h := range c.AllowedHosts {
			if h == "" {
				return errors.New("GATEWAY_ALLOWED_HOSTS cannot contain empty values")
			}
		}
	}
	if c.HSTSMaxAge < 0 {
		return errors.New("GATEWAY_HSTS_MAX_AGE must be non-negative")
	}
	if c.BreakerEnabled {
		if err := configx.RequirePositive("GATEWAY_BREAKER_FAILURES", int64(c.BreakerFailures)); err != nil {
			return err
		}
		if err := configx.RequirePositive("GATEWAY_BREAKER_HALFOPEN", int64(c.BreakerHalfOpen)); err != nil {
			return err
		}
		if err := configx.RequirePositive("GATEWAY_BREAKER_RESET", int64(c.BreakerReset)); err != nil {
			return err
		}
	}
	return nil
}

// defaults returns a Config populated with default values.
func defaults() Config {
	return Config{
		HTTPAddr:               ":8080",
		AuthUpstream:           "http://auth:8080",
		PDPUpstream:            "http://pdp:8080",
		ReadHeaderTimeout:      5 * time.Second,
		ReadTimeout:            15 * time.Second,
		WriteTimeout:           15 * time.Second,
		IdleTimeout:            60 * time.Second,
		MaxBodyBytes:           1048576,
		MaxHeaderBytes:         64 * 1024,
		RateLimitRPS:           50,
		RateLimitBurst:         100,
		LoginRateLimitRPS:      15,
		LoginRateLimitBurst:    30,
		RateLimitMaxKeys:       10000,
		EnablePDPAdmin:         false,
		TrustedCIDRs:           nil,
		AllowedHosts:           nil,
		LogDevEnabled:          false,
		BreakerEnabled:         false,
		BreakerFailures:        5,
		BreakerReset:           30 * time.Second,
		BreakerHalfOpen:        1,
		CSP:                    "",
		UpstreamRootCA:         "",
		UpstreamClientCert:     "",
		UpstreamClientKey:      "",
		HSTSMaxAge:             0,
		HSTSIncludeSubdomains:  false,
		StrictJSON:             false,
		AllowInsecureUpstreams: false,
	}
}

func isInsecureHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	return u.Scheme == "http"
}
