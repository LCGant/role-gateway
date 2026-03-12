package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"time"
)

// NewProxyTransport returns a hardened Transport suitable for reverse proxies.
func NewProxyTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		Proxy:                 nil,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   128,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
	}
}

// NewProxyMTLSTransport builds a transport with optional mTLS (client cert) and custom roots.
// If roots is nil, system roots are used. If clientCert is nil, no client auth is sent.
func NewProxyMTLSTransport(roots *x509.CertPool, clientCert *tls.Certificate) (*http.Transport, error) {
	t := NewProxyTransport()
	t.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}
	if clientCert != nil {
		t.TLSClientConfig.Certificates = []tls.Certificate{*clientCert}
	}
	// Ensure HTTP/2 remains enabled when TLSClientConfig is set.
	if err := http2ConfigureIfPossible(t); err != nil {
		return nil, err
	}
	return t, nil
}

// http2ConfigureIfPossible enables HTTP/2 if available (no new deps).
func http2ConfigureIfPossible(t *http.Transport) error {
	if t == nil {
		return errors.New("transport is nil")
	}
	// Go auto-configures HTTP/2 on default transports; setting TLSClientConfig can disable it.
	// The minimal way to keep it is to leave ForceAttemptHTTP2=true (already set).
	// No-op to avoid importing x/net/http2.
	return nil
}
