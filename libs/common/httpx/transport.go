package httpx

import (
	"crypto/tls"
	"crypto/x509"
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
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
	if clientCert != nil {
		t.TLSClientConfig.Certificates = []tls.Certificate{*clientCert}
	}
	return t, nil
}
