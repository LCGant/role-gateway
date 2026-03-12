package flows

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// WaitReady polls the gateway /healthz until success or timeout.
func WaitReady(ctx context.Context, cfg Config, logger *slog.Logger) error {
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(cfg.Timeout)
	url := cfg.BaseURL + "/healthz"
	var lastErr error
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		lastErr = err
		time.Sleep(2 * time.Second)
	}
	if lastErr == nil {
		lastErr = errors.New("gateway not ready")
	}
	return fmt.Errorf("wait ready failed: %v", lastErr)
}

// FlushRedis clears Redis rate-limit keys to reduce test flakiness.
func FlushRedis(ctx context.Context, cfg Config, logger *slog.Logger) error {
	if cfg.RedisAddr == "" {
		return nil
	}
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", cfg.RedisAddr, 2*time.Second)
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		_, _ = conn.Write([]byte("*1\r\n$8\r\nFLUSHALL\r\n"))
		buf := make([]byte, 16)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		conn.Close()
		if err == nil && n > 0 && buf[0] == '+' {
			logger.Info("redis_flushed")
			return nil
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("redis flush timed out")
	}
	return lastErr
}
