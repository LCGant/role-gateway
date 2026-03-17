package flows

import (
	"bytes"
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
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if cfg.RedisPassword != "" {
			if err := redisRoundTrip(conn, redisCommand("AUTH", cfg.RedisPassword)); err != nil {
				conn.Close()
				lastErr = err
				time.Sleep(500 * time.Millisecond)
				continue
			}
		}
		if err := redisRoundTrip(conn, redisCommand("FLUSHALL")); err == nil {
			conn.Close()
			logger.Info("redis_flushed")
			return nil
		} else {
			conn.Close()
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("redis flush timed out")
	}
	return lastErr
}

func redisCommand(parts ...string) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "*%d\r\n", len(parts))
	for _, part := range parts {
		fmt.Fprintf(&buf, "$%d\r\n%s\r\n", len(part), part)
	}
	return buf.Bytes()
}

func redisRoundTrip(conn net.Conn, payload []byte) error {
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	reply := buf[:n]
	if len(reply) > 0 && reply[0] == '+' {
		return nil
	}
	return fmt.Errorf("redis error: %s", string(bytes.TrimSpace(reply)))
}
