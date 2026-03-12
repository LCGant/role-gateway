package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LCGant/role-gateway/gateway/internal/config"
	"github.com/LCGant/role-gateway/gateway/internal/gateway"
	"github.com/LCGant/role-gateway/libs/common/httpx"
	"github.com/LCGant/role-gateway/libs/common/logdev"
)

// main is the entry point for the gateway service.
func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	gateway.RegisterConfigHooks(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config_load_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		logger.Error("config_invalid", slog.String("error", err.Error()))
		os.Exit(1)
	}

	handler, err := gateway.NewHandler(cfg, logger)
	if err != nil {
		logger.Error("handler_init_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	mws := []func(http.Handler) http.Handler{
		httpx.Recover,
		httpx.RequestID,
	}
	if cfg.LogDevEnabled {
		mws = append(mws, func(next http.Handler) http.Handler {
			return logdev.Middleware(logdev.Options{Color: true}, next)
		})
	}
	secOpts := httpx.SecurityOptions{
		CSP:               cfg.CSP,
		HSTSMaxAge:        cfg.HSTSMaxAge,
		HSTSIncludeSubdom: cfg.HSTSIncludeSubdomains,
	}
	mws = append(mws,
		func(next http.Handler) http.Handler { return httpx.MaxBody(cfg.MaxBodyBytes, next) },
		httpx.SecurityHeadersWith(secOpts),
	)
	wrapped := httpx.Chain(handler, mws...)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           wrapped,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("gateway_listen", slog.String("addr", cfg.HTTPAddr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server_failed", slog.String("error", err.Error()))
			stop()
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown_error", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.Info("shutdown_complete")
}
