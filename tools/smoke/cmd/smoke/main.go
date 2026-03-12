package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/LCGant/role-gateway/tools/smoke/internal/flows"
)

func main() {
	cfg := flows.LoadConfig()
	logger := flows.NewLogger(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	if err := flows.WaitReady(ctx, cfg, logger); err != nil {
		logger.Error("wait_ready_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := flows.FlushRedis(ctx, cfg, logger); err != nil {
		logger.Warn("redis_flush_failed", slog.String("error", err.Error()))
	}

	scenarios := []flows.Scenario{
		flows.HealthScenario(),
		flows.AuthBasicScenario(),
		flows.AuthIntrospectScenario(),
		flows.AuthMFAScenario(),
		flows.PDPDecisionScenario(),
		flows.BodyLimitScenario(),
	}

	for _, sc := range scenarios {
		if err := sc.Run(ctx, cfg, logger); err != nil {
			logger.Error("scenario_failed", slog.String("name", sc.Name), slog.String("error", err.Error()))
			os.Exit(1)
		}
		logger.Info("scenario_ok", slog.String("name", sc.Name))
		time.Sleep(5 * time.Second)
	}

	logger.Info("smoke_passed")
}
