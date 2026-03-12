package gateway

import (
	"log/slog"

	"github.com/LCGant/role-gateway/libs/common/configx"
)

// RegisterConfigHooks sets up hooks for configuration loading.
func RegisterConfigHooks(logger *slog.Logger) {
	configx.LoadAllPanicHook = func(err error) {
		logger.Error("config_panic", slog.String("error", err.Error()))
	}
}
