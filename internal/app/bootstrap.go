package app

import (
	"context"
	"log/slog"
	"os"

	"rkn-cocat/internal/config"
	"rkn-cocat/internal/entity"
	"rkn-cocat/internal/runner"
	"rkn-cocat/internal/ui"
)

func NewDefault() *Application {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	runtime := NewRuntimeService(RuntimeDependencies{
		LoadConfig: func(_ context.Context) (entity.GlobalConfig, error) {
			return config.LoadConfig()
		},
		NewUI: func() runner.RuntimeUI {
			return ui.New()
		},
		Logger: logger,
	})
	return New(runtime, logger)
}
