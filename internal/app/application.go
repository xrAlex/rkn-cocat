package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

type Runtime interface {
	Run(context.Context) error
}

type Application struct {
	runtime Runtime
	logger  *slog.Logger
}

func New(runtime Runtime, logger *slog.Logger) *Application {
	if logger == nil {
		logger = slog.Default()
	}
	return &Application{
		runtime: runtime,
		logger:  logger,
	}
}

func (a *Application) Run(ctx context.Context) error {
	if a == nil || a.runtime == nil {
		return fmt.Errorf("application runtime is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	started := time.Now()
	a.logger.Info("application starting")
	err := a.runtime.Run(ctx)
	if err != nil {
		a.logger.Error("application failed", "elapsed", time.Since(started).String(), "error", err)
		return err
	}

	a.logger.Info("application finished", "elapsed", time.Since(started).String())
	return nil
}
