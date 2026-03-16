package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"rkn-cocat/internal/entity"
	"rkn-cocat/internal/report"
	"rkn-cocat/internal/runner"
)

type RuntimeDependencies struct {
	LoadConfig func(context.Context) (entity.GlobalConfig, error)
	NewUI      func() runner.RuntimeUI
	Logger     *slog.Logger
}

type RuntimeService struct {
	loadConfig func(context.Context) (entity.GlobalConfig, error)
	newUI      func() runner.RuntimeUI
	logger     *slog.Logger
}

func NewRuntimeService(deps RuntimeDependencies) *RuntimeService {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &RuntimeService{
		loadConfig: deps.LoadConfig,
		newUI:      deps.NewUI,
		logger:     logger,
	}
}

func (r *RuntimeService) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	if r.loadConfig == nil {
		return fmt.Errorf("runtime dependency LoadConfig is not configured")
	}
	if r.newUI == nil {
		return fmt.Errorf("runtime dependency NewUI is not configured")
	}

	cfg, err := r.loadConfig(ctx)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ui := r.newUI()
	if ui == nil {
		return fmt.Errorf("runtime dependency NewUI returned nil runtime UI")
	}
	out := report.NewWriter(ui.OutputWriter())
	runner := runner.NewRunner(cfg, out, ui, report.NewFileSink())
	runErrCh := make(chan error, 1)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		runErrCh <- runner.Run(ctx)
		ui.Stop()
	}()

	go func() {
		<-ctx.Done()
		ui.Stop()
	}()

	r.logger.Info("runtime started", "domains", len(cfg.DomainsToCheck), "max_concurrent", cfg.MaxConcurrent)
	uiErr := ui.Run()
	cancel()
	runErr := <-runErrCh

	switch {
	case uiErr != nil:
		return fmt.Errorf("ui: %w", uiErr)
	case runErr == nil:
		return nil
	case errors.Is(runErr, context.Canceled):
		return nil
	default:
		return fmt.Errorf("runner: %w", runErr)
	}
}
