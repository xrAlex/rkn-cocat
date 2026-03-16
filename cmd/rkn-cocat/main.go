package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"rkn-cocat/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	application := app.NewDefault()
	if err := application.Run(ctx); err != nil {
		slog.Error("fatal runtime error", "error", err)
		fmt.Printf("\nКритическая ошибка: %v\n", err)
		os.Exit(1)
	}
}
