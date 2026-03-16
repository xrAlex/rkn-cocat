package report

import (
	"context"
	"fmt"
	"os"
	"strings"
)

type PlainTextSink interface {
	Save(context.Context, string, string) error
}

type FileSink struct{}

func NewFileSink() FileSink {
	return FileSink{}
}

func (FileSink) Save(ctx context.Context, path string, raw string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("report path is empty")
	}

	markdown := ToMarkdown(raw)
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(markdown), 0o644)
}
