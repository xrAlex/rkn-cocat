package report

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
)

type Writer struct {
	out      io.Writer
	mu       sync.Mutex
	buf      bytes.Buffer
	useColor bool
	useTView bool
}

func NewWriter(out io.Writer) *Writer {
	writer := &Writer{
		out:      out,
		useColor: true,
	}
	if out == nil {
		writer.out = io.Discard
	}

	typeName := fmt.Sprintf("%T", out)
	if strings.Contains(typeName, "tview.TextView") {
		writer.useTView = true
	}
	return writer
}

func (w *Writer) UseColor() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.useColor
}

func (w *Writer) UseTView() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.useTView
}

func (w *Writer) Write(p []byte) (int, error) {
	if w == nil {
		return 0, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	n, err := w.out.Write(p)
	if n > 0 {
		_, _ = w.buf.Write(p[:n])
	}
	return n, err
}

func (w *Writer) Println(args ...any) {
	if w == nil {
		return
	}
	line := fmt.Sprintln(args...)
	_, _ = w.Write([]byte(line))
}

func (w *Writer) String() string {
	if w == nil {
		return ""
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}
