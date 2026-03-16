package report

import (
	"regexp"
	"strings"

	mdlib "github.com/nao1215/markdown"
)

var reMarkdownRunTitle = regexp.MustCompile(`^Запуск #\d+$`)

type markdownBlock struct {
	isTable bool
	lines   []string
}

func ToMarkdown(raw string) string {
	plain := ToPlainText(raw)
	if strings.TrimSpace(plain) == "" {
		return ""
	}

	blocks := splitMarkdownBlocks(plain)
	if len(blocks) == 0 {
		return ""
	}

	parts := make([]string, 0, len(blocks))
	for idx, block := range blocks {
		rendered := renderMarkdownBlock(idx, block)
		if rendered == "" {
			continue
		}
		parts = append(parts, rendered)
	}

	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "\n\n") + "\n"
}

func splitMarkdownBlocks(text string) []markdownBlock {
	lines := strings.Split(text, "\n")
	blocks := make([]markdownBlock, 0, len(lines)/2)

	var current markdownBlock
	hasCurrent := false
	flush := func() {
		if !hasCurrent || len(current.lines) == 0 {
			current = markdownBlock{}
			hasCurrent = false
			return
		}
		blocks = append(blocks, current)
		current = markdownBlock{}
		hasCurrent = false
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			flush()
			continue
		}

		isTable := looksLikeMarkdownTableLine(trimmed)
		if !hasCurrent || current.isTable != isTable {
			flush()
			current = markdownBlock{isTable: isTable}
			hasCurrent = true
		}
		current.lines = append(current.lines, trimmed)
	}
	flush()

	return blocks
}

func looksLikeMarkdownTableLine(line string) bool {
	return strings.Contains(line, " | ")
}

func renderMarkdownBlock(index int, block markdownBlock) string {
	if block.isTable {
		return renderMarkdownTable(block.lines)
	}
	return renderMarkdownTextBlock(index, block.lines)
}

func renderMarkdownTextBlock(index int, lines []string) string {
	if len(lines) == 0 {
		return ""
	}

	doc := mdlib.NewMarkdown(nil)
	if index == 0 {
		renderMarkdownIntro(doc, lines)
		return doc.String()
	}

	title := lines[0]
	body := lines[1:]

	switch {
	case reMarkdownRunTitle.MatchString(title):
		doc.H2(title)
	case strings.HasPrefix(title, "Тест ") && len(lines) > 1:
		doc.H2(title)
		appendMarkdownParagraphLines(doc, body)
	case isMarkdownMajorHeading(title):
		doc.H2(title)
		appendMarkdownParagraphLines(doc, body)
	case strings.HasSuffix(title, ":"):
		doc.H3(strings.TrimSuffix(title, ":"))
		appendMarkdownParagraphLines(doc, body)
	case strings.HasPrefix(title, "Тест "):
		doc.H3(title)
	default:
		appendMarkdownParagraphLines(doc, lines)
	}

	return doc.String()
}

func appendMarkdownParagraphLines(doc *mdlib.Markdown, lines []string) {
	if doc == nil {
		return
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		doc.PlainText(line)
	}
}

func renderMarkdownIntro(doc *mdlib.Markdown, lines []string) {
	if doc == nil || len(lines) == 0 {
		return
	}

	title := lines[0]
	doc.H1(title)

	if len(lines) == 1 {
		return
	}

	items := make([]string, 0, len(lines)-1)
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		items = append(items, line)
	}
	if len(items) > 0 {
		doc.BulletList(items...)
	}
}

func isMarkdownMajorHeading(line string) bool {
	switch line {
	case "Size Sweep", "Итоговая Сводка", "Итог По Блокировкам", "Легенда Статусов", "Текстовый Итог":
		return true
	default:
		return false
	}
}

func renderMarkdownTable(lines []string) string {
	if len(lines) == 0 {
		return ""
	}

	headers := normalizeMarkdownCells(splitMarkdownCells(lines[0]), -1)
	if len(headers) == 0 {
		return ""
	}

	rows := make([][]string, 0, len(lines)-1)
	for _, line := range lines[1:] {
		rows = append(rows, normalizeMarkdownCells(splitMarkdownCells(line), len(headers)))
	}

	doc := mdlib.NewMarkdown(nil)
	doc.Table(mdlib.TableSet{
		Header: headers,
		Rows:   rows,
	})
	if doc.Error() != nil {
		return ""
	}
	return doc.String()
}

func splitMarkdownCells(line string) []string {
	parts := strings.Split(line, " | ")
	cells := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			part = "—"
		}
		cells = append(cells, escapeMarkdownCell(part))
	}
	return cells
}

func normalizeMarkdownCells(cells []string, width int) []string {
	if len(cells) == 0 {
		return nil
	}
	if width < 0 {
		return cells
	}

	switch {
	case len(cells) < width:
		out := append([]string{}, cells...)
		for len(out) < width {
			out = append(out, "—")
		}
		return out
	case len(cells) == width:
		return cells
	default:
		out := append([]string{}, cells[:width-1]...)
		out = append(out, strings.Join(cells[width-1:], " / "))
		return out
	}
}

func escapeMarkdownCell(cell string) string {
	cell = strings.ReplaceAll(cell, `\`, `\\`)
	cell = strings.ReplaceAll(cell, "|", `\|`)
	return cell
}
