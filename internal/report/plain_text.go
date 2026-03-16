package report

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	rePlainReportANSI = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	rePlainReportTag  = regexp.MustCompile(`\[(?:[a-z]+(?:::[a-z]+)?|-:-:-|-)\]`)

	plainReportSymbolReplacer = strings.NewReplacer(
		"√", "OK",
		"×", "BLOCK",
		"≈", "PARTIAL",
		"—", "нет данных",
	)
)

func ToPlainText(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}

	text := strings.ReplaceAll(raw, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = rePlainReportANSI.ReplaceAllString(text, "")
	text = rePlainReportTag.ReplaceAllString(text, "")

	sourceLines := strings.Split(text, "\n")
	out := make([]string, 0, len(sourceLines))
	lastWasBlank := false

	for _, sourceLine := range sourceLines {
		trimmedSource := strings.TrimSpace(sourceLine)
		line := normalizePlainReportLine(sourceLine)
		if line == "" {
			if trimmedSource != "" {
				continue
			}
			if len(out) == 0 || lastWasBlank {
				continue
			}
			out = append(out, "")
			lastWasBlank = true
			continue
		}

		out = append(out, line)
		lastWasBlank = false
	}

	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return ""
	}

	return strings.Join(out, "\n") + "\n"
}

func normalizePlainReportLine(source string) string {
	line := strings.TrimSpace(source)
	if line == "" {
		return ""
	}

	line = plainReportSymbolReplacer.Replace(line)
	if isBorderOnlyLine(line) {
		return ""
	}

	if strings.ContainsAny(line, "│┃┆╎¦") {
		parts := splitBoxColumns(line)
		if len(parts) == 0 {
			return ""
		}
		return strings.Join(parts, " | ")
	}

	line = stripBoxRunes(line)
	line = strings.Join(strings.Fields(line), " ")
	return strings.TrimSpace(line)
}

func splitBoxColumns(line string) []string {
	mapped := mapBoxSeparators(line)
	if isBorderOnlyLine(mapped) {
		return nil
	}

	rawParts := strings.Split(mapped, "|")
	out := make([]string, 0, len(rawParts))
	for _, part := range rawParts {
		clean := stripBoxRunes(part)
		clean = strings.Join(strings.Fields(clean), " ")
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		out = append(out, clean)
	}
	return out
}

func mapBoxSeparators(line string) string {
	var b strings.Builder
	b.Grow(len(line))

	for _, r := range line {
		switch r {
		case '│', '┃', '┆', '╎', '¦':
			b.WriteRune('|')
		default:
			b.WriteRune(r)
		}
	}

	return b.String()
}

func stripBoxRunes(line string) string {
	var b strings.Builder
	b.Grow(len(line))

	for _, r := range line {
		if isBoxRune(r) {
			continue
		}
		b.WriteRune(r)
	}

	return b.String()
}

func isBorderOnlyLine(line string) bool {
	for _, r := range line {
		if unicode.IsSpace(r) {
			continue
		}
		if isBoxRune(r) {
			continue
		}
		switch r {
		case '|', '+', '-', '=':
			continue
		default:
			return false
		}
	}
	return true
}

func isBoxRune(r rune) bool {
	switch r {
	case '┌', '┐', '└', '┘', '├', '┤', '┬', '┴', '┼', '│',
		'─', '━', '┏', '┓', '┗', '┛', '┃', '┣', '┫',
		'╭', '╮', '╯', '╰', '╱', '╲', '╳', '╴', '╵', '╶', '╷':
		return true
	default:
		return false
	}
}
