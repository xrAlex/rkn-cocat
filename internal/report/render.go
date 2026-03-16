package report

import (
	"strings"
	"unicode/utf8"
)

const minHeaderBlockWidth = 44

func WriteHeader(out *Writer, header Header) {
	if out == nil {
		return
	}

	width := utf8.RuneCountInString(header.Title)
	for _, line := range header.Lines {
		if n := utf8.RuneCountInString(line); n > width {
			width = n
		}
	}
	if width < minHeaderBlockWidth {
		width = minHeaderBlockWidth
	}

	top := "┏" + strings.Repeat("━", width+2) + "┓"
	sep := "┣" + strings.Repeat("━", width+2) + "┫"
	bot := "┗" + strings.Repeat("━", width+2) + "┛"

	out.Println(top)
	out.Println("┃ " + padRight(header.Title, width) + " ┃")
	if len(header.Lines) > 0 {
		out.Println(sep)
		for _, line := range header.Lines {
			out.Println("┃ " + padRight(line, width) + " ┃")
		}
	}
	out.Println(bot)
}

func WriteSection(out *Writer, section Section) {
	if out == nil {
		return
	}
	if strings.TrimSpace(section.Title) != "" {
		writeSectionTitle(out, section.Title)
	}
	for _, block := range section.Blocks {
		WriteBlock(out, block)
	}
}

func WriteBlock(out *Writer, block Block) {
	if out == nil || block == nil {
		return
	}

	switch typedBlock := block.(type) {
	case Header:
		WriteHeader(out, typedBlock)
	case *Header:
		if typedBlock != nil {
			WriteHeader(out, *typedBlock)
		}
	case Paragraph:
		WriteParagraph(out, typedBlock)
	case *Paragraph:
		if typedBlock != nil {
			WriteParagraph(out, *typedBlock)
		}
	case Table:
		WriteTable(out, typedBlock)
	case *Table:
		if typedBlock != nil {
			WriteTable(out, *typedBlock)
		}
	}
}

func WriteParagraph(out *Writer, paragraph Paragraph) {
	if out == nil {
		return
	}
	for _, line := range paragraph.Lines {
		out.Println(line)
	}
}

func WriteTable(out *Writer, table Table) {
	if out == nil || len(table.Headers) == 0 {
		return
	}

	cleanHeaders := make([]string, len(table.Headers))
	for i, header := range table.Headers {
		cleanHeaders[i] = sanitizeCellText(header)
	}

	cleanRows := make([][]string, 0, len(table.Rows))
	for _, row := range table.Rows {
		sanitizedRow := make([]string, len(cleanHeaders))
		for i := 0; i < len(cleanHeaders) && i < len(row); i++ {
			sanitizedRow[i] = sanitizeCellText(row[i])
		}
		cleanRows = append(cleanRows, sanitizedRow)
	}

	displayRows := cleanRows
	if out.UseTView() {
		displayRows = make([][]string, len(cleanRows))
		for r, row := range cleanRows {
			colored := make([]string, len(cleanHeaders))
			for c := 0; c < len(cleanHeaders); c++ {
				value := "—"
				if c < len(row) {
					value = row[c]
				}
				colored[c] = tableStatusColorizer.colorizeCell(out, cleanHeaders[c], value)
			}
			displayRows[r] = colored
		}
	}

	rendered := NewTableWriter().Draw(cleanHeaders, displayRows)
	if strings.TrimSpace(rendered) == "" {
		return
	}
	out.Println(rendered)
}

func writeSectionTitle(out *Writer, title string) {
	if out == nil {
		return
	}
	width := utf8.RuneCountInString(title) + 4
	if width < 36 {
		width = 36
	}
	line := strings.Repeat("─", width)
	out.Println("")
	out.Println("┌" + line + "┐")
	out.Println("│ " + padRight(title, width-2) + " │")
	out.Println("└" + line + "┘")
}

func sanitizeCellText(text string) string {
	text = strings.ReplaceAll(text, "\r", " ")
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.TrimSpace(text)
	if text == "" {
		return "—"
	}
	return text
}

func containsAny(text string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func padRight(text string, size int) string {
	runeCount := utf8.RuneCountInString(text)
	if runeCount >= size {
		return text
	}
	return text + strings.Repeat(" ", size-runeCount)
}
