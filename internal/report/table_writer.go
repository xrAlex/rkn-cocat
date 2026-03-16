package report

import (
	"strings"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var (
	renderColorPanelAccent = tcell.GetColor("#1e293b")
	renderColorBorder      = tcell.GetColor("#334155")
	renderColorTitle       = tcell.GetColor("#7dd3fc")
	renderColorTextPrimary = tcell.GetColor("#e2e8f0")
	renderColorPanel       = tcell.GetColor("#0b1220")
	renderColorPanelRaised = tcell.GetColor("#0f172a")
	renderColorSuccess     = tcell.GetColor("#22c55e")
)

type TableWriter struct{}

func NewTableWriter() *TableWriter {
	return &TableWriter{}
}

func (w *TableWriter) Draw(headers []string, rows [][]string) string {
	if w == nil || len(headers) == 0 {
		return ""
	}

	colWidths := computeColumnWidths(headers, rows)
	totalWidth, totalHeight := tableRect(colWidths, len(rows)+1)
	if totalWidth <= 0 || totalHeight <= 0 {
		return ""
	}

	table := newRenderableTable(headers, rows, colWidths)
	table.SetRect(0, 0, totalWidth, totalHeight)

	screen := tcell.NewSimulationScreen("UTF-8")
	if screen == nil {
		return ""
	}
	if err := screen.Init(); err != nil {
		return ""
	}
	defer screen.Fini()

	screen.SetSize(totalWidth, totalHeight)
	table.Draw(screen)
	screen.Show()

	return simulationScreenToText(screen)
}

func newRenderableTable(headers []string, rows [][]string, colWidths []int) *tview.Table {
	table := tview.NewTable().
		SetBorders(true).
		SetSelectable(false, false)
	table.SetBordersColor(renderColorBorder)

	headerStyle := tcell.StyleDefault.Foreground(renderColorTitle).Background(renderColorPanelAccent).Bold(true)
	for c, header := range headers {
		cell := tview.NewTableCell(header).
			SetStyle(headerStyle).
			SetAlign(tview.AlignCenter).
			SetSelectable(false).
			SetExpansion(0)
		if c < len(colWidths) {
			cell.SetMaxWidth(colWidths[c])
		}
		table.SetCell(0, c, cell)
	}

	for r, row := range rows {
		rowBG := renderColorPanelRaised
		if r%2 == 1 {
			rowBG = renderColorPanel
		}
		for c := 0; c < len(headers); c++ {
			value := "—"
			if c < len(row) && strings.TrimSpace(row[c]) != "" {
				value = row[c]
			}

			style := tcell.StyleDefault.Foreground(renderColorTextPrimary).Background(rowBG)
			cell := tview.NewTableCell(value).
				SetStyle(style).
				SetAlign(tview.AlignLeft).
				SetSelectable(false).
				SetExpansion(0)
			if c < len(colWidths) {
				cell.SetMaxWidth(colWidths[c])
			}
			table.SetCell(r+1, c, cell)
		}
	}

	return table
}

func computeColumnWidths(headers []string, rows [][]string) []int {
	widths := make([]int, len(headers))
	for i, header := range headers {
		width := tview.TaggedStringWidth(strings.TrimSpace(header))
		if width < 1 {
			width = 1
		}
		widths[i] = width
	}

	for _, row := range rows {
		for c := 0; c < len(headers); c++ {
			value := "—"
			if c < len(row) && strings.TrimSpace(row[c]) != "" {
				value = row[c]
			}
			width := tview.TaggedStringWidth(value)
			if width < 1 {
				width = 1
			}
			if width > widths[c] {
				widths[c] = width
			}
		}
	}

	return widths
}

func tableRect(colWidths []int, rowCount int) (int, int) {
	if len(colWidths) == 0 || rowCount <= 0 {
		return 0, 0
	}

	totalWidth := len(colWidths) + 1
	for _, width := range colWidths {
		if width < 1 {
			width = 1
		}
		totalWidth += width
	}
	totalHeight := rowCount*2 + 1
	return totalWidth, totalHeight
}

func simulationScreenToText(screen tcell.SimulationScreen) string {
	cells, width, height := screen.GetContents()
	if width <= 0 || height <= 0 || len(cells) == 0 {
		return ""
	}

	lines := make([]string, 0, height)
	for y := 0; y < height; y++ {
		rowStart := y * width
		last := -1
		for x := width - 1; x >= 0; x-- {
			if simCellRune(cells[rowStart+x]) != ' ' {
				last = x
				break
			}
		}
		if last < 0 {
			lines = append(lines, "")
			continue
		}

		var line strings.Builder
		line.Grow(width)
		activeTag := ""
		for x := 0; x <= last; x++ {
			cell := cells[rowStart+x]
			ch := simCellRune(cell)
			nextTag := simCellTag(cell, ch)
			if nextTag != activeTag {
				if activeTag != "" {
					line.WriteString("[-:-:-]")
				}
				if nextTag != "" {
					line.WriteString(nextTag)
				}
				activeTag = nextTag
			}
			line.WriteRune(ch)
		}
		if activeTag != "" {
			line.WriteString("[-:-:-]")
		}
		lines = append(lines, line.String())
	}

	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}

func simCellRune(cell tcell.SimCell) rune {
	if len(cell.Runes) > 0 && cell.Runes[0] != 0 {
		return cell.Runes[0]
	}
	if len(cell.Bytes) > 0 {
		r, _ := utf8.DecodeRune(cell.Bytes)
		if r != utf8.RuneError {
			return r
		}
	}
	return ' '
}

func simCellTag(cell tcell.SimCell, ch rune) string {
	if ch == ' ' {
		return ""
	}

	fg, _, attr := cell.Style.Decompose()
	fg = fg.TrueColor()
	switch fg {
	case renderColorSuccess.TrueColor():
		fallthrough
	case tcell.ColorGreen.TrueColor():
		if attr&tcell.AttrBold != 0 {
			return "[green::b]"
		}
		return "[green]"
	case tcell.ColorYellow.TrueColor():
		if attr&tcell.AttrBold != 0 {
			return "[yellow::b]"
		}
		return "[yellow]"
	case tcell.ColorRed.TrueColor():
		if attr&tcell.AttrBold != 0 {
			return "[red::b]"
		}
		return "[red]"
	default:
		return ""
	}
}
