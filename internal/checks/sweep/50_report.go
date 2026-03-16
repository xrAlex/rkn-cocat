package sweep

import (
	"fmt"

	reportmodel "rkn-cocat/internal/report"
)

func newSweepSection(minKB int, maxKB int) reportmodel.Section {
	return reportmodel.Section{
		Title: "Size Sweep",
		Blocks: []reportmodel.Block{
			reportmodel.Paragraph{Lines: []string{fmt.Sprintf("Диапазон анализа: %d-%dKB", minKB, maxKB)}},
		},
	}
}

func appendSweepMessage(section *reportmodel.Section, line string) {
	if section == nil {
		return
	}
	section.Blocks = append(section.Blocks, reportmodel.Paragraph{Lines: []string{line}})
}

func appendSweepTable(section *reportmodel.Section, rows [][]string) {
	if section == nil {
		return
	}
	section.Blocks = append(section.Blocks, reportmodel.Table{
		Headers: []string{"Провайдер", "IP", "Статус", "Детали"},
		Rows:    rows,
	})
}
