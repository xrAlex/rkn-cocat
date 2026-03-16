package ooni

import (
	"fmt"

	"rkn-cocat/internal/entity"
	reportmodel "rkn-cocat/internal/report"
)

func newOONISection(cfg entity.GlobalConfig, effectiveSinceDays int) reportmodel.Section {
	parameterLines := []string{
		fmt.Sprintf("Параметры: probe_cc=%s | since_days=%d | concurrency=%d | timeout=%.1fs", cfg.OONIProbeCC, effectiveSinceDays, cfg.OONIConcurrency, cfg.OONITimeoutSec),
	}
	if effectiveSinceDays != cfg.OONISinceDays {
		parameterLines = append(parameterLines, fmt.Sprintf("Примечание: OONI API ограничивает since_days до %d; используется %d вместо %d.", ooniMaxSinceDays, effectiveSinceDays, cfg.OONISinceDays))
	}
	return reportmodel.Section{
		Title: "OONI Blocking Check",
		Blocks: []reportmodel.Block{
			reportmodel.Paragraph{Lines: parameterLines},
		},
	}
}

func appendOONIEmptyTargets(section *reportmodel.Section) {
	if section == nil {
		return
	}
	section.Blocks = append(section.Blocks, reportmodel.Paragraph{Lines: []string{"Нет целей для OONI blocking check."}})
}

func appendOONIResultsTable(section *reportmodel.Section, rows [][]string) {
	if section == nil {
		return
	}
	section.Blocks = append(section.Blocks, reportmodel.Table{
		Headers: []string{"TYPE", "TARGET", "VERDICT", "TEST", "WHEN(UTC)", "DETAILS", "MEASUREMENT"},
		Rows:    rows,
	})
}
