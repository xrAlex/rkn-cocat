package domain

import (
	"context"
	"sort"

	"rkn-cocat/internal/checks/common"
	"rkn-cocat/internal/entity"
	reportmodel "rkn-cocat/internal/report"
)

func RunTLSSNIDifferentialTest(ctx context.Context, cfg entity.GlobalConfig, entries []entity.DomainEntry, sem chan struct{}) common.PhaseResult[entity.SNIDiffStats] {
	return newSNIDiffService(ctx, cfg, sem).run(entries)
}

func (s *sniDiffService) run(entries []entity.DomainEntry) common.PhaseResult[entity.SNIDiffStats] {
	section := reportmodel.Section{
		Title: "Тест 6: TLS дифференциальный SNI",
		Blocks: []reportmodel.Block{
			reportmodel.Paragraph{Lines: []string{"Сценарий: TCP к IP:443 -> TLS с SNI=target -> TLS к тому же IP без SNI."}},
		},
	}

	probeEntries := common.LimitItems(entries, s.cfg.SNIDiffProbeDomains)
	if len(probeEntries) == 0 {
		section.Blocks = append(section.Blocks, reportmodel.Paragraph{Lines: []string{"Нет доменов для SNI-теста."}})
		return common.PhaseResult[entity.SNIDiffStats]{Section: section}
	}

	rows := make([]sniDiffRow, len(probeEntries))
	_ = common.RunParallelContext(s.ctx, len(probeEntries), func(_ context.Context, idx int) {
		rows[idx] = s.worker(probeEntries[idx])
	})
	sort.Slice(rows, func(i, j int) bool { return rows[i].Domain < rows[j].Domain })

	stats := entity.SNIDiffStats{Total: len(rows)}
	tableRows := make([][]string, 0, len(rows))

	for _, row := range rows {
		tableRows = append(tableRows, []string{
			row.Domain,
			row.IP,
			row.TCPStatus,
			row.TargetSNI,
			row.NoSNI,
			row.Verdict,
			row.Detail,
		})

		s.applyVerdictStats(&stats, row)
	}

	stats.ConfirmedResources = common.UniqueStrings(stats.ConfirmedResources)
	stats.InconclusiveResources = common.UniqueStrings(stats.InconclusiveResources)
	stats.ErrorResources = common.UniqueStrings(stats.ErrorResources)

	section.Blocks = append(section.Blocks, reportmodel.Table{
		Headers: []string{
			"Домен",
			"IP",
			"TCP:443",
			"TLS SNI=target",
			"TLS no SNI",
			"Итог",
			"Детали",
		},
		Rows: tableRows,
	})

	return common.PhaseResult[entity.SNIDiffStats]{
		Stats:   stats,
		Section: section,
	}
}
