package sweep

import (
	"context"

	"rkn-cocat/internal/entity"
)

func runSizeSweepTest(ctx context.Context, cfg entity.GlobalConfig, items []entity.TCPTarget, sem chan struct{}, stubIPs map[string]struct{}) PhaseResult[entity.SweepStats] {
	return newSizeSweepService(ctx, cfg, sem, stubIPs).run(items)
}

func (s *sizeSweepService) run(items []entity.TCPTarget) PhaseResult[entity.SweepStats] {
	section := newSweepSection(s.cfg.SweepMinKB, s.cfg.SweepMaxKB)

	if !s.hasValidSweepRange() {
		appendSweepMessage(&section, "Некорректная конфигурация size-sweep: проверьте SweepMinKB/SweepMaxKB.")
		return PhaseResult[entity.SweepStats]{
			Stats:   entity.SweepStats{Error: 1},
			Section: section,
		}
	}

	selected := s.selectedItems(items)
	if len(selected) == 0 {
		appendSweepMessage(&section, "Нет целей для size-sweep теста.")
		return PhaseResult[entity.SweepStats]{Section: section}
	}

	rows := make([]sweepRow, len(selected))
	_ = runParallelContext(s.ctx, len(selected), func(_ context.Context, idx int) {
		rows[idx] = s.worker(selected[idx])
	})

	sortSweepRows(rows)
	stats, tableRows := s.aggregateRows(rows)
	appendSweepTable(&section, tableRows)

	return PhaseResult[entity.SweepStats]{
		Stats:   stats,
		Section: section,
	}
}
