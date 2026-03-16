package sweep

import (
	"sort"

	"rkn-cocat/internal/entity"
)

func (s *sizeSweepService) resourceLabel(row sweepRow) string {
	return buildResourceLabel(row.Domain, row.ID, row.Provider)
}

func (s *sizeSweepService) applyRowStats(stats *entity.SweepStats, row sweepRow) {
	if stats == nil {
		return
	}

	switch row.Status {
	case statusSweepPass:
		stats.Pass++
	case statusSweepBlock:
		stats.BreakInRange++
		stats.BreakInRangeResources = append(stats.BreakInRangeResources, s.resourceLabel(row))
	case statusSweepOutside:
		stats.BreakOutRange++
		stats.BreakOutRangeResources = append(stats.BreakOutRangeResources, s.resourceLabel(row))
	case statusDNSFail, statusDNSFake:
		stats.DNSFail++
		stats.DNSFailResources = append(stats.DNSFailResources, s.resourceLabel(row))
	default:
		stats.Error++
		stats.ErrorResources = append(stats.ErrorResources, s.resourceLabel(row))
	}
}

func sortSweepRows(rows []sweepRow) {
	providerCounts := map[string]int{}
	for _, row := range rows {
		providerCounts[getGroupName(row.Provider)]++
	}

	sort.Slice(rows, func(i, j int) bool {
		gi := getGroupName(rows[i].Provider)
		gj := getGroupName(rows[j].Provider)
		ci := providerCounts[gi]
		cj := providerCounts[gj]
		if ci != cj {
			return ci > cj
		}
		if gi != gj {
			return gi < gj
		}
		return extractIDNum(rows[i].ID) < extractIDNum(rows[j].ID)
	})
}

func (s *sizeSweepService) aggregateRows(rows []sweepRow) (entity.SweepStats, [][]string) {
	stats := entity.SweepStats{}
	tableRows := make([][]string, 0, len(rows))

	for _, row := range rows {
		stats.Total++
		tableRows = append(tableRows, []string{row.Provider, row.TargetIP, row.Status, row.Detail})
		s.applyRowStats(&stats, row)
	}

	stats.BreakInRangeResources = uniqueStrings(stats.BreakInRangeResources)
	stats.BreakOutRangeResources = uniqueStrings(stats.BreakOutRangeResources)
	stats.DNSFailResources = uniqueStrings(stats.DNSFailResources)
	stats.ErrorResources = uniqueStrings(stats.ErrorResources)

	return stats, tableRows
}
