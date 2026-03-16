package dns

import (
	"context"
	"strings"

	"rkn-cocat/internal/entity"
	reportmodel "rkn-cocat/internal/report"
)

func runDNSTransportMatrixTest(ctx context.Context, cfg entity.GlobalConfig) PhaseResult[entity.DNSTransportStats] {
	return newDNSTransportMatrixService(ctx, cfg).run()
}

func (s *dnsTransportMatrixService) run() PhaseResult[entity.DNSTransportStats] {
	section := reportmodel.Section{
		Title: "Проверка DNS Transport Matrix",
		Blocks: []reportmodel.Block{
			reportmodel.Paragraph{Lines: []string{"Транспорты: UDP53 / TCP53 / DoH / DoT"}},
		},
	}

	domains := s.prepareDomains()
	if len(domains) == 0 {
		section.Blocks = append(section.Blocks, reportmodel.Paragraph{Lines: []string{"Нет доменов для DNS transport matrix."}})
		return PhaseResult[entity.DNSTransportStats]{Section: section}
	}

	stats := entity.DNSTransportStats{Total: len(domains)}
	rows := make([][]string, 0, len(domains))
	matrixRows := s.collectRows(domains, s.buildRow)

	for _, row := range matrixRows {
		if strings.TrimSpace(row.Domain) == "" {
			continue
		}

		s.applyRowStats(&stats, row.Domain, row.Final, row.Diverged)
		rows = append(rows, []string{
			row.Domain,
			s.formatCell(row.UDP),
			s.formatCell(row.TCP),
			s.formatCell(row.DoH),
			s.formatCell(row.DoT),
			row.Final,
		})
	}

	stats.BlockedResources = uniqueStrings(stats.BlockedResources)
	stats.PartialResources = uniqueStrings(stats.PartialResources)
	stats.DivergedResources = uniqueStrings(stats.DivergedResources)
	section.Blocks = append(section.Blocks, reportmodel.Table{
		Headers: []string{"Домен", "UDP53", "TCP53", "DoH", "DoT", "Итог"},
		Rows:    rows,
	})

	return PhaseResult[entity.DNSTransportStats]{
		Stats:   stats,
		Section: section,
	}
}
