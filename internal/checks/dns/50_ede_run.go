package dns

import (
	"context"

	"rkn-cocat/internal/entity"
	reportmodel "rkn-cocat/internal/report"
)

func runDNSEDEDiagnosticsTest(ctx context.Context, cfg entity.GlobalConfig) PhaseResult[entity.DNSEDEStats] {
	return newDNSEDEService(ctx, cfg).run()
}

func (s *dnsEDEService) run() PhaseResult[entity.DNSEDEStats] {
	section := reportmodel.Section{
		Title: "Тест 1: DNS EDE diagnostics",
		Blocks: []reportmodel.Block{
			reportmodel.Paragraph{Lines: []string{"Фиксируем EDE, RCODE и ответы A/AAAA с TTL для диагностики блокировок."}},
		},
	}

	domainsRaw := limitItems(s.cfg.DNSEDEDomains, s.cfg.DNSEDEProbeDomains)
	if len(domainsRaw) == 0 {
		section.Blocks = append(section.Blocks, reportmodel.Paragraph{Lines: []string{"Нет доменов для теста 1."}})
		return PhaseResult[entity.DNSEDEStats]{Section: section}
	}

	domains := s.prepareDomains()
	if len(domains) == 0 {
		section.Blocks = append(section.Blocks, reportmodel.Paragraph{Lines: []string{"Нет валидных доменов для теста 1."}})
		return PhaseResult[entity.DNSEDEStats]{Section: section}
	}

	endpoints := s.buildEndpoints()
	if len(endpoints) == 0 {
		section.Blocks = append(section.Blocks, reportmodel.Paragraph{Lines: []string{"Список резолверов для теста 1 пуст."}})
		return PhaseResult[entity.DNSEDEStats]{Section: section}
	}

	probeRows := s.collectProbeRows(domains, endpoints, s.runProbe)
	rows := make([][]string, 0, len(probeRows))
	stats := entity.DNSEDEStats{}
	for _, row := range probeRows {
		if row.Domain == "" && row.Resolver == "" && row.Transport == "" {
			continue
		}

		stats.Total++
		s.classifyStats(&stats, row)
		rows = append(rows, []string{
			row.Domain,
			row.Resolver,
			row.Transport,
			row.A,
			row.AAAA,
			row.TTL,
			row.EDE,
			row.Verdict,
			row.Detail,
		})
	}

	stats.NXDOMAINResources = uniqueStrings(stats.NXDOMAINResources)
	stats.SERVFAILResources = uniqueStrings(stats.SERVFAILResources)
	stats.TimeoutResources = uniqueStrings(stats.TimeoutResources)
	stats.BlockHintResources = uniqueStrings(stats.BlockHintResources)
	stats.EDEBlockedResources = uniqueStrings(stats.EDEBlockedResources)

	section.Blocks = append(section.Blocks, reportmodel.Table{
		Headers: []string{"Домен", "Резолвер", "Транспорт", "A", "AAAA", "TTL", "EDE", "Итог", "Детали"},
		Rows:    rows,
	})

	return PhaseResult[entity.DNSEDEStats]{
		Stats:   stats,
		Section: section,
	}
}
