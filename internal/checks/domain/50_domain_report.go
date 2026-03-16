package domain

import (
	"context"
	"strings"

	"rkn-cocat/internal/checks/common"
	"rkn-cocat/internal/entity"
	reportmodel "rkn-cocat/internal/report"
)

func (p *Pipeline) RunResolveTest(_ context.Context, entries []entity.DomainEntry) common.PhaseResult[entity.DomainStats] {
	rows := make([][]string, 0, len(entries))
	phaseRows := make([]domainPhaseRow, 0, len(entries))

	for _, entry := range entries {
		status := common.StatusDNSOK
		detail := ""
		switch entry.DNSState {
		case dnsStateFail:
			status = common.StatusDNSFail
			detail = strings.TrimSpace(entry.T13Res.Detail)
			if detail == "" {
				detail = "Домен не найден"
			}
		case dnsStateFake:
			status = common.StatusDNSFake
			detail = strings.TrimSpace(entry.T13Res.Detail)
		}

		phaseRows = append(phaseRows, domainPhaseRow{
			Domain: entry.Domain,
			Status: status,
			Detail: detail,
		})
		rows = append(rows, []string{entry.Domain, status, entry.ResolvedIP, detail})
	}

	return common.PhaseResult[entity.DomainStats]{
		Stats: domainStatsFromRows(phaseRows),
		Section: reportmodel.Section{
			Title: "Тест 2: DNS-резолв",
			Blocks: []reportmodel.Block{
				reportmodel.Table{
					Headers: []string{"Домен", "DNS", "IP", "Детали"},
					Rows:    rows,
				},
			},
		},
	}
}

func (p *Pipeline) runTLSTest(
	ctx context.Context,
	entries []entity.DomainEntry,
	sectionTitle string,
	tlsVersion string,
	statusColumn string,
	useTLS13 bool,
) common.PhaseResult[entity.DomainStats] {
	_ = common.RunParallelContext(ctx, len(entries), func(_ context.Context, idx int) {
		p.runTLSPhase(&entries[idx], tlsVersion)
	})

	rows := make([][]string, 0, len(entries))
	phaseRows := make([]domainPhaseRow, 0, len(entries))
	for _, entry := range entries {
		result := entry.T12Res
		if useTLS13 {
			result = entry.T13Res
		}
		detail := formatTLSDetail(result)
		phaseRows = append(phaseRows, domainPhaseRow{
			Domain: entry.Domain,
			Status: result.Status,
			Detail: detail,
		})
		rows = append(rows, []string{entry.Domain, result.Status, detail})
	}

	return common.PhaseResult[entity.DomainStats]{
		Stats: domainStatsFromRows(phaseRows),
		Section: reportmodel.Section{
			Title: sectionTitle,
			Blocks: []reportmodel.Block{
				reportmodel.Table{
					Headers: []string{"Домен", statusColumn, "Детали"},
					Rows:    rows,
				},
			},
		},
	}
}

func (p *Pipeline) RunTLS13Test(ctx context.Context, entries []entity.DomainEntry) common.PhaseResult[entity.DomainStats] {
	return p.runTLSTest(ctx, entries, "Тест 3: TLS 1.3", "TLSv1.3", "TLS1.3", true)
}

func (p *Pipeline) RunTLS12Test(ctx context.Context, entries []entity.DomainEntry) common.PhaseResult[entity.DomainStats] {
	return p.runTLSTest(ctx, entries, "Тест 4: TLS 1.2", "TLSv1.2", "TLS1.2", false)
}

func (p *Pipeline) RunHTTPTest(ctx context.Context, entries []entity.DomainEntry) common.PhaseResult[entity.DomainStats] {
	_ = common.RunParallelContext(ctx, len(entries), func(_ context.Context, idx int) {
		p.runHTTPPhase(&entries[idx])
	})

	rows := make([][]string, 0, len(entries))
	phaseRows := make([]domainPhaseRow, 0, len(entries))
	for _, entry := range entries {
		detail := common.CleanDetail(entry.HTTPRes.Detail)
		if detail == "" {
			detail = strings.TrimSpace(entry.HTTPRes.Detail)
		}
		phaseRows = append(phaseRows, domainPhaseRow{
			Domain: entry.Domain,
			Status: entry.HTTPRes.Status,
			Detail: detail,
		})
		rows = append(rows, []string{entry.Domain, entry.HTTPRes.Status, detail})
	}

	return common.PhaseResult[entity.DomainStats]{
		Stats: domainStatsFromRows(phaseRows),
		Section: reportmodel.Section{
			Title: "Тест 5: HTTP injection",
			Blocks: []reportmodel.Block{
				reportmodel.Table{
					Headers: []string{"Домен", "HTTP", "Детали"},
					Rows:    rows,
				},
			},
		},
	}
}
