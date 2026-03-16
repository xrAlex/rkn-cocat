package domain

import (
	"fmt"
	"strings"

	"rkn-cocat/internal/checks/common"
	"rkn-cocat/internal/entity"
)

func formatTLSDetail(res entity.TLSResult) string {
	detail := common.CleanDetail(res.Detail)
	if detail == "" {
		detail = strings.TrimSpace(res.Detail)
	}
	if res.Elapsed <= 0 {
		return detail
	}
	if detail == "" {
		return fmt.Sprintf("%.1fs", res.Elapsed)
	}
	return fmt.Sprintf("%s | %.1fs", detail, res.Elapsed)
}

func domainStatsFromRows(rows []domainPhaseRow) entity.DomainStats {
	okCount := 0
	blockedResources := make([]string, 0, len(rows))
	timeoutResources := make([]string, 0, len(rows))
	dnsFailResources := make([]string, 0, len(rows))
	blockMarkers := []string{common.StatusTLSDPI, common.StatusTLSMITM, common.StatusTLSBlock, common.StatusISPPage, common.StatusBlocked, common.StatusTCPRST, common.StatusTCPAbort}

	for _, row := range rows {
		status := strings.ToUpper(strings.TrimSpace(row.Status))
		if status == "" || status == "—" {
			continue
		}
		if strings.Contains(status, common.StatusOK) || strings.Contains(status, common.StatusRedir) {
			okCount++
		}
		if common.ContainsAny(status, blockMarkers) {
			blockedResources = append(blockedResources, row.Domain)
		}
		if strings.Contains(status, common.StatusTimeout) {
			timeoutResources = append(timeoutResources, row.Domain)
		}
		if strings.Contains(status, common.StatusDNSFail) {
			dnsFailResources = append(dnsFailResources, row.Domain)
		}
	}

	blockedResources = common.UniqueStrings(blockedResources)
	timeoutResources = common.UniqueStrings(timeoutResources)
	dnsFailResources = common.UniqueStrings(dnsFailResources)

	return entity.DomainStats{
		Total:            len(rows),
		OK:               okCount,
		Blocked:          len(blockedResources),
		Timeout:          len(timeoutResources),
		DNSFail:          len(dnsFailResources),
		BlockedResources: blockedResources,
		TimeoutResources: timeoutResources,
		DNSFailResources: dnsFailResources,
	}
}
