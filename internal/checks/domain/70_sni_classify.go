package domain

import (
	"fmt"
	"net"
	"strings"

	"rkn-cocat/internal/checks/common"
	"rkn-cocat/internal/entity"
)

func (s *sniDiffService) applyPrecheckFailure(row *sniDiffRow, entry entity.DomainEntry) bool {
	if row == nil {
		return true
	}

	if entry.DNSState == dnsStateFail {
		row.Verdict = common.StatusDNSFail
		row.Detail = "Домен не разрешился"
		return true
	}
	if entry.DNSState == dnsStateFake {
		row.Verdict = common.StatusDNSFake
		row.Detail = "DNS подмена IP, SNI-тест пропущен"
		return true
	}
	if strings.TrimSpace(entry.ResolvedIP) == "" {
		row.Verdict = common.StatusDNSFail
		row.Detail = "Нет IP после резолва"
		return true
	}
	return false
}

func (s *sniDiffService) applyVerdictStats(stats *entity.SNIDiffStats, row sniDiffRow) {
	if stats == nil {
		return
	}

	switch row.Verdict {
	case common.StatusSNIDPI:
		stats.Confirmed++
		stats.ConfirmedResources = append(stats.ConfirmedResources, row.Domain)
	case common.StatusNoDiff:
		stats.NoDiff++
	case common.StatusSNIInconclusive:
		stats.Inconclusive++
		stats.InconclusiveResources = append(stats.InconclusiveResources, row.Domain)
	default:
		stats.Error++
		stats.ErrorResources = append(stats.ErrorResources, row.Domain)
	}
}

func formatSNIVerdictDetail(verdict string, domain string, targetDetail string, noSNIDetail string) string {
	switch verdict {
	case common.StatusSNIDPI:
		return fmt.Sprintf("SNI=%s: %s; без SNI: OK", domain, targetDetail)
	case common.StatusSNIInconclusive:
		return fmt.Sprintf("SNI=%s: %s; без SNI: %s", domain, targetDetail, noSNIDetail)
	default:
		return fmt.Sprintf("SNI=%s: %s", domain, targetDetail)
	}
}

func (s *sniDiffService) evaluateVerdict(tcpStatus string, targetSNIStatus string, noSNIStatus string) string {
	if !s.isStatusOK(tcpStatus) {
		return common.StatusTCPFail
	}
	if s.isStatusOK(targetSNIStatus) {
		return common.StatusNoDiff
	}
	if s.isStatusOK(noSNIStatus) {
		return common.StatusSNIDPI
	}
	return common.StatusSNIInconclusive
}

func (s *sniDiffService) isStatusOK(status string) bool {
	return strings.Contains(strings.ToUpper(strings.TrimSpace(status)), common.StatusOK)
}

func (s *sniDiffService) formatProbeStatus(status string, elapsed float64) string {
	status = strings.TrimSpace(status)
	if status == "" {
		status = common.StatusError
	}
	if s.isStatusOK(status) && elapsed > 0 {
		return fmt.Sprintf("%s %.1fs", status, elapsed)
	}
	return status
}

func (s *sniDiffService) fallbackText(primary string, fallback string) string {
	primary = strings.TrimSpace(primary)
	if primary != "" {
		return primary
	}
	fallback = strings.TrimSpace(fallback)
	if fallback != "" {
		return fallback
	}
	return "неизвестно"
}

func (s *sniDiffService) selectTCPNetwork(ip string) string {
	if s.cfg.UseIPv4Only {
		return "tcp4"
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed != nil && parsed.To4() == nil {
		return "tcp6"
	}
	return "tcp"
}
