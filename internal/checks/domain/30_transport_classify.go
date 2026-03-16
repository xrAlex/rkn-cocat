package domain

import (
	"fmt"
	"strings"

	"rkn-cocat/internal/checks/common"
)

func normalizeRedirectHost(host string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(host)), "www.")
}

func isRelatedRedirectDomain(domain string, locationDomain string) bool {
	cleanDomain := normalizeRedirectHost(domain)
	cleanLoc := normalizeRedirectHost(locationDomain)
	if cleanDomain == "" || cleanLoc == "" {
		return false
	}
	return cleanLoc == cleanDomain ||
		strings.HasSuffix(cleanLoc, "."+cleanDomain) ||
		strings.HasSuffix(cleanDomain, "."+cleanLoc)
}

func isLegitRedirectDomain(locationDomain string) bool {
	return common.ContainsAny(normalizeRedirectHost(locationDomain), tlsLegitRedirectMarkers)
}

func normalizeTransportAttemptStatus(status string) string {
	status = strings.TrimSpace(status)
	if status == "" {
		return common.StatusError
	}
	return status
}

func isSuccessfulTransportAttempt(status string) bool {
	return strings.Contains(strings.ToUpper(strings.TrimSpace(status)), common.StatusOK)
}

func transportFailurePriority(status string) int {
	switch {
	case common.ContainsAny(status, []string{
		common.StatusISPPage,
		common.StatusBlocked,
		common.StatusTLSDPI,
		common.StatusTLSBlock,
		common.StatusTLSMITM,
		common.StatusTCP1620,
		common.StatusTCPRST,
		common.StatusTCPAbort,
		common.StatusDPIReset,
		common.StatusDPIAbort,
		common.StatusDPIClose,
	}):
		return 0
	case common.ContainsAny(status, []string{common.StatusTimeout, common.StatusNetUnreach, common.StatusHostUnreach}):
		return 1
	case common.ContainsAny(status, []string{common.StatusDNSFail, common.StatusRefused, common.StatusConnFail}):
		return 2
	default:
		return 3
	}
}

func formatTransportAttemptSummary(order []string, counts map[string]int, total int) string {
	if total <= 0 || len(order) <= 1 {
		return ""
	}

	parts := make([]string, 0, len(order))
	for _, status := range order {
		parts = append(parts, fmt.Sprintf("%s=%d/%d", status, counts[status], total))
	}
	return strings.Join(parts, ", ")
}

func mergeTransportAttemptDetail(primary string, summary string, emphasizeMixed bool) string {
	primary = strings.TrimSpace(primary)
	summary = strings.TrimSpace(summary)
	if summary == "" {
		return primary
	}

	label := "Ретраи"
	if emphasizeMixed {
		label = "Смешанные ретраи"
	}
	summary = label + ": " + summary

	if primary == "" {
		return summary
	}
	return primary + " | " + summary
}

func chooseTransportFailureResult(results []transportAttemptResult, counts map[string]int, order []string) transportAttemptResult {
	best := transportAttemptResult{Status: common.StatusError}
	bestCount := -1
	bestPriority := 1 << 30
	hasBest := false

	for _, status := range order {
		count := counts[status]
		priority := transportFailurePriority(status)
		candidate := transportAttemptResult{Status: status}
		for _, item := range results {
			if normalizeTransportAttemptStatus(item.Status) == status {
				candidate = item
				break
			}
		}

		if !hasBest || count > bestCount || (count == bestCount && priority < bestPriority) {
			best = candidate
			bestCount = count
			bestPriority = priority
			hasBest = true
		}
	}

	return best
}

func (s *transportCheckService) aggregateTransportResults(results []transportAttemptResult) transportAttemptResult {
	if len(results) == 0 {
		return transportAttemptResult{Status: common.StatusError, Detail: "Операция отменена"}
	}

	counts := make(map[string]int, len(results))
	order := make([]string, 0, len(results))
	okResult := transportAttemptResult{}
	hasOK := false
	maxCount := 0

	for idx := range results {
		results[idx].Status = normalizeTransportAttemptStatus(results[idx].Status)
		status := results[idx].Status
		if _, exists := counts[status]; !exists {
			order = append(order, status)
		}
		counts[status]++
		if counts[status] > maxCount {
			maxCount = counts[status]
		}
		if !hasOK && isSuccessfulTransportAttempt(status) {
			okResult = results[idx]
			hasOK = true
		}
	}

	if len(order) == 1 {
		return results[0]
	}

	mixedPct := float64(len(results)-maxCount) * 100 / float64(len(results))
	emphasizeMixed := mixedPct >= s.cfg.DpiVarianceThresh
	summary := formatTransportAttemptSummary(order, counts, len(results))

	if hasOK {
		okResult.Detail = mergeTransportAttemptDetail(okResult.Detail, summary, emphasizeMixed)
		return okResult
	}

	best := chooseTransportFailureResult(results, counts, order)
	best.Detail = mergeTransportAttemptDetail(best.Detail, summary, emphasizeMixed)
	return best
}

func (s *transportCheckService) classifyTLSHTTPResponse(domain string, statusCode int, location string) (string, string, bool) {
	if statusCode == 451 {
		return common.StatusBlocked, "HTTP 451 (юридическое ограничение доступа)", true
	}
	location = strings.TrimSpace(location)
	if location == "" {
		return "", "", false
	}

	locationLower := strings.ToLower(location)
	if common.ContainsAny(locationLower, s.cfg.BlockMarkers) {
		return common.StatusISPPage, "Редирект на страницу ограничения доступа", true
	}

	locationDomain := common.ExtractLocationDomain(location)
	if locationDomain == "" {
		return "", "", false
	}
	if isRelatedRedirectDomain(domain, locationDomain) {
		return "", "", false
	}
	if isLegitRedirectDomain(locationDomain) {
		return "", "", false
	}
	return common.StatusISPPage, "Редирект на сторонний домен: " + locationDomain, true
}

func (s *transportCheckService) classifyHTTPRedirect(domain string, statusCode int, location string) (string, string) {
	location = strings.TrimSpace(location)
	if location == "" {
		return common.StatusRedir, fmt.Sprintf("%d", statusCode)
	}

	locationLower := strings.ToLower(location)
	if common.ContainsAny(locationLower, s.cfg.BlockMarkers) {
		return common.StatusISPPage, "Редирект/страница ограничения доступа"
	}

	locationDomain := common.ExtractLocationDomain(location)
	if locationDomain == "" || isRelatedRedirectDomain(domain, locationDomain) || isLegitRedirectDomain(locationDomain) {
		return common.StatusOK, fmt.Sprintf("%d", statusCode)
	}
	return common.StatusRedir, fmt.Sprintf("%d -> %s", statusCode, locationDomain)
}
