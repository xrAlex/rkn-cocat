package ooni

import (
	"strings"

	"rkn-cocat/internal/entity"
)

func aggregateOONIResults(allResults []entity.OONIResult) (entity.OONIStats, [][]string) {
	stats := entity.OONIStats{}
	tableRows := make([][]string, 0, len(allResults))

	for _, result := range allResults {
		stats.Total++
		resource := buildResourceLabel(result.Target, "", "")

		switch result.Verdict {
		case ooniVerdictOK:
			stats.OK++
		case ooniVerdictBlocked:
			stats.Blocked++
			stats.BlockedResources = append(stats.BlockedResources, resource)
		case ooniVerdictNoData:
			stats.NoData++
			stats.NoDataResources = append(stats.NoDataResources, resource)
		case ooniVerdictTCPReach:
			stats.TCPReachable++
			stats.TCPReachResources = append(stats.TCPReachResources, resource)
		case ooniVerdictTCPFail:
			stats.TCPFail++
			stats.TCPFailResources = append(stats.TCPFailResources, resource)
		default:
			stats.Unknown++
			stats.UnknownResources = append(stats.UnknownResources, resource)
		}

		tableRows = append(tableRows, []string{
			result.TargetType,
			result.Target,
			string(result.Verdict),
			result.TestName,
			ooniWhenValue(result.When),
			formatOONIDetail(result),
			result.MeasurementURL,
		})
	}

	stats.BlockedResources = uniqueStrings(stats.BlockedResources)
	stats.NoDataResources = uniqueStrings(stats.NoDataResources)
	stats.TCPReachResources = uniqueStrings(stats.TCPReachResources)
	stats.TCPFailResources = uniqueStrings(stats.TCPFailResources)
	stats.UnknownResources = uniqueStrings(stats.UnknownResources)

	return stats, tableRows
}

func formatOONIDetail(result entity.OONIResult) string {
	details := strings.TrimSpace(result.Reason)
	if result.Notes != "" {
		if details == "" {
			details = result.Notes
		} else {
			details += " | " + result.Notes
		}
	}
	if details == "" {
		return "—"
	}
	return details
}

func ooniWhenValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "—"
	}
	return value
}
