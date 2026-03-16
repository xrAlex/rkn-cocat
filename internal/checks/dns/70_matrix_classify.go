package dns

import (
	"strings"

	"rkn-cocat/internal/entity"
)

func (s *dnsTransportMatrixService) applyRowStats(
	stats *entity.DNSTransportStats,
	domain string,
	final string,
	diverged bool,
) {
	if stats == nil {
		return
	}

	switch final {
	case statusAllOK:
		stats.AllOK++
	case statusPartial:
		stats.Partial++
		stats.PartialResources = append(stats.PartialResources, domain)
	case statusBlocked:
		stats.Blocked++
		stats.BlockedResources = append(stats.BlockedResources, domain)
	}

	if diverged {
		stats.Diverged++
		stats.DivergedResources = append(stats.DivergedResources, domain)
	}
}

func (st *transportProbeState) note(status string, detail string) {
	if strings.TrimSpace(detail) != "" {
		st.lastDetail = detail
	}
	switch status {
	case statusTimeout:
		st.timeouts++
	case statusBlocked:
		st.blocked++
	}
}

func (s *dnsTransportMatrixService) evaluateRow(udp dnsTransportOutcome, tcp dnsTransportOutcome, doh dnsTransportOutcome, dot dnsTransportOutcome) (string, bool) {
	outcomes := []dnsTransportOutcome{udp, tcp, doh, dot}
	successLike := 0
	for _, item := range outcomes {
		if isTransportSuccessLike(item.Status) {
			successLike++
		}
	}

	diverged := hasSuccessfulIPDivergence(outcomes)
	if hasConsistentTransportResult(outcomes) {
		return statusAllOK, diverged
	}

	switch successLike {
	case 0:
		return statusBlocked, diverged
	default:
		return statusPartial, diverged
	}
}

func isTransportSuccessLike(status string) bool {
	switch strings.TrimSpace(status) {
	case statusOK, statusNXDOMAIN:
		return true
	default:
		return false
	}
}

func hasConsistentTransportResult(outcomes []dnsTransportOutcome) bool {
	if len(outcomes) == 0 {
		return false
	}

	baseStatus := strings.TrimSpace(outcomes[0].Status)
	if !isTransportSuccessLike(baseStatus) {
		return false
	}

	for _, outcome := range outcomes[1:] {
		if strings.TrimSpace(outcome.Status) != baseStatus {
			return false
		}
	}

	if baseStatus == statusNXDOMAIN {
		return true
	}

	baseIPs := outcomes[0].IPs
	for _, outcome := range outcomes[1:] {
		if !sameSet(baseIPs, outcome.IPs) {
			return false
		}
	}
	return true
}

func hasSuccessfulIPDivergence(outcomes []dnsTransportOutcome) bool {
	var reference []string
	hasReference := false

	for _, outcome := range outcomes {
		if strings.TrimSpace(outcome.Status) != statusOK || len(outcome.IPs) == 0 {
			continue
		}
		if !hasReference {
			reference = outcome.IPs
			hasReference = true
			continue
		}
		if !sameSet(reference, outcome.IPs) {
			return true
		}
	}

	return false
}
