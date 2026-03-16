package dns

import (
	"fmt"
	"strings"

	"rkn-cocat/internal/entity"
)

func dnsSemanticStatus(result dnsWireResult, qType uint16) string {
	if result.Status != statusOK {
		return result.Status
	}

	switch result.Message.RCode {
	case 0:
		if len(collectDNSAnswerValues(result.Message, qType)) > 0 {
			return statusValid
		}
		return statusNoErrorEmpty
	case 2:
		return statusSERVFAIL
	case 3:
		return statusNXDOMAIN
	case 5:
		return statusRefused
	default:
		return dnsRCodeName(result.Message.RCode)
	}
}

func combineDNSVerdict(aStatus string, aaaaStatus string, blockHint bool) string {
	if aStatus == statusValid || aaaaStatus == statusValid {
		if blockHint {
			return statusValidWithDNSHint
		}
		return statusValid
	}

	switch {
	case aStatus == statusNXDOMAIN && aaaaStatus == statusNXDOMAIN:
		return statusNXDOMAIN
	case aStatus == statusSERVFAIL || aaaaStatus == statusSERVFAIL:
		return statusSERVFAIL
	case aStatus == statusTimeout && aaaaStatus == statusTimeout:
		return statusTimeout
	case aStatus == statusBlocked && aaaaStatus == statusBlocked:
		return statusBlocked
	case aStatus == statusRefused && aaaaStatus == statusRefused:
		return statusRefused
	case aStatus == statusNoErrorEmpty && aaaaStatus == statusNoErrorEmpty:
		return statusNoErrorEmptyView
	case aStatus == aaaaStatus:
		return aStatus
	default:
		return fmt.Sprintf("%s (%s/%s)", statusMixed, aStatus, aaaaStatus)
	}
}

func formatQueryRCODE(result dnsWireResult, qType uint16) string {
	if result.Status != statusOK {
		return result.Status
	}
	if result.Message.RCode == 0 && len(collectDNSAnswerValues(result.Message, qType)) > 0 {
		return statusNoErrorAnswer
	}
	if result.Message.RCode == 0 {
		return "NOERROR/EMPTY"
	}
	return dnsRCodeName(result.Message.RCode)
}

func formatTTLSummary(aTTL []uint32, aaaaTTL []uint32) string {
	partA := "A:—"
	partAAAA := "AAAA:—"
	if len(aTTL) > 0 {
		partA = "A:" + formatTTLRange(aTTL)
	}
	if len(aaaaTTL) > 0 {
		partAAAA = "AAAA:" + formatTTLRange(aaaaTTL)
	}
	return partA + " | " + partAAAA
}

func formatTTLRange(values []uint32) string {
	if len(values) == 0 {
		return "—"
	}
	minTTL := values[0]
	maxTTL := values[0]
	for _, value := range values[1:] {
		if value < minTTL {
			minTTL = value
		}
		if value > maxTTL {
			maxTTL = value
		}
	}
	if minTTL == maxTTL {
		return fmt.Sprintf("%d", minTTL)
	}
	return fmt.Sprintf("%d-%d", minTTL, maxTTL)
}

func formatAnswerValues(values []string) string {
	if len(values) == 0 {
		return "—"
	}
	if len(values) <= 2 {
		return strings.Join(values, ", ")
	}
	return fmt.Sprintf("%s, %s (+%d)", values[0], values[1], len(values)-2)
}

func collectDNSAnswerValues(message entity.DNSWireMessage, qType uint16) []string {
	out := make([]string, 0, len(message.Answers))
	for _, answer := range message.Answers {
		if answer.Type == qType {
			out = append(out, strings.TrimSpace(answer.Data))
		}
	}
	return uniqueStrings(out)
}

func collectDNSTTL(message entity.DNSWireMessage, qType uint16) []uint32 {
	out := make([]uint32, 0, len(message.Answers))
	for _, answer := range message.Answers {
		if answer.Type == qType {
			out = append(out, answer.TTL)
		}
	}
	return out
}

func mergeDNSEDE(left []entity.DNSEDEOption, right []entity.DNSEDEOption) []entity.DNSEDEOption {
	merged := make([]entity.DNSEDEOption, 0, len(left)+len(right))
	seen := make(map[string]struct{}, len(left)+len(right))
	appendItems := func(items []entity.DNSEDEOption) {
		for _, item := range items {
			key := fmt.Sprintf("%d|%s", item.Code, strings.TrimSpace(item.Text))
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			merged = append(merged, item)
		}
	}
	appendItems(left)
	appendItems(right)
	return merged
}

func formatEDEItems(items []entity.DNSEDEOption) string {
	if len(items) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		part := fmt.Sprintf("%d(%s)", item.Code, edeCodeName(item.Code))
		detail := strings.TrimSpace(cleanDetail(item.Text))
		if detail != "" {
			part += ": " + limitString(detail, 48)
		}
		parts = append(parts, part)
	}
	if len(parts) <= 2 {
		return strings.Join(parts, " | ")
	}
	return strings.Join(parts[:2], " | ") + fmt.Sprintf(" (+%d)", len(parts)-2)
}

func detectEDEBlocked(items []entity.DNSEDEOption) (bool, string) {
	for _, item := range items {
		if isBlockedEDECode(item.Code) {
			return true, fmt.Sprintf("EDE %d(%s)", item.Code, edeCodeName(item.Code))
		}
		lower := strings.ToLower(strings.TrimSpace(item.Text))
		if containsAny(lower, blockedTextMarkers()) {
			return true, "EDE text marker: " + limitString(lower, 40)
		}
	}
	return false, ""
}

func detectDNSBlockHints(
	cfg entity.GlobalConfig,
	msgA entity.DNSWireMessage,
	msgAAAA entity.DNSWireMessage,
	aValues []string,
	aaaaValues []string,
	edeItems []entity.DNSEDEOption,
) (bool, []string) {
	reasons := make([]string, 0, 4)
	if blocked, reason := detectEDEBlocked(edeItems); blocked && reason != "" {
		reasons = append(reasons, reason)
	}

	ipSet := make(map[string]struct{}, len(aValues)+len(aaaaValues))
	for _, item := range aValues {
		ipSet[item] = struct{}{}
	}
	for _, item := range aaaaValues {
		ipSet[item] = struct{}{}
	}

	blockIPs := make(map[string]struct{}, len(cfg.DNSBlockIPs))
	for _, item := range cfg.DNSBlockIPs {
		blockIPs[strings.TrimSpace(item)] = struct{}{}
	}
	for ip := range ipSet {
		if _, ok := blockIPs[ip]; ok {
			reasons = append(reasons, "IP совпадает с dns_block_ips: "+ip)
		}
	}

	cnames := append(collectDNSAnswerValues(msgA, dnsTypeCNAME), collectDNSAnswerValues(msgAAAA, dnsTypeCNAME)...)
	cnames = uniqueStrings(cnames)
	if len(cnames) > 0 {
		markers := append([]string{}, cfg.BlockMarkers...)
		markers = append(markers, cfg.BodyBlockMarkers...)
		for _, cname := range cnames {
			lower := strings.ToLower(strings.TrimSpace(cname))
			if lower == "" {
				continue
			}
			if containsAny(lower, normalizeMarkers(markers)) {
				reasons = append(reasons, "CNAME marker: "+limitString(cname, 44))
				break
			}
		}
	}

	return len(reasons) > 0, uniqueStrings(reasons)
}

func blockedTextMarkers() []string {
	return []string{
		"blocked",
		"censored",
		"filtered",
		"prohibited",
		"forbidden",
		"restricted",
		"заблок",
		"ограничен",
	}
}

func normalizeMarkers(markers []string) []string {
	out := make([]string, 0, len(markers))
	for _, marker := range markers {
		clean := strings.ToLower(strings.TrimSpace(marker))
		if clean == "" {
			continue
		}
		out = append(out, clean)
	}
	return uniqueStrings(out)
}

func isBlockedEDECode(code uint16) bool {
	switch code {
	case 15, 16, 17, 18:
		return true
	default:
		return false
	}
}

func edeCodeName(code uint16) string {
	switch code {
	case 0:
		return "Other"
	case 1:
		return "Unsupported DNSKEY Algo"
	case 2:
		return "Unsupported DS Digest"
	case 3:
		return "Stale Answer"
	case 4:
		return "Forged Answer"
	case 5:
		return "DNSSEC Indeterminate"
	case 6:
		return "DNSSEC Bogus"
	case 7:
		return "Signature Expired"
	case 8:
		return "Signature Not Yet Valid"
	case 9:
		return "DNSKEY Missing"
	case 10:
		return "RRSIGs Missing"
	case 11:
		return "No Zone Key Bit Set"
	case 12:
		return "NSEC Missing"
	case 13:
		return "Cached Error"
	case 14:
		return "Not Ready"
	case 15:
		return "Blocked"
	case 16:
		return "Censored"
	case 17:
		return "Filtered"
	case 18:
		return "Prohibited"
	case 19:
		return "Stale NXDOMAIN"
	case 20:
		return "Not Authoritative"
	case 21:
		return "Not Supported"
	case 22:
		return "No Reachable Authority"
	case 23:
		return "Network Error"
	case 24:
		return "Invalid Data"
	default:
		return "Code " + fmt.Sprintf("%d", code)
	}
}

func dnsRCodeName(code int) string {
	switch code {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return statusSERVFAIL
	case 3:
		return statusNXDOMAIN
	case 4:
		return "NOTIMP"
	case 5:
		return statusRefused
	case 6:
		return "YXDOMAIN"
	case 7:
		return "YXRRSET"
	case 8:
		return "NXRRSET"
	case 9:
		return "NOTAUTH"
	case 10:
		return "NOTZONE"
	default:
		return fmt.Sprintf("RCODE=%d", code)
	}
}

func limitString(value string, maxRunes int) string {
	if maxRunes <= 0 {
		return value
	}
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	if maxRunes <= 3 {
		return string(runes[:maxRunes])
	}
	return string(runes[:maxRunes-3]) + "..."
}

func normalizeWireTransportStatus(status string, detail string) string {
	switch status {
	case statusTimeout:
		return statusTimeout
	case statusBlocked:
		return statusBlocked
	default:
		if strings.TrimSpace(detail) != "" {
			return statusError
		}
		return statusError
	}
}

func (s *dnsEDEService) classifyStats(stats *entity.DNSEDEStats, row dnsEDEProbeRow) {
	switch row.Verdict {
	case statusNXDOMAIN:
		stats.NXDOMAIN++
		stats.NXDOMAINResources = append(stats.NXDOMAINResources, row.Resource)
	case statusSERVFAIL:
		stats.SERVFAIL++
		stats.SERVFAILResources = append(stats.SERVFAILResources, row.Resource)
	case statusTimeout:
		stats.Timeout++
		stats.TimeoutResources = append(stats.TimeoutResources, row.Resource)
	default:
		if strings.HasPrefix(row.Verdict, statusValid) {
			stats.Valid++
		} else {
			stats.Error++
		}
	}

	if row.BlockHint {
		stats.BlockHint++
		stats.BlockHintResources = append(stats.BlockHintResources, row.Resource)
	}
	if row.EDEBlocked {
		stats.EDEBlocked++
		stats.EDEBlockedResources = append(stats.EDEBlockedResources, row.Resource)
	}
}
