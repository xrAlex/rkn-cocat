package ooni

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"rkn-cocat/internal/entity"
)

func (s *ooniService) checkDomain(domain string) entity.OONIResult {
	result := entity.OONIResult{Target: domain, TargetType: ooniTargetDomain, TestName: ooniTestWeb}

	brief, err := s.latestMeasurementWithFallback(
		s.webMeasurementQuery(domain, true),
		s.webMeasurementQuery(domain, false),
	)
	if err != nil {
		result.Verdict = ooniVerdictUnknown
		result.Reason = "API error: " + err.Error()
		return result
	}
	if brief == nil {
		result.Verdict = ooniVerdictNoData
		result.Reason = fmt.Sprintf("no %s %s measurements found", s.cfg.ProbeCC, ooniTestWeb)
		return result
	}

	ooniApplyMeasurementMeta(&result, brief)
	result.MeasurementURL = ooniMeasurementFetchURL(s.cfg.BaseURL, brief)
	result.Verdict, result.Reason = s.interpretDomainMeasurement(brief)
	ooniApplyMeasurementNotes(&result, brief)
	return result
}

func (s *ooniService) checkIP(ip string) entity.OONIResult {
	result := entity.OONIResult{Target: ip, TargetType: ooniTargetIP, TestName: ooniTestTCP}

	parsedIP := net.ParseIP(ooniStripIPv6Brackets(ip))
	if parsedIP == nil {
		result.Verdict = ooniVerdictUnknown
		result.Reason = "invalid IP"
		return result
	}

	portResults := s.checkIPPorts(ip)

	allNoData := true
	anyOK := false
	anyMeasuredFailure := false
	for _, pr := range portResults {
		if pr.Failure != "no data" {
			allNoData = false
		}
		if pr.OK {
			anyOK = true
			continue
		}
		if pr.Failure != "no data" {
			anyMeasuredFailure = true
		}
	}
	if allNoData {
		result.Verdict = ooniVerdictNoData
		result.Reason = "no tcp_connect measurements found in public OONI API"
		return result
	}
	if anyOK {
		result.Verdict = ooniVerdictTCPReach
		result.Reason = fmt.Sprintf("tcp_connect results: %s", ooniTCPSummary(portResults))
		applyOONIPortMeta(&result, portResults)
		if anyMeasuredFailure {
			result.Notes = "partial tcp_connect reachability; some ports failed or have no data"
		}
		return result
	}

	result.Verdict = ooniVerdictTCPFail
	applyOONIPortMeta(&result, portResults)
	result.Reason = fmt.Sprintf("tcp_connect results: %s", ooniTCPSummary(portResults))
	result.Notes = "tcp_connect shows reachability only; failures may be censorship OR outages/firewalls"
	return result
}

func (s *ooniService) checkIPPorts(ip string) []entity.OONIPortResult {
	if len(s.cfg.TCPPorts) == 0 {
		return nil
	}

	portResults := make([]entity.OONIPortResult, len(s.cfg.TCPPorts))
	var wg sync.WaitGroup

	for idx, port := range s.cfg.TCPPorts {
		wg.Add(1)
		go func(idx int, port int) {
			defer wg.Done()
			portResults[idx] = s.checkIPPort(ip, port)
		}(idx, port)
	}

	wg.Wait()
	return portResults
}

func (s *ooniService) checkIPPort(ip string, port int) entity.OONIPortResult {
	endpoint := ooniFormatEndpoint(ip, port)
	brief := s.latestMeasurementBestEffort(
		s.tcpMeasurementQuery(endpoint, true),
		s.tcpMeasurementQuery(endpoint, false),
	)
	if brief == nil {
		return entity.OONIPortResult{Port: port, OK: false, Failure: "no data"}
	}

	raw, rawErr := s.fetchMeasurementBody(brief)
	if rawErr != nil {
		return entity.OONIPortResult{
			Port:    port,
			OK:      false,
			Failure: "raw fetch failed: " + rawErr.Error(),
		}
	}

	ok, failure := ooniInterpretTCPConnect(raw, ip, port)
	return entity.OONIPortResult{
		Port:    port,
		OK:      ok,
		Failure: failure,
		When:    ooniNormalizeTime(brief.StartTime),
		URL:     ooniMeasurementFetchURL(s.cfg.BaseURL, brief),
		Report:  brief.ReportID,
	}
}

func applyOONIPortMeta(result *entity.OONIResult, portResults []entity.OONIPortResult) {
	if result == nil {
		return
	}
	result.When = ooniBestWhen(portResults)
	result.MeasurementURL = ooniBestURL(portResults)
	result.ReportID = ooniBestReport(portResults)
}

func (s *ooniService) interpretDomainMeasurement(brief *ooniMeasurementRow) (string, string) {
	if brief == nil {
		return ooniVerdictNoData, "no measurement summary"
	}

	if brief.Confirmed {
		if blockingType := ooniBlockingTypeFromScores(brief); blockingType != "" {
			return ooniVerdictBlocked, ooniReasonFromBlockingType(blockingType, "scores")
		}
		return ooniVerdictBlocked, "confirmed=true"
	}

	if blockingType := ooniBlockingTypeFromScores(brief); blockingType != "" {
		return ooniVerdictBlocked, ooniReasonFromBlockingType(blockingType, "scores")
	}

	if brief.Anomaly || brief.Failure {
		raw, err := s.fetchMeasurementBody(brief)
		if err == nil {
			verdict, reason := ooniInterpretWebConnectivity(raw)
			if verdict != ooniVerdictUnknown || reason != "" {
				return verdict, reason
			}
		}
	}

	return ooniInterpretWebSummary(brief)
}

func ooniInterpretWebSummary(brief *ooniMeasurementRow) (string, string) {
	if brief == nil {
		return ooniVerdictNoData, "no measurement summary"
	}
	switch {
	case brief.Confirmed:
		return ooniVerdictBlocked, "confirmed=true"
	case brief.Anomaly:
		return ooniVerdictUnknown, "anomaly=true (possible blocking)"
	case brief.Failure:
		return ooniVerdictUnknown, "failure=true"
	default:
		return ooniVerdictOK, "latest measurement reports no anomaly"
	}
}

func ooniApplyMeasurementMeta(result *entity.OONIResult, brief *ooniMeasurementRow) {
	result.MeasurementURL = ooniMeasurementFetchURL("", brief)
	result.ReportID = brief.ReportID
	result.When = ooniNormalizeTime(brief.StartTime)
}

func ooniApplyMeasurementNotes(result *entity.OONIResult, brief *ooniMeasurementRow) {
	if brief.Confirmed {
		result.Notes = "confirmed=true"
	} else if brief.Anomaly {
		result.Notes = "anomaly=true"
	}
}

func ooniBlockingTypeFromScores(brief *ooniMeasurementRow) string {
	if brief == nil {
		return ""
	}

	scores, _ := brief.Scores.(map[string]any)
	if scores == nil {
		return ""
	}
	analysis, _ := scores["analysis"].(map[string]any)
	if analysis == nil {
		return ""
	}
	blockingType, _ := analysis["blocking_type"].(string)
	return strings.TrimSpace(blockingType)
}

func ooniReasonFromBlockingType(blockingType string, source string) string {
	blockingType = strings.TrimSpace(blockingType)
	if blockingType == "" {
		return ""
	}
	if strings.TrimSpace(source) == "" {
		return fmt.Sprintf("blocking_type=%q", blockingType)
	}
	return fmt.Sprintf("%s blocking_type=%q", source, blockingType)
}

func ooniInterpretWebConnectivity(raw map[string]any) (string, string) {
	testKeys, _ := raw["test_keys"].(map[string]any)
	if testKeys == nil {
		return ooniVerdictUnknown, "missing test_keys"
	}
	accessible, hasAccessible := testKeys["accessible"].(bool)
	blocking := testKeys["blocking"]

	switch value := blocking.(type) {
	case string:
		if hasAccessible && accessible {
			return ooniVerdictBlocked, fmt.Sprintf("blocking=%q but accessible=true", value)
		}
		return ooniVerdictBlocked, fmt.Sprintf("blocking=%q", value)
	case bool:
		if !value {
			if hasAccessible && accessible {
				return ooniVerdictOK, "blocking=false, accessible=true"
			}
			if hasAccessible && !accessible {
				return ooniVerdictUnknown, "blocking=false, accessible=false (site down? server-side block? unclear)"
			}
			return ooniVerdictUnknown, "blocking=false (accessible=null)"
		}
		return ooniVerdictUnknown, "blocking=true (unexpected)"
	case nil:
		return ooniVerdictUnknown, "blocking=null"
	default:
		return ooniVerdictUnknown, fmt.Sprintf("blocking has unexpected type %T", value)
	}
}

func ooniInterpretTCPConnect(raw map[string]any, ip string, port int) (bool, string) {
	testKeys, _ := raw["test_keys"].(map[string]any)
	if testKeys == nil {
		return false, "missing test_keys"
	}

	if conn, ok := testKeys["connection"].(string); ok {
		if conn == "success" {
			return true, ""
		}
		return false, conn
	}

	rawEntries, ok := testKeys["tcp_connect"].([]any)
	if !ok {
		return false, "unknown tcp_connect format"
	}

	wantIP := ooniStripIPv6Brackets(ip)
	for _, item := range rawEntries {
		entry, _ := item.(map[string]any)
		if entry == nil {
			continue
		}
		entryIP, _ := entry["ip"].(string)
		entryPort, hasPort := ooniAsInt(entry["port"])
		if ooniStripIPv6Brackets(entryIP) != wantIP || !hasPort || entryPort != port {
			continue
		}

		status, _ := entry["status"].(map[string]any)
		if status == nil {
			continue
		}
		if success, ok := status["success"].(bool); ok && success {
			return true, ""
		}
		if failure, ok := status["failure"].(string); ok && strings.TrimSpace(failure) != "" {
			return false, failure
		}
		return false, "connection failed"
	}
	return false, "no matching tcp_connect entry"
}

func ooniAsInt(value any) (int, bool) {
	switch typedValue := value.(type) {
	case float64:
		return int(typedValue), true
	case int:
		return typedValue, true
	default:
		return 0, false
	}
}

func ooniBestWhen(results []entity.OONIPortResult) string {
	for _, result := range results {
		if result.When != "" {
			return result.When
		}
	}
	return ""
}

func ooniBestURL(results []entity.OONIPortResult) string {
	for _, result := range results {
		if result.URL != "" {
			return result.URL
		}
	}
	return ""
}

func ooniBestReport(results []entity.OONIPortResult) string {
	for _, result := range results {
		if result.Report != "" {
			return result.Report
		}
	}
	return ""
}

func ooniTCPSummary(results []entity.OONIPortResult) string {
	parts := make([]string, 0, len(results))
	for _, result := range results {
		switch {
		case result.Failure == "no data":
			parts = append(parts, fmt.Sprintf("%d=no_data", result.Port))
		case result.OK:
			parts = append(parts, fmt.Sprintf("%d=success", result.Port))
		default:
			parts = append(parts, fmt.Sprintf("%d=fail(%s)", result.Port, result.Failure))
		}
	}
	return strings.Join(parts, ", ")
}
