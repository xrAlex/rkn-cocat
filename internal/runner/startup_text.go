package runner

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"

	"rkn-cocat/internal/entity"
	"rkn-cocat/internal/report"
)

const startupConfigLineWidth = 108

type startupConfigItem struct {
	key   string
	value string
}

func buildInitialHeader(cfg entity.GlobalConfig) report.Header {
	return report.Header{
		Title: "RKN COCAT v1.0 | DNS EDE + TLS + SNI diff + HTTP + DNS matrix + sweep + OONI",
		Lines: []string{
			fmt.Sprintf("Go: %s | OS: %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH),
		},
	}
}

func buildInitialConfigSection(cfg entity.GlobalConfig) report.Section {
	return report.Section{
		Title: "Конфигурация",
		Blocks: []report.Block{
			report.Paragraph{Lines: buildInitialConfigLines(cfg)},
		},
	}
}

func buildInitialConfigLines(cfg entity.GlobalConfig) []string {
	lines := make([]string, 0, 64)

	lines = appendStartupConfigGroup(lines, "Общие", []startupConfigItem{
		{key: "use_ipv4_only", value: strconv.FormatBool(cfg.UseIPv4Only)},
		{key: "max_concurrent", value: strconv.Itoa(cfg.MaxConcurrent)},
		{key: "timeout_sec", value: formatFloat(cfg.TimeoutSec)},
		{key: "timeout_tcp_1620_sec", value: formatFloat(cfg.TimeoutTCP1620Sec)},
		{key: "domain_check_retries", value: strconv.Itoa(cfg.DomainCheckRetries)},
		{key: "tcp_1620_check_retries", value: strconv.Itoa(cfg.TCP1620CheckRetries)},
		{key: "dpi_variance_thresh", value: formatFloat(cfg.DpiVarianceThresh)},
		{key: "tcp_block_min_kb", value: strconv.Itoa(cfg.TCPBlockMinKB)},
		{key: "tcp_block_max_kb", value: strconv.Itoa(cfg.TCPBlockMaxKB)},
		{key: "body_inspect_limit", value: strconv.Itoa(cfg.BodyInspectLimit)},
		{key: "data_read_threshold", value: strconv.Itoa(cfg.DataReadThreshold)},
	})

	lines = appendStartupConfigGroup(lines, "HTTP", []startupConfigItem{
		{key: "user_agent", value: strings.TrimSpace(cfg.UserAgent)},
		{key: "block_markers", value: formatStringList(cfg.BlockMarkers)},
		{key: "body_block_markers", value: formatStringList(cfg.BodyBlockMarkers)},
	})

	lines = appendStartupConfigGroup(lines, "Тесты", []startupConfigItem{
		{key: "sni_diff_probe_domains", value: strconv.Itoa(cfg.SNIDiffProbeDomains)},
		{key: "dns_ede_probe_domains", value: strconv.Itoa(cfg.DNSEDEProbeDomains)},
		{key: "dns_transport_domains", value: strconv.Itoa(cfg.DNSTransportDomains)},
		{key: "sweep_probe_targets", value: strconv.Itoa(cfg.SweepProbeTargets)},
		{key: "sweep_min_kb", value: strconv.Itoa(cfg.SweepMinKB)},
		{key: "sweep_max_kb", value: strconv.Itoa(cfg.SweepMaxKB)},
	})

	lines = appendStartupConfigGroup(lines, "DNS и OONI", []startupConfigItem{
		{key: "dns_check_timeout", value: formatFloat(cfg.DNSCheckTimeout)},
		{key: "dns_block_ips", value: formatStringList(cfg.DNSBlockIPs)},
		{key: "ooni_probe_cc", value: strings.TrimSpace(cfg.OONIProbeCC)},
		{key: "ooni_since_days", value: strconv.Itoa(cfg.OONISinceDays)},
		{key: "ooni_concurrency", value: strconv.Itoa(cfg.OONIConcurrency)},
		{key: "ooni_timeout_sec", value: formatFloat(cfg.OONITimeoutSec)},
		{key: "ooni_base_url", value: strings.TrimSpace(cfg.OONIBaseURL)},
		{key: "ooni_user_agent", value: strings.TrimSpace(cfg.OONIUserAgent)},
		{key: "ooni_tcp_ports", value: formatIntList(cfg.OONITCPPorts)},
	})

	lines = appendStartupConfigGroup(lines, "Загруженные наборы", []startupConfigItem{
		{key: "domains_to_check", value: strconv.Itoa(len(cfg.DomainsToCheck))},
		{key: "dns_ede_domains", value: strconv.Itoa(len(cfg.DNSEDEDomains))},
		{key: "dns_ede_local_resolvers", value: strconv.Itoa(len(cfg.DNSEDELocalResolvers))},
		{key: "dns_ede_doh_servers", value: strconv.Itoa(len(cfg.DNSEDEDoHServers))},
		{key: "dns_ede_dot_servers", value: strconv.Itoa(len(cfg.DNSEDEDoTServers))},
		{key: "dns_matrix_domains", value: strconv.Itoa(len(cfg.DNSMatrixDomains))},
		{key: "dns_matrix_udp_servers", value: strconv.Itoa(len(cfg.DNSMatrixUDPServers))},
		{key: "dns_matrix_doh_servers", value: strconv.Itoa(len(cfg.DNSMatrixDoHServers))},
		{key: "dns_matrix_dot_servers", value: strconv.Itoa(len(cfg.DNSMatrixDoTServers))},
		{key: "sweep_targets", value: strconv.Itoa(len(cfg.SweepTargets))},
		{key: "ooni_domains", value: strconv.Itoa(len(cfg.OONIDomains))},
		{key: "ooni_ips", value: strconv.Itoa(len(cfg.OONIIPs))},
	})

	return lines
}

func appendStartupConfigGroup(lines []string, title string, items []startupConfigItem) []string {
	if len(lines) > 0 {
		lines = append(lines, "")
	}
	lines = append(lines, title+":")
	for _, item := range items {
		lines = append(lines, wrapStartupConfigLine(item.key, item.value)...)
	}
	return lines
}

func wrapStartupConfigLine(key string, value string) []string {
	prefix := "  " + key + "="
	if value == "" {
		return []string{prefix}
	}

	maxValueWidth := startupConfigLineWidth - utf8.RuneCountInString(prefix)
	if maxValueWidth < 16 {
		maxValueWidth = 16
	}

	parts := wrapStartupText(value, maxValueWidth)
	lines := make([]string, 0, len(parts))
	lines = append(lines, prefix+parts[0])

	indent := strings.Repeat(" ", utf8.RuneCountInString(prefix))
	for _, part := range parts[1:] {
		lines = append(lines, indent+part)
	}
	return lines
}

func wrapStartupText(text string, width int) []string {
	clean := strings.TrimSpace(text)
	if clean == "" {
		return []string{""}
	}
	if width < 1 {
		return []string{clean}
	}

	runes := []rune(clean)
	if len(runes) <= width {
		return []string{clean}
	}

	lines := make([]string, 0, len(runes)/width+1)
	for len(runes) > width {
		cut := width
		for i := width; i > 0; i-- {
			switch runes[i-1] {
			case ' ', ',', ';':
				cut = i
				i = 0
			}
		}
		part := strings.TrimSpace(string(runes[:cut]))
		if part == "" {
			part = strings.TrimSpace(string(runes[:width]))
			cut = width
		}
		lines = append(lines, part)
		runes = []rune(strings.TrimSpace(string(runes[cut:])))
	}

	if len(runes) > 0 {
		lines = append(lines, string(runes))
	}
	return lines
}

func formatStringList(items []string) string {
	if len(items) == 0 {
		return "[]"
	}

	clean := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		clean = append(clean, item)
	}
	if len(clean) == 0 {
		return "[]"
	}
	return "[" + strings.Join(clean, ", ") + "]"
}

func formatIntList(items []int) string {
	if len(items) == 0 {
		return "[]"
	}

	values := make([]string, 0, len(items))
	for _, item := range items {
		values = append(values, strconv.Itoa(item))
	}
	return "[" + strings.Join(values, ", ") + "]"
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}
