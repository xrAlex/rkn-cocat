package runner

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"rkn-cocat/internal/entity"
	"rkn-cocat/internal/report"
)

type runReportBuilder struct {
	cfg entity.GlobalConfig
}

type narrativeLevel int

type phaseNarrative struct {
	Label        string
	TargetLevels map[string]narrativeLevel
}

type targetNarrative struct {
	TestLevels map[string]narrativeLevel
}

type narrativeSummary struct {
	TestLevels map[string]narrativeLevel
	Targets    map[string]*targetNarrative
}

const (
	narrativeAvailable narrativeLevel = iota + 1
	narrativeSuspected
	narrativeBlocked
)

var (
	narrativeTestOrder = []string{
		"DNS EDE",
		"DNS resolve",
		"TLS 1.3",
		"TLS 1.2",
		"HTTP injection",
		"TLS SNI diff",
		"DNS matrix",
		"Size sweep",
		"OONI blocking",
	}
	narrativeDomainBlockedMarkers = []string{
		"BLOCKED",
		"ISP PAGE",
		"TLS DPI",
		"TLS MITM",
		"TLS BLOCK",
		"TCP RST",
		"TCP ABORT",
		"DPI RESET",
		"DPI ABORT",
		"DPI CLOSE",
		"DNS FAKE",
	}
	narrativeDNSEDEBlockedMarkers = []string{
		"blocked",
		"censored",
		"filtered",
		"prohibited",
	}
)

func newRunReportBuilder(cfg entity.GlobalConfig) *runReportBuilder {
	return &runReportBuilder{cfg: cfg}
}

func (b *runReportBuilder) buildNarrativeSection(results runResults) report.Section {
	phases := b.buildNarrativePhases(results)
	summary := buildNarrativeSummary(phases)
	tests := summary.activeTests()
	if len(tests) == 0 || len(summary.Targets) == 0 {
		return report.Section{
			Title: "Текстовый Итог",
			Blocks: []report.Block{
				report.Paragraph{Lines: []string{"Нет данных для текстового итога."}},
			},
		}
	}

	headers := make([]string, 0, len(tests)+1)
	headers = append(headers, "Домен / IP")
	headers = append(headers, tests...)

	return report.Section{
		Title: "Текстовый Итог",
		Blocks: []report.Block{
			report.Paragraph{Lines: []string{
				"Коды: OK = доступно; ? = под подозрением/нет данных; BLOCKED = блокировка; — = тест не запускался или цель в него не входила.",
			}},
			report.Table{
				Headers: headers,
				Rows:    summary.tableRows(tests),
			},
		},
	}
}

func (b *runReportBuilder) buildNarrativePhases(results runResults) []phaseNarrative {
	phases := make([]phaseNarrative, 0, 9)
	phases = append(phases,
		buildPhaseNarrativeFromSection("DNS EDE", results.dnsEDESection, 0, classifyDNSEDENarrativeRow),
		buildPhaseNarrativeFromSection("DNS resolve", results.resolveSection, 0, classifyResolveNarrativeRow),
		buildPhaseNarrativeFromSection("TLS 1.3", results.tls13Section, 0, classifyDomainTransportNarrativeRow),
		buildPhaseNarrativeFromSection("TLS 1.2", results.tls12Section, 0, classifyDomainTransportNarrativeRow),
		buildPhaseNarrativeFromSection("HTTP injection", results.httpSection, 0, classifyDomainTransportNarrativeRow),
		buildPhaseNarrativeFromSection("TLS SNI diff", results.sniSection, 0, classifySNINarrativeRow),
		buildPhaseNarrativeFromSection("DNS matrix", results.dnsMatrixSection, 0, classifyDNSMatrixNarrativeRow),
		b.buildSweepNarrative(results.sws),
		buildPhaseNarrativeFromSection("OONI blocking", results.ooniSection, 1, classifyOONINarrativeRow),
	)
	return phases
}

func buildPhaseNarrativeFromSection(
	label string,
	section *report.Section,
	targetCol int,
	classify func([]string) narrativeLevel,
) phaseNarrative {
	phase := newPhaseNarrative(label)
	if section == nil || classify == nil {
		return phase
	}

	for _, row := range collectSectionRows(section) {
		target := normalizeNarrativeTarget(cellValue(row, targetCol))
		if target == "" {
			continue
		}
		phase.add(target, classify(row))
	}
	return phase
}

func newPhaseNarrative(label string) phaseNarrative {
	return phaseNarrative{
		Label:        label,
		TargetLevels: make(map[string]narrativeLevel),
	}
}

func (p *phaseNarrative) add(target string, level narrativeLevel) {
	if p == nil {
		return
	}
	target = normalizeNarrativeTarget(target)
	if target == "" || level < narrativeAvailable {
		return
	}
	if level > p.TargetLevels[target] {
		p.TargetLevels[target] = level
	}
}

func (p phaseNarrative) level() narrativeLevel {
	level := narrativeLevel(0)
	for _, itemLevel := range p.TargetLevels {
		if itemLevel > level {
			level = itemLevel
		}
	}
	return level
}

func buildNarrativeSummary(phases []phaseNarrative) narrativeSummary {
	summary := narrativeSummary{
		TestLevels: make(map[string]narrativeLevel),
		Targets:    make(map[string]*targetNarrative),
	}

	for _, phase := range phases {
		if len(phase.TargetLevels) == 0 {
			continue
		}

		if phaseLevel := phase.level(); phaseLevel > summary.TestLevels[phase.Label] {
			summary.TestLevels[phase.Label] = phaseLevel
		}

		for target, level := range phase.TargetLevels {
			info := summary.Targets[target]
			if info == nil {
				info = &targetNarrative{TestLevels: make(map[string]narrativeLevel)}
				summary.Targets[target] = info
			}
			if level > info.TestLevels[phase.Label] {
				info.TestLevels[phase.Label] = level
			}
		}
	}

	return summary
}

func (s narrativeSummary) activeTests() []string {
	tests := make([]string, 0, len(s.TestLevels))
	for _, label := range narrativeTestOrder {
		if _, ok := s.TestLevels[label]; ok {
			tests = append(tests, label)
		}
	}
	return tests
}

func (s narrativeSummary) tableRows(tests []string) [][]string {
	targets := s.sortedTargets()
	rows := make([][]string, 0, len(targets))
	for _, target := range targets {
		info := s.Targets[target]
		row := make([]string, 0, len(tests)+1)
		row = append(row, target)
		for _, test := range tests {
			row = append(row, narrativeCellValue(info.levelForTest(test)))
		}
		rows = append(rows, row)
	}
	return rows
}

func (s narrativeSummary) sortedTargets() []string {
	targets := make([]string, 0, len(s.Targets))
	for target := range s.Targets {
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool {
		leftInfo := s.Targets[targets[i]]
		rightInfo := s.Targets[targets[j]]

		leftLevel := narrativeLevel(0)
		if leftInfo != nil {
			leftLevel = leftInfo.overallLevel()
		}
		rightLevel := narrativeLevel(0)
		if rightInfo != nil {
			rightLevel = rightInfo.overallLevel()
		}
		if leftLevel != rightLevel {
			return leftLevel > rightLevel
		}
		return strings.ToLower(targets[i]) < strings.ToLower(targets[j])
	})
	return targets
}

func (t *targetNarrative) overallLevel() narrativeLevel {
	if t == nil {
		return 0
	}
	level := narrativeLevel(0)
	for _, testLevel := range t.TestLevels {
		if testLevel > level {
			level = testLevel
		}
	}
	return level
}

func (t *targetNarrative) levelForTest(label string) narrativeLevel {
	if t == nil {
		return 0
	}
	return t.TestLevels[label]
}

func collectSectionRows(section *report.Section) [][]string {
	if section == nil {
		return nil
	}

	rows := make([][]string, 0, 16)
	for _, block := range section.Blocks {
		switch typed := block.(type) {
		case report.Table:
			rows = append(rows, typed.Rows...)
		case *report.Table:
			if typed != nil {
				rows = append(rows, typed.Rows...)
			}
		}
	}
	return rows
}

func classifyResolveNarrativeRow(row []string) narrativeLevel {
	status := upperCellValue(row, 1)
	switch {
	case status == "DNS OK":
		return narrativeAvailable
	case status == "DNS FAKE":
		return narrativeBlocked
	default:
		return narrativeSuspected
	}
}

func classifyDomainTransportNarrativeRow(row []string) narrativeLevel {
	status := upperCellValue(row, 1)
	switch {
	case status == "" || status == "—":
		return narrativeSuspected
	case strings.Contains(status, "OK") || strings.Contains(status, "REDIR"):
		return narrativeAvailable
	case containsAny(status, narrativeDomainBlockedMarkers):
		return narrativeBlocked
	default:
		return narrativeSuspected
	}
}

func classifySNINarrativeRow(row []string) narrativeLevel {
	verdict := upperCellValue(row, 5)
	switch {
	case verdict == "NO DIFF":
		return narrativeAvailable
	case verdict == "SNI DPI":
		return narrativeBlocked
	default:
		return narrativeSuspected
	}
}

func classifyDNSEDENarrativeRow(row []string) narrativeLevel {
	verdict := upperCellValue(row, 7)
	ede := strings.ToLower(cellValue(row, 6))
	detail := strings.ToLower(cellValue(row, 8))

	switch {
	case verdict == "VALID":
		return narrativeAvailable
	case verdict == "BLOCKED":
		return narrativeBlocked
	case containsAny(ede, narrativeDNSEDEBlockedMarkers):
		return narrativeBlocked
	case strings.Contains(detail, "ede ") && containsAny(detail, narrativeDNSEDEBlockedMarkers):
		return narrativeBlocked
	default:
		return narrativeSuspected
	}
}

func classifyDNSMatrixNarrativeRow(row []string) narrativeLevel {
	verdict := upperCellValue(row, 5)
	switch {
	case verdict == "ALL OK":
		return narrativeAvailable
	case verdict == "BLOCKED":
		return narrativeBlocked
	default:
		return narrativeSuspected
	}
}

func classifyOONINarrativeRow(row []string) narrativeLevel {
	verdict := upperCellValue(row, 2)
	switch {
	case verdict == "OK" || verdict == "TCP_REACHABLE":
		return narrativeAvailable
	case verdict == "BLOCKED":
		return narrativeBlocked
	default:
		return narrativeSuspected
	}
}

func (b *runReportBuilder) buildSweepNarrative(stats *entity.SweepStats) phaseNarrative {
	phase := newPhaseNarrative("Size sweep")
	if stats == nil {
		return phase
	}

	for _, target := range b.selectedSweepTargets() {
		phase.add(target, narrativeAvailable)
	}
	for _, target := range stats.BreakInRangeResources {
		phase.add(target, narrativeBlocked)
	}
	for _, target := range stats.BreakOutRangeResources {
		phase.add(target, narrativeSuspected)
	}
	for _, target := range stats.DNSFailResources {
		phase.add(target, narrativeSuspected)
	}
	for _, target := range stats.ErrorResources {
		phase.add(target, narrativeSuspected)
	}
	return phase
}

func (b *runReportBuilder) selectedSweepTargets() []string {
	items := b.cfg.SweepTargets
	if limit := b.cfg.SweepProbeTargets; limit > 0 && limit < len(items) {
		items = items[:limit]
	}

	labels := make([]string, 0, len(items))
	for _, item := range items {
		labels = append(labels, buildNarrativeResourceLabel(extractNarrativeTargetDomain(item.URL), item.ID, item.Provider))
	}
	return dedupStrings(labels)
}

func extractNarrativeTargetDomain(rawURL string) string {
	parsed, _ := url.Parse(strings.TrimSpace(rawURL))
	if parsed != nil {
		if host := strings.TrimSpace(parsed.Hostname()); host != "" {
			return host
		}
	}

	rawURL = strings.TrimSpace(rawURL)
	rawURL = strings.TrimPrefix(rawURL, "https://")
	rawURL = strings.TrimPrefix(rawURL, "http://")
	if idx := strings.Index(rawURL, "/"); idx >= 0 {
		rawURL = rawURL[:idx]
	}
	if idx := strings.Index(rawURL, ":"); idx >= 0 {
		rawURL = rawURL[:idx]
	}
	return strings.TrimSpace(rawURL)
}

func buildNarrativeResourceLabel(domain string, id string, provider string) string {
	base := strings.TrimSpace(domain)
	if base == "" {
		base = strings.TrimSpace(id)
	}
	if base == "" {
		base = strings.TrimSpace(provider)
	}
	if base == "" {
		base = "неизвестная цель"
	}
	id = strings.TrimSpace(id)
	if id != "" && id != base {
		return fmt.Sprintf("%s [%s]", base, id)
	}
	return base
}

func cellValue(row []string, idx int) string {
	if idx < 0 || idx >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[idx])
}

func upperCellValue(row []string, idx int) string {
	value := cellValue(row, idx)
	if value == "" {
		return ""
	}
	return strings.ToUpper(value)
}

func normalizeNarrativeTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" || target == "—" {
		return ""
	}
	if strings.HasSuffix(target, "]") {
		if idx := strings.LastIndex(target, " ["); idx > 0 {
			target = strings.TrimSpace(target[:idx])
		}
	}
	return target
}

func narrativeCellValue(level narrativeLevel) string {
	switch level {
	case narrativeAvailable:
		return "OK"
	case narrativeSuspected:
		return "?"
	case narrativeBlocked:
		return "BLOCKED"
	default:
		return "—"
	}
}

func containsAny(text string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func dedupStrings(items []string) []string {
	if len(items) == 0 {
		return items
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
