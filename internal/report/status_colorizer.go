package report

import (
	"regexp"
	"strings"
)

const (
	statusSeverityOK    = "ok"
	statusSeverityWarn  = "warn"
	statusSeverityBlock = "block"
)

const (
	statusANSIReset  = "\x1b[0m"
	statusANSIGreen  = "\x1b[32m"
	statusANSIYellow = "\x1b[33m"
	statusANSIRed    = "\x1b[31m"
)

type statusColorizer struct{}

func newStatusColorizer() *statusColorizer {
	return &statusColorizer{}
}

var tableStatusColorizer = newStatusColorizer()

var (
	reStatusANSI       = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	reStatusTViewColor = regexp.MustCompile(`\[(?:green|yellow|red|-)\]`)

	statusHeaderContainsMarkers = []string{
		"статус", "status", "итог", "результат", "result", "код", "code",
		"dns", "tls", "http", "break", "sweep", "ooni",
	}

	statusHeaderExactMarkers = map[string]struct{}{
		"a":       {},
		"aaaa":    {},
		"ede":     {},
		"rcode":   {},
		"verdict": {},
		"udp53":   {},
		"tcp53":   {},
		"doh":     {},
		"dot":     {},
	}

	statusSeverityOKMarkers = []string{
		"OK",
		"ALL OK",
		"SWEEP PASS",
		"DNS OK",
		"NO DIFF",
		"REDIR",
		"VALID",
		"NOERROR+ANSWER",
		"TCP_REACHABLE",
		" OK",
	}

	statusSeverityWarnMarkers = []string{
		"TIMEOUT",
		"MIXED",
		"PARTIAL",
		"DNS FAIL",
		"SNI INCONCLUSIVE",
		"SWEEP OUTSIDE",
		"SWEEP ERR",
		"SWEEP SHORT",
		"SWEEP BREAK",
		"CONN ERR",
		"CONN FAIL",
		"NET UNREACH",
		"HOST UNREACH",
		"NO_DATA",
		"UNKNOWN",
		"TCP_FAIL",
		"GLOBALCONFIG ERR",
		"NXDOMAIN",
		"SERVFAIL",
		"REFUSED",
		"TLS ERR",
		"SSL CERT",
		"SSL INT",
		"SSL ERR",
		"TCP RST",
		"TCP ABORT",
		"DPI RESET",
		"DPI ABORT",
		"DPI PIPE",
		"DPI CLOSE",
		"DPI TRUNC",
		"BROKEN PIPE",
		"PEER CLOSE",
		"INCOMPLETE",
		"READ ERR",
		"NOERROR EMPTY",
		"NOERROR_EMPTY",
		"EMPTY",
		"NOERROR/EMPTY",
		"FORMERR",
		"NOTIMP",
		"YXDOMAIN",
		"YXRRSET",
		"NXRRSET",
		"NOTAUTH",
		"NOTZONE",
		"RCODE=",
	}

	statusSeverityBlockMarkers = []string{
		"BLOCKED",
		"ISP PAGE",
		"TCP16-20",
		"DNS FAKE",
		"SWEEP BLOCK",
		"SNI DPI",
		"TLS BLOCK",
		"TLS DPI",
		"TLS MITM",
		"TCP FAIL",
		"VALID + DNS BLOCK HINT",
	}

	statusSeverityOKTextMarkers = []string{
		"доступен",
		"успеш",
	}

	statusSeverityWarnTextMarkers = []string{
		"возможно",
		"недоступ",
		"таймаут",
		"сбой",
		"ошиб",
		"нестабил",
		"подозр",
	}

	statusSeverityBlockTextMarkers = []string{
		"заблок",
		"блокиров",
		"ограничение доступа",
		"dns подмен",
		"подмена",
		"blocked",
		"censored",
		"filtered",
		"prohibited",
		"forbidden",
		"restricted",
	}

	statusSeverityExact = map[string]string{
		"OK":                     statusSeverityOK,
		"ALL OK":                 statusSeverityOK,
		"SWEEP PASS":             statusSeverityOK,
		"DNS OK":                 statusSeverityOK,
		"NO DIFF":                statusSeverityOK,
		"REDIR":                  statusSeverityOK,
		"VALID":                  statusSeverityOK,
		"NOERROR+ANSWER":         statusSeverityOK,
		"TCP_REACHABLE":          statusSeverityOK,
		"BLOCKED":                statusSeverityBlock,
		"ISP PAGE":               statusSeverityBlock,
		"TCP16-20":               statusSeverityBlock,
		"DNS FAKE":               statusSeverityBlock,
		"SWEEP BLOCK":            statusSeverityBlock,
		"SNI DPI":                statusSeverityBlock,
		"TLS BLOCK":              statusSeverityBlock,
		"TLS DPI":                statusSeverityBlock,
		"TLS MITM":               statusSeverityBlock,
		"TCP FAIL":               statusSeverityBlock,
		"VALID + DNS BLOCK HINT": statusSeverityBlock,
		"TIMEOUT":                statusSeverityWarn,
		"MIXED":                  statusSeverityWarn,
		"PARTIAL":                statusSeverityWarn,
		"DNS FAIL":               statusSeverityWarn,
		"SNI INCONCLUSIVE":       statusSeverityWarn,
		"SWEEP OUTSIDE":          statusSeverityWarn,
		"SWEEP ERR":              statusSeverityWarn,
		"SWEEP SHORT":            statusSeverityWarn,
		"SWEEP BREAK":            statusSeverityWarn,
		"CONN ERR":               statusSeverityWarn,
		"CONN FAIL":              statusSeverityWarn,
		"NET UNREACH":            statusSeverityWarn,
		"HOST UNREACH":           statusSeverityWarn,
		"NO_DATA":                statusSeverityWarn,
		"UNKNOWN":                statusSeverityWarn,
		"TCP_FAIL":               statusSeverityWarn,
		"ERR":                    statusSeverityWarn,
		"ERROR":                  statusSeverityWarn,
		"GLOBALCONFIG ERR":       statusSeverityWarn,
		"NXDOMAIN":               statusSeverityWarn,
		"SERVFAIL":               statusSeverityWarn,
		"REFUSED":                statusSeverityWarn,
		"TLS ERR":                statusSeverityWarn,
		"SSL CERT":               statusSeverityWarn,
		"SSL INT":                statusSeverityWarn,
		"SSL ERR":                statusSeverityWarn,
		"TCP RST":                statusSeverityWarn,
		"TCP ABORT":              statusSeverityWarn,
		"DPI RESET":              statusSeverityWarn,
		"DPI ABORT":              statusSeverityWarn,
		"DPI PIPE":               statusSeverityWarn,
		"DPI CLOSE":              statusSeverityWarn,
		"DPI TRUNC":              statusSeverityWarn,
		"BROKEN PIPE":            statusSeverityWarn,
		"PEER CLOSE":             statusSeverityWarn,
		"INCOMPLETE":             statusSeverityWarn,
		"READ ERR":               statusSeverityWarn,
		"NOERROR EMPTY":          statusSeverityWarn,
		"NOERROR_EMPTY":          statusSeverityWarn,
		"EMPTY":                  statusSeverityWarn,
	}
)

func (c *statusColorizer) colorizeCell(writer *Writer, header string, value string) string {
	if writer == nil || !writer.UseColor() {
		return value
	}

	severity := c.classifySeverity(header, value)
	if writer.UseTView() {
		switch severity {
		case statusSeverityOK:
			return "[green]" + value + "[-]"
		case statusSeverityWarn:
			return "[yellow]" + value + "[-]"
		case statusSeverityBlock:
			return "[red]" + value + "[-]"
		default:
			return value
		}
	}

	switch severity {
	case statusSeverityOK:
		return statusANSIGreen + value + statusANSIReset
	case statusSeverityWarn:
		return statusANSIYellow + value + statusANSIReset
	case statusSeverityBlock:
		return statusANSIRed + value + statusANSIReset
	default:
		return value
	}
}

func (c *statusColorizer) classifySeverity(header string, value string) string {
	raw := strings.TrimSpace(c.stripColorTags(value))
	if raw == "" || raw == "—" {
		return ""
	}
	if !c.isStatusColumnHeader(header) {
		return ""
	}

	upper := strings.ToUpper(raw)
	lower := strings.ToLower(raw)
	if severity, ok := statusSeverityExact[upper]; ok {
		return severity
	}

	if containsAny(lower, statusSeverityBlockTextMarkers) {
		return statusSeverityBlock
	}
	if containsAny(lower, statusSeverityWarnTextMarkers) {
		return statusSeverityWarn
	}
	if containsAny(lower, statusSeverityOKTextMarkers) {
		return statusSeverityOK
	}

	if containsAny(upper, statusSeverityBlockMarkers) {
		return statusSeverityBlock
	}
	if containsAny(upper, statusSeverityWarnMarkers) {
		return statusSeverityWarn
	}
	if containsAny(upper, statusSeverityOKMarkers) {
		return statusSeverityOK
	}

	if strings.Contains(raw, "√") || strings.HasPrefix(lower, "ok") || lower == "ок" || strings.HasPrefix(lower, "ок ") {
		return statusSeverityOK
	}
	if strings.Contains(raw, "×") {
		return statusSeverityBlock
	}
	if strings.Contains(raw, "!") || strings.Contains(raw, "≈") || strings.Contains(raw, "?") {
		return statusSeverityWarn
	}
	return ""
}

func (c *statusColorizer) isStatusColumnHeader(header string) bool {
	normalized := strings.ToLower(strings.TrimSpace(header))
	if normalized == "" {
		return false
	}
	if _, ok := statusHeaderExactMarkers[normalized]; ok {
		return true
	}
	return containsAny(normalized, statusHeaderContainsMarkers)
}

func (c *statusColorizer) stripColorTags(text string) string {
	if text == "" {
		return text
	}
	text = reStatusANSI.ReplaceAllString(text, "")
	return reStatusTViewColor.ReplaceAllString(text, "")
}
