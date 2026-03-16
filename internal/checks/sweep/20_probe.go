package sweep

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"rkn-cocat/internal/entity"
)

func (s *sizeSweepService) worker(item entity.TCPTarget) sweepRow {
	domain := extractTargetDomain(item.URL)
	targetIP := strings.TrimSpace(item.IP)

	resolvedIP := ""
	if shouldResolveSweepTarget(targetIP, s.stubIPs) {
		resolvedIP, _ = s.dns.resolveIP(domain)
		if targetIP == "" {
			targetIP = resolvedIP
		}
		if resolvedIP != "" {
			if _, fake := s.stubIPs[resolvedIP]; fake {
				return sweepRow{
					ID:         item.ID,
					Provider:   item.Provider,
					Domain:     domain,
					TargetIP:   targetIP,
					Status:     statusDNSFake,
					BreakText:  "—",
					Detail:     fmt.Sprintf("DNS подмена -> %s", resolvedIP),
					ResolvedIP: resolvedIP,
				}
			}
		}
	}

	rawStatus, detail, breakKB := s.probeBreakpoint(item.URL)
	status := s.classifySweepStatus(rawStatus, breakKB)
	breakText := formatSweepBreakText(breakKB)

	return sweepRow{
		ID:         item.ID,
		Provider:   item.Provider,
		Domain:     domain,
		TargetIP:   targetIP,
		Status:     status,
		BreakKB:    breakKB,
		BreakText:  breakText,
		Detail:     detail,
		ResolvedIP: resolvedIP,
	}
}

func shouldResolveSweepTarget(targetIP string, stubIPs map[string]struct{}) bool {
	if strings.TrimSpace(targetIP) == "" {
		return true
	}
	return len(stubIPs) > 0
}

func (s *sizeSweepService) probeBreakpoint(rawURL string) (string, string, int) {
	maxBytes := s.cfg.SweepMaxKB * 1024
	if maxBytes <= 0 {
		return statusGlobalConfigErr, "Некорректный SweepMaxKB", 0
	}

	timeout := tcp1620Timeout(s.cfg)

	if !acquire(s.ctx, s.sem) {
		return statusError, "Операция отменена", 0
	}
	defer release(s.sem)

	client := newNoRedirectHTTPClient(s.cfg, &tls.Config{}, timeout)
	req, err := newConfiguredRequest(s.ctx, "GET", rawURL, nil, s.cfg)
	if err != nil {
		return statusGlobalConfigErr, "Некорректный URL запроса: " + cleanDetail(err.Error()), 0
	}

	resp, err := client.Do(req)
	if err != nil {
		status, detail, _ := s.classifier.classifyConnectError(err, 0)
		return status, detail, 0
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	bytesRead := 0
	buf := make([]byte, 256)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			bytesRead += n
			if bytesRead >= maxBytes {
				return statusSweepPass, fmt.Sprintf("Стабильно до %dKB и более", s.cfg.SweepMaxKB), 0
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				kb := int(math.Ceil(float64(bytesRead) / 1024.0))
				return statusSweepShort, fmt.Sprintf("Ответ закончился на %dKB (данных меньше окна sweep)", kb), 0
			}

			kb := int(math.Ceil(float64(bytesRead) / 1024.0))
			if kb <= 0 {
				status, detail, _ := s.classifier.classifyReadError(rerr, bytesRead)
				if detail == "" {
					detail = cleanDetail(rerr.Error())
				}
				return status, "Сбой до получения данных: " + detail, 0
			}

			label, detail, _ := s.classifier.classifyReadError(rerr, bytesRead)
			if detail == "" {
				detail = cleanDetail(rerr.Error())
			}
			return statusSweepBreak, fmt.Sprintf("Обрыв на %dKB — %s (%s)", kb, detail, label), kb
		}
	}
}
