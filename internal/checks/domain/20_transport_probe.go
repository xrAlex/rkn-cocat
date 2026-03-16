package domain

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"rkn-cocat/internal/checks/common"
	"rkn-cocat/internal/entity"
)

func newTLSConfigForVersion(tlsVersion string) *tls.Config {
	tlsCfg := &tls.Config{}
	switch tlsVersion {
	case "TLSv1.2":
		tlsCfg.MinVersion = tls.VersionTLS12
		tlsCfg.MaxVersion = tls.VersionTLS12
	case "TLSv1.3":
		tlsCfg.MinVersion = tls.VersionTLS13
		tlsCfg.MaxVersion = tls.VersionTLS13
	}
	return tlsCfg
}

func parseContentLength(headerValue string) int {
	clean := strings.TrimSpace(headerValue)
	if clean == "" {
		return 0
	}
	n, err := strconv.Atoi(clean)
	if err != nil {
		return 0
	}
	return n
}

func (s *transportCheckService) checkTCPTLS(domain string, tlsVersion string) (string, string, float64) {
	if s.cfg.DomainCheckRetries <= 0 {
		return common.StatusGlobalConfigErr, "Некорректная конфигурация: DomainCheckRetries должен быть >= 1", 0
	}

	results := runTransportAttempts(s.ctx, s.cfg.DomainCheckRetries, 100*time.Millisecond, func(int) transportAttemptResult {
		status, detail, _, elapsed := s.checkTCPTLSSingle(domain, tlsVersion)
		return transportAttemptResult{Status: status, Detail: detail, Elapsed: elapsed}
	})
	if len(results) == 0 {
		return common.StatusError, "Операция отменена", 0
	}

	aggregated := s.aggregateTransportResults(results)
	return aggregated.Status, aggregated.Detail, aggregated.Elapsed
}

func runTransportAttempts(
	ctx context.Context,
	retries int,
	stagger time.Duration,
	attempt func(int) transportAttemptResult,
) []transportAttemptResult {
	if retries <= 0 || attempt == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	results := make([]transportAttemptResult, retries)
	var wg sync.WaitGroup

	for i := 0; i < retries; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			if idx > 0 && stagger > 0 {
				if !common.SleepContext(ctx, time.Duration(idx)*stagger) {
					return
				}
			}

			select {
			case <-ctx.Done():
				return
			default:
			}

			results[idx] = attempt(idx)
		}(i)
	}

	wg.Wait()

	filtered := results[:0]
	for _, result := range results {
		if result.Status == "" && result.Detail == "" && result.Elapsed == 0 {
			continue
		}
		filtered = append(filtered, result)
	}
	return filtered
}

func (s *transportCheckService) checkTCPTLSSingle(domain string, tlsVersion string) (string, string, int, float64) {
	bytesRead := 0
	start := time.Now()

	if !common.Acquire(s.ctx, s.sem) {
		return common.StatusError, "Операция отменена", bytesRead, time.Since(start).Seconds()
	}
	defer common.Release(s.sem)

	timeout := common.DomainTimeout(s.cfg)
	client := common.NewNoRedirectHTTPClient(s.cfg, newTLSConfigForVersion(tlsVersion), timeout)

	req, err := common.NewConfiguredRequest(s.ctx, "GET", "https://"+domain, nil, s.cfg)
	if err != nil {
		return common.StatusGlobalConfigErr, "Некорректный URL запроса: " + common.CleanDetail(err.Error()), bytesRead, time.Since(start).Seconds()
	}

	resp, err := client.Do(req)
	if err != nil {
		status, detail, _ := s.classifier.ClassifyHTTPSConnectError(err, bytesRead)
		return status, detail, bytesRead, time.Since(start).Seconds()
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	statusCode := resp.StatusCode
	location := resp.Header.Get("Location")
	if status, detail, blocked := s.classifyTLSHTTPResponse(domain, statusCode, location); blocked {
		return status, detail, bytesRead, time.Since(start).Seconds()
	}

	if statusCode >= 300 && statusCode < 400 {
		return common.StatusOK, "", bytesRead, time.Since(start).Seconds()
	}
	elapsed := time.Since(start).Seconds()

	if statusCode == 200 {
		if blocked, inspectedBytes := s.inspectTLSBodyForBlock(resp.Body, resp.Header.Get("Content-Length")); blocked {
			return common.StatusISPPage, "Контент похож на блок-страницу провайдера", inspectedBytes, elapsed
		}
	}

	if statusCode >= 200 && statusCode < 500 {
		return common.StatusOK, "", bytesRead, elapsed
	}
	return common.StatusOK, fmt.Sprintf("HTTP %d", statusCode), bytesRead, elapsed
}

func (s *transportCheckService) inspectTLSBodyForBlock(body io.Reader, contentLengthHeader string) (bool, int) {
	contentLen := parseContentLength(contentLengthHeader)
	if contentLen <= 0 || contentLen >= s.cfg.BodyInspectLimit {
		return false, 0
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(body, int64(s.cfg.BodyInspectLimit)))
	bodyText := strings.ToLower(string(bodyBytes))
	if common.ContainsAny(bodyText, s.cfg.BodyBlockMarkers) {
		return true, len(bodyBytes)
	}
	return false, 0
}

func (s *transportCheckService) inspectHTTPBodyForBlock(body io.Reader, contentLengthHeader string) (bool, int) {
	contentLen := parseContentLength(contentLengthHeader)
	if contentLen >= s.cfg.BodyInspectLimit && contentLen > 0 {
		return false, 0
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(body, int64(s.cfg.BodyInspectLimit)))
	bodyText := strings.ToLower(string(bodyBytes))
	if common.ContainsAny(bodyText, s.cfg.BodyBlockMarkers) {
		return true, len(bodyBytes)
	}
	return false, 0
}

func (s *transportCheckService) checkHTTPInjection(domain string) (string, string) {
	cleanDomain := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://"))
	timeout := common.DomainTimeout(s.cfg)

	if !common.Acquire(s.ctx, s.sem) {
		return common.StatusError, "Операция отменена"
	}
	defer common.Release(s.sem)

	client := common.NewNoRedirectHTTPClient(s.cfg, nil, timeout)

	req, err := common.NewConfiguredRequest(s.ctx, "GET", "http://"+cleanDomain, nil, s.cfg)
	if err != nil {
		return common.StatusGlobalConfigErr, "Некорректный URL запроса: " + common.CleanDetail(err.Error())
	}

	resp, err := client.Do(req)
	if err != nil {
		status, detail, _ := s.classifier.ClassifyHTTPConnectError(err, 0)
		return status, detail
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	statusCode := resp.StatusCode
	if statusCode == 451 {
		return common.StatusBlocked, "HTTP 451 (юридическое ограничение доступа)"
	}
	if statusCode < 300 || statusCode >= 400 {
		if blocked, _ := s.inspectHTTPBodyForBlock(resp.Body, resp.Header.Get("Content-Length")); blocked {
			return common.StatusISPPage, "Контент похож на блок-страницу (HTTP)"
		}
	}
	if statusCode >= 200 && statusCode < 300 {
		return common.StatusOK, fmt.Sprintf("%d", statusCode)
	}
	if statusCode >= 300 && statusCode < 400 {
		return s.classifyHTTPRedirect(cleanDomain, statusCode, resp.Header.Get("Location"))
	}
	return common.StatusOK, fmt.Sprintf("%d", statusCode)
}

func (p *Pipeline) runTLSPhase(entry *entity.DomainEntry, tlsVersion string) {
	if entry.DNSState != dnsStateOK {
		return
	}
	status, detail, elapsed := p.checks.checkTCPTLS(entry.Domain, tlsVersion)
	if tlsVersion == "TLSv1.3" {
		entry.T13Res = entity.TLSResult{Status: status, Detail: detail, Elapsed: elapsed}
	} else {
		entry.T12Res = entity.TLSResult{Status: status, Detail: detail, Elapsed: elapsed}
	}
}

func (p *Pipeline) runHTTPPhase(entry *entity.DomainEntry) {
	if entry.DNSState != dnsStateOK {
		return
	}
	status, detail := p.checks.checkHTTPInjection(entry.Domain)
	entry.HTTPRes = entity.HTTPResult{Status: status, Detail: detail}
}
