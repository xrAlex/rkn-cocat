package domain

import (
	"crypto/tls"
	"net"
	"strings"
	"time"

	"rkn-cocat/internal/checks/common"
	"rkn-cocat/internal/entity"
)

func (s *sniDiffService) worker(entry entity.DomainEntry) sniDiffRow {
	row := newSNIDiffRow(entry)

	if s.applyPrecheckFailure(&row, entry) {
		return row
	}

	tcpStatus, tcpDetail, tcpElapsed := s.probeTCPConnect443(entry.ResolvedIP)
	row.TCPStatus = s.formatProbeStatus(tcpStatus, tcpElapsed)
	if !s.isStatusOK(tcpStatus) {
		row.Verdict = common.StatusTCPFail
		row.Detail = "TCP: " + s.fallbackText(tcpDetail, tcpStatus)
		return row
	}

	targetStatus, targetDetail, targetElapsed := s.probeTLSHandshakeByIP(entry.ResolvedIP, entry.Domain)
	row.TargetSNI = s.formatProbeStatus(targetStatus, targetElapsed)
	row.TargetDetail = s.fallbackText(targetDetail, targetStatus)

	if s.isStatusOK(targetStatus) {
		row.Verdict = common.StatusNoDiff
		row.Detail = "TLS с target SNI проходит"
		return row
	}

	noSNIStatus, noSNIDetail, noSNIElapsed := s.probeTLSHandshakeByIP(entry.ResolvedIP, "")
	row.NoSNI = s.formatProbeStatus(noSNIStatus, noSNIElapsed)
	row.NoSNIDetail = s.fallbackText(noSNIDetail, noSNIStatus)
	row.Verdict = s.evaluateVerdict(tcpStatus, targetStatus, noSNIStatus)
	row.Detail = formatSNIVerdictDetail(row.Verdict, entry.Domain, row.TargetDetail, row.NoSNIDetail)

	return row
}

func (s *sniDiffService) probeTCPConnect443(ip string) (string, string, float64) {
	start := time.Now()

	if !common.Acquire(s.ctx, s.sem) {
		return common.StatusError, "Операция отменена", time.Since(start).Seconds()
	}
	defer common.Release(s.sem)

	timeout := common.DomainTimeout(s.cfg)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(s.ctx, s.selectTCPNetwork(ip), net.JoinHostPort(ip, "443"))
	if err != nil {
		status, detail, _ := s.classifier.ClassifyConnectError(err, 0)
		return status, detail, time.Since(start).Seconds()
	}
	_ = conn.Close()
	return common.StatusOK, "", time.Since(start).Seconds()
}

func (s *sniDiffService) probeTLSHandshakeByIP(ip string, sni string) (string, string, float64) {
	start := time.Now()

	if !common.Acquire(s.ctx, s.sem) {
		return common.StatusError, "Операция отменена", time.Since(start).Seconds()
	}
	defer common.Release(s.sem)

	timeout := common.DomainTimeout(s.cfg)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := (&tls.Dialer{
		NetDialer: &dialer,
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Диагностика канала, проверка сертификата здесь намеренно отключена.
			ServerName:         strings.TrimSpace(sni),
			MinVersion:         tls.VersionTLS12,
		},
	}).DialContext(s.ctx, s.selectTCPNetwork(ip), net.JoinHostPort(ip, "443"))
	if err != nil {
		status, detail, _ := s.classifier.ClassifyTLSHandshakeError(err, 0)
		return status, detail, time.Since(start).Seconds()
	}
	defer func() {
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return common.StatusOK, "", time.Since(start).Seconds()
}
