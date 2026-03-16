package dns

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"rkn-cocat/internal/entity"
)

func (s *dnsEDEService) collectProbeRows(
	domains []string,
	endpoints []dnsEDEEndpoint,
	probe func(string, dnsEDEEndpoint) dnsEDEProbeRow,
) []dnsEDEProbeRow {
	if len(domains) == 0 || len(endpoints) == 0 || probe == nil {
		return nil
	}

	jobs := make([]dnsEDEProbeJob, 0, len(domains)*len(endpoints))
	for _, domain := range domains {
		for _, endpoint := range endpoints {
			jobs = append(jobs, dnsEDEProbeJob{
				index:    len(jobs),
				domain:   domain,
				endpoint: endpoint,
			})
		}
	}

	workerLimit := s.cfg.MaxConcurrent
	if workerLimit <= 0 || workerLimit > len(jobs) {
		workerLimit = len(jobs)
	}
	if workerLimit < 1 {
		workerLimit = 1
	}

	results := make([]dnsEDEProbeRow, len(jobs))
	sem := make(chan struct{}, workerLimit)
	var wg sync.WaitGroup

	for _, job := range jobs {
		if s.ctx.Err() != nil {
			break
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(job dnsEDEProbeJob) {
			defer wg.Done()
			defer func() {
				<-sem
			}()

			if s.ctx.Err() != nil {
				return
			}
			results[job.index] = probe(job.domain, job.endpoint)
		}(job)
	}

	wg.Wait()
	return results
}

func (s *dnsEDEService) runProbe(domain string, endpoint dnsEDEEndpoint) dnsEDEProbeRow {
	aRes := endpoint.Query(domain, dnsTypeA)
	aaaaRes := endpoint.Query(domain, dnsTypeAAAA)

	aStatus := dnsSemanticStatus(aRes, dnsTypeA)
	aaaaStatus := dnsSemanticStatus(aaaaRes, dnsTypeAAAA)

	answersA := collectDNSAnswerValues(aRes.Message, dnsTypeA)
	answersAAAA := collectDNSAnswerValues(aaaaRes.Message, dnsTypeAAAA)

	ttlA := collectDNSTTL(aRes.Message, dnsTypeA)
	ttlAAAA := collectDNSTTL(aaaaRes.Message, dnsTypeAAAA)

	edeItems := mergeDNSEDE(aRes.Message.EDE, aaaaRes.Message.EDE)
	edeBlocked, edeReason := detectEDEBlocked(edeItems)
	blockHint, blockReasons := detectDNSBlockHints(s.cfg, aRes.Message, aaaaRes.Message, answersA, answersAAAA, edeItems)
	if edeReason != "" {
		blockHint = true
		blockReasons = append([]string{edeReason}, blockReasons...)
	}

	verdict := combineDNSVerdict(aStatus, aaaaStatus, blockHint)
	resource := fmt.Sprintf("%s [%s/%s]", domain, endpoint.Transport, endpoint.Name)

	details := make([]string, 0, 4)
	if detail := strings.TrimSpace(aRes.Detail); detail != "" && aStatus != statusValid {
		details = append(details, "A: "+detail)
	}
	if detail := strings.TrimSpace(aaaaRes.Detail); detail != "" && aaaaStatus != statusValid {
		details = append(details, "AAAA: "+detail)
	}
	if len(blockReasons) > 0 {
		details = append(details, strings.Join(uniqueStrings(blockReasons), "; "))
	}

	return dnsEDEProbeRow{
		Domain:     domain,
		Resolver:   endpoint.Name,
		Transport:  endpoint.Transport,
		A:          formatAnswerValues(answersA),
		AAAA:       formatAnswerValues(answersAAAA),
		TTL:        formatTTLSummary(ttlA, ttlAAAA),
		RCode:      fmt.Sprintf("A:%s | AAAA:%s", formatQueryRCODE(aRes, dnsTypeA), formatQueryRCODE(aaaaRes, dnsTypeAAAA)),
		EDE:        formatEDEItems(edeItems),
		Verdict:    verdict,
		Detail:     strings.Join(details, " | "),
		BlockHint:  blockHint,
		EDEBlocked: edeBlocked,
		Resource:   resource,
	}
}

func (s *dnsEDEService) queryWireOverUDP(nameserver string, domain string, qType uint16) dnsWireResult {
	query, err := buildDNSQuery(domain, qType)
	if err != nil {
		return dnsWireResult{Status: statusError, Detail: "Некорректный DNS запрос"}
	}

	timeout := dnsTimeout(s.cfg)
	network := "udp"
	if s.cfg.UseIPv4Only {
		network = "udp4"
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(s.ctx, network, net.JoinHostPort(strings.TrimSpace(nameserver), "53"))
	if err != nil {
		return dnsWireResult{Status: normalizeWireTransportStatus(s.classifier.classifyDNSTransportError(err)), Detail: cleanDetail(err.Error())}
	}
	defer func() {
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(query); err != nil {
		return dnsWireResult{Status: normalizeWireTransportStatus(s.classifier.classifyDNSTransportError(err)), Detail: cleanDetail(err.Error())}
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return dnsWireResult{Status: normalizeWireTransportStatus(s.classifier.classifyDNSTransportError(err)), Detail: cleanDetail(err.Error())}
	}

	message, err := parseDNSWireMessage(buf[:n])
	if err != nil {
		return dnsWireResult{Status: statusError, Detail: "Некорректный DNS ответ"}
	}
	return dnsWireResult{Status: statusOK, Message: message}
}

func (s *dnsEDEService) queryWireOverDoH(dohURL string, domain string, qType uint16) dnsWireResult {
	query, err := buildDNSQuery(domain, qType)
	if err != nil {
		return dnsWireResult{Status: statusError, Detail: "Некорректный DNS запрос"}
	}

	timeout := dnsTimeout(s.cfg)
	client := &http.Client{
		Timeout:   timeout,
		Transport: newHTTPTransport(s.cfg, nil, timeout),
	}

	req, err := newConfiguredRequest(s.ctx, "POST", dohURL, bytes.NewReader(query), s.cfg)
	if err != nil {
		return dnsWireResult{Status: statusError, Detail: "Некорректный URL DoH endpoint"}
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return dnsWireResult{Status: normalizeWireTransportStatus(s.classifier.classifyDNSTransportError(err)), Detail: cleanDetail(err.Error())}
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnavailableForLegalReasons {
			return dnsWireResult{Status: statusBlocked, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
		}
		return dnsWireResult{Status: statusError, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return dnsWireResult{Status: statusError, Detail: "Не удалось прочитать DoH ответ"}
	}

	message, err := parseDNSWireMessage(body)
	if err != nil {
		return dnsWireResult{Status: statusError, Detail: "DoH вернул не-wireformat ответ"}
	}
	return dnsWireResult{Status: statusOK, Message: message}
}

func (s *dnsEDEService) queryWireOverDoT(server entity.DoTServer, domain string, qType uint16) dnsWireResult {
	query, err := buildDNSQuery(domain, qType)
	if err != nil {
		return dnsWireResult{Status: statusError, Detail: "Некорректный DNS запрос"}
	}

	timeout := dnsTimeout(s.cfg)
	network := "tcp"
	if s.cfg.UseIPv4Only {
		network = "tcp4"
	}

	serverName := strings.TrimSpace(server.ServerName)
	if serverName == "" {
		host, _, splitErr := net.SplitHostPort(server.Address)
		if splitErr == nil {
			serverName = host
		}
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := (&tls.Dialer{
		NetDialer: &dialer,
		Config: &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		},
	}).DialContext(s.ctx, network, server.Address)
	if err != nil {
		return dnsWireResult{Status: normalizeWireTransportStatus(s.classifier.classifyDNSTransportError(err)), Detail: cleanDetail(err.Error())}
	}
	defer func() {
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := conn.Write(frame); err != nil {
		return dnsWireResult{Status: normalizeWireTransportStatus(s.classifier.classifyDNSTransportError(err)), Detail: cleanDetail(err.Error())}
	}

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return dnsWireResult{Status: normalizeWireTransportStatus(s.classifier.classifyDNSTransportError(err)), Detail: cleanDetail(err.Error())}
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf))
	if respLen <= 0 || respLen > 4096 {
		return dnsWireResult{Status: statusError, Detail: "Некорректная длина DoT ответа"}
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return dnsWireResult{Status: normalizeWireTransportStatus(s.classifier.classifyDNSTransportError(err)), Detail: cleanDetail(err.Error())}
	}

	message, err := parseDNSWireMessage(resp)
	if err != nil {
		return dnsWireResult{Status: statusError, Detail: "Некорректный DoT ответ"}
	}
	return dnsWireResult{Status: statusOK, Message: message}
}
