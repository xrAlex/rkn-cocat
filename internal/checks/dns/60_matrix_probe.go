package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"rkn-cocat/internal/entity"
)

func (s *dnsTransportMatrixService) collectRows(
	domains []string,
	build func(string) dnsTransportMatrixRow,
) []dnsTransportMatrixRow {
	if len(domains) == 0 || build == nil {
		return nil
	}

	workerLimit := s.cfg.MaxConcurrent
	if workerLimit <= 0 || workerLimit > len(domains) {
		workerLimit = len(domains)
	}
	if workerLimit < 1 {
		workerLimit = 1
	}

	rows := make([]dnsTransportMatrixRow, len(domains))
	sem := make(chan struct{}, workerLimit)
	var wg sync.WaitGroup

	for idx, domain := range domains {
		if s.ctx.Err() != nil {
			break
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(idx int, domain string) {
			defer wg.Done()
			defer func() {
				<-sem
			}()

			if s.ctx.Err() != nil {
				return
			}
			rows[idx] = build(domain)
		}(idx, domain)
	}

	wg.Wait()
	return rows
}

func (s *dnsTransportMatrixService) buildRow(domain string) dnsTransportMatrixRow {
	return buildDNSMatrixRow(
		domain,
		func(domain string) dnsTransportOutcome { return s.probeResolverTransport(domain, "udp") },
		func(domain string) dnsTransportOutcome { return s.probeResolverTransport(domain, "tcp") },
		s.probeDoHTransport,
		s.probeDoTTransport,
		s.evaluateRow,
	)
}

func buildDNSMatrixRow(
	domain string,
	udpProbe func(string) dnsTransportOutcome,
	tcpProbe func(string) dnsTransportOutcome,
	dohProbe func(string) dnsTransportOutcome,
	dotProbe func(string) dnsTransportOutcome,
	evaluate func(dnsTransportOutcome, dnsTransportOutcome, dnsTransportOutcome, dnsTransportOutcome) (string, bool),
) dnsTransportMatrixRow {
	row := dnsTransportMatrixRow{Domain: domain}
	if strings.TrimSpace(domain) == "" {
		return row
	}

	type probeResult struct {
		kind    string
		outcome dnsTransportOutcome
	}

	resultCh := make(chan probeResult, 4)
	var wg sync.WaitGroup

	run := func(kind string, probe func(string) dnsTransportOutcome) {
		if probe == nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			resultCh <- probeResult{kind: kind, outcome: probe(domain)}
		}()
	}

	run("udp", udpProbe)
	run("tcp", tcpProbe)
	run("doh", dohProbe)
	run("dot", dotProbe)

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for result := range resultCh {
		switch result.kind {
		case "udp":
			row.UDP = result.outcome
		case "tcp":
			row.TCP = result.outcome
		case "doh":
			row.DoH = result.outcome
		case "dot":
			row.DoT = result.outcome
		}
	}

	if evaluate != nil {
		row.Final, row.Diverged = evaluate(row.UDP, row.TCP, row.DoH, row.DoT)
	}
	return row
}

func (s *dnsTransportMatrixService) probeResolverTransport(domain string, proto string) dnsTransportOutcome {
	state := transportProbeState{}

	for _, server := range s.cfg.DNSMatrixUDPServers {
		resolver := s.newResolver(server.IP, proto)
		ctx, cancel := withTimeout(s.ctx, time.Duration(s.cfg.DNSCheckTimeout*float64(time.Second)))
		ips, err := s.dns.lookupAWithResolver(ctx, resolver, domain)
		cancel()
		if err == nil {
			if len(ips) == 0 {
				return dnsTransportOutcome{Status: statusError, Detail: "Пустой DNS ответ", Server: server.Name}
			}
			return dnsTransportOutcome{Status: statusOK, Detail: "", Server: server.Name, IPs: ips}
		}

		status, detail := s.classifier.classifyDNSTransportError(err)
		switch status {
		case statusNXDOMAIN:
			return dnsTransportOutcome{Status: statusNXDOMAIN, Detail: detail, Server: server.Name}
		}
		state.note(status, detail)
	}

	return s.finalizeOutcome(state.blocked, state.timeouts, state.lastDetail, "Серверы не ответили корректно")
}

func (s *dnsTransportMatrixService) probeDoHTransport(domain string) dnsTransportOutcome {
	state := transportProbeState{}

	for _, server := range s.cfg.DNSMatrixDoHServers {
		probe := s.dns.probeDoHServer(server.URL, []string{domain})
		res := probe.Results[domain]
		ips := extractIPs(res)
		if len(ips) > 0 {
			return dnsTransportOutcome{Status: statusOK, Server: server.Name, IPs: ips}
		}

		switch strVal(res) {
		case statusNXDOMAIN:
			return dnsTransportOutcome{Status: statusNXDOMAIN, Server: server.Name, Detail: statusNXDOMAIN}
		case statusTimeout:
			state.note(statusTimeout, "Таймаут DoH запроса")
		case statusBlocked:
			state.note(statusBlocked, "DoH endpoint недоступен/фильтруется")
		default:
			state.note(statusError, "DoH ответ некорректен")
		}
	}

	return s.finalizeOutcome(state.blocked, state.timeouts, state.lastDetail, "DoH серверы не вернули корректный ответ")
}

func (s *dnsTransportMatrixService) probeDoTTransport(domain string) dnsTransportOutcome {
	if len(s.cfg.DNSMatrixDoTServers) == 0 {
		return dnsTransportOutcome{Status: statusError, Detail: "DoT серверы не настроены"}
	}

	state := transportProbeState{}

	for _, server := range s.cfg.DNSMatrixDoTServers {
		ips, status, detail := s.lookupAWithDoT(server, domain)
		switch status {
		case statusOK:
			return dnsTransportOutcome{Status: statusOK, Server: server.Name, IPs: ips}
		case statusNXDOMAIN:
			return dnsTransportOutcome{Status: statusNXDOMAIN, Server: server.Name, Detail: detail}
		}
		state.note(status, detail)
	}

	return s.finalizeOutcome(state.blocked, state.timeouts, state.lastDetail, "DoT серверы не вернули корректный ответ")
}

func (s *dnsTransportMatrixService) finalizeOutcome(blocked int, timeouts int, lastDetail string, fallback string) dnsTransportOutcome {
	if blocked > 0 {
		return dnsTransportOutcome{Status: statusBlocked, Detail: lastDetail}
	}
	if timeouts > 0 {
		return dnsTransportOutcome{Status: statusTimeout, Detail: lastDetail}
	}
	if lastDetail == "" {
		lastDetail = fallback
	}
	return dnsTransportOutcome{Status: statusError, Detail: lastDetail}
}

func (s *dnsTransportMatrixService) newResolver(nameserver string, proto string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: dnsTimeout(s.cfg)}
			var network string
			switch proto {
			case "tcp":
				if s.cfg.UseIPv4Only {
					network = "tcp4"
				} else {
					network = "tcp"
				}
			default:
				if s.cfg.UseIPv4Only {
					network = "udp4"
				} else {
					network = "udp"
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(nameserver, "53"))
		},
	}
}

func (s *dnsTransportMatrixService) lookupAWithDoT(server entity.DoTServer, domain string) ([]string, string, string) {
	query, err := buildDNSAQuery(domain)
	if err != nil {
		return nil, statusError, "Не удалось собрать DoT запрос"
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
		status, detail := s.classifier.classifyDNSTransportError(err)
		return nil, status, detail
	}
	defer func() {
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := conn.Write(frame); err != nil {
		status, detail := s.classifier.classifyDNSTransportError(err)
		return nil, status, detail
	}

	respLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, respLenBuf); err != nil {
		status, detail := s.classifier.classifyDNSTransportError(err)
		return nil, status, detail
	}
	respLen := int(binary.BigEndian.Uint16(respLenBuf))
	if respLen <= 0 || respLen > 4096 {
		return nil, statusError, "Некорректная длина DoT ответа"
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		status, detail := s.classifier.classifyDNSTransportError(err)
		return nil, status, detail
	}

	ips, rcode, err := parseDNSAResponse(resp)
	if err != nil {
		return nil, statusError, "Не удалось распарсить DoT ответ"
	}
	if rcode == 3 {
		return nil, statusNXDOMAIN, statusNXDOMAIN
	}
	if rcode != 0 {
		return nil, statusError, fmt.Sprintf("DNS RCODE=%d", rcode)
	}
	if len(ips) == 0 {
		return nil, statusError, "Пустой DoT ответ"
	}

	return ips, statusOK, ""
}

func (s *dnsTransportMatrixService) formatCell(outcome dnsTransportOutcome) string {
	if outcome.Status == statusOK && len(outcome.IPs) > 0 {
		return "OK " + strings.Join(takeFirst(outcome.IPs, 1), ",")
	}
	if outcome.Status == "" {
		return statusError
	}
	return outcome.Status
}

func buildDNSAQuery(domain string) ([]byte, error) {
	return buildDNSQuery(domain, dnsTypeA)
}

func parseDNSAResponse(msg []byte) ([]string, int, error) {
	parsed, err := parseDNSWireMessage(msg)
	if err != nil {
		return nil, 0, err
	}

	ips := make([]string, 0, len(parsed.Answers))
	for _, record := range parsed.Answers {
		if record.Type == dnsTypeA {
			ips = append(ips, record.Data)
		}
	}
	return uniqueStrings(ips), parsed.RCode, nil
}
