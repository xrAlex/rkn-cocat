package dns

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"rkn-cocat/internal/entity"
)

func (s *dnsService) probeDoHServer(dohURL string, domains []string) entity.DNSProbeResult {
	probe := entity.DNSProbeResult{Results: make(map[string]any, len(domains))}
	timeout := dnsTimeout(s.cfg)
	client := &http.Client{
		Timeout:   timeout,
		Transport: newHTTPTransport(s.cfg, nil, timeout),
	}

	for _, domain := range domains {
		status, ips := s.resolveDoHDomain(client, dohURL, domain)
		applyDoHProbeDomainResult(&probe, domain, status, ips)
	}
	return probe
}

func applyDoHProbeDomainResult(probe *entity.DNSProbeResult, domain string, status string, ips []string) {
	if probe == nil {
		return
	}

	switch status {
	case statusOK:
		if len(ips) == 0 {
			probe.Results[domain] = statusEmpty
		} else {
			probe.Results[domain] = ips
		}
		probe.OK++
	case statusNXDOMAIN:
		probe.Results[domain] = statusNXDOMAIN
		probe.OK++
	case statusTimeout:
		probe.Results[domain] = statusTimeout
		probe.Timeout++
	case statusBlocked:
		probe.Results[domain] = statusBlocked
		probe.Blocked++
	default:
		probe.Results[domain] = statusError
		probe.Error++
	}
}

func (s *dnsService) resolveDoHDomain(client *http.Client, dohURL string, domain string) (string, []string) {
	if status, ips, ok := s.resolveDoHDomainJSON(client, dohURL, domain); ok {
		return status, ips
	}

	wire := s.dnsEDE.queryWireOverDoH(dohURL, domain, dnsTypeA)
	return mapDoHWireResult(wire)
}

func (s *dnsService) resolveDoHDomainJSON(client *http.Client, dohURL string, domain string) (string, []string, bool) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", nil, false
	}

	queryParams := u.Query()
	queryParams.Set("name", domain)
	queryParams.Set("type", "A")
	u.RawQuery = queryParams.Encode()

	req, reqErr := newConfiguredRequest(s.ctx, "GET", u.String(), nil, s.cfg)
	if reqErr != nil {
		return "", nil, false
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, doErr := client.Do(req)
	if doErr != nil {
		if isTimeoutErr(doErr) {
			return statusTimeout, nil, true
		}
		return "", nil, false
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", nil, false
	}

	var data dohJSONResponse
	if decErr := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data); decErr != nil {
		return "", nil, false
	}
	if data.Status == 3 {
		return statusNXDOMAIN, nil, true
	}

	ips := make([]string, 0, len(data.Answer))
	for _, answer := range data.Answer {
		if answer.Type == 1 {
			ips = append(ips, answer.Data)
		}
	}
	return statusOK, uniqueStrings(ips), true
}

func mapDoHWireResult(wire dnsWireResult) (string, []string) {
	switch wire.Status {
	case statusOK:
		if wire.Message.RCode == 3 {
			return statusNXDOMAIN, nil
		}
		if wire.Message.RCode != 0 {
			return statusError, nil
		}
		return statusOK, collectDNSAnswerValues(wire.Message, dnsTypeA)
	case statusTimeout:
		return statusTimeout, nil
	case statusBlocked:
		return statusBlocked, nil
	default:
		return statusError, nil
	}
}

func (s *dnsService) lookupAWithResolver(ctx context.Context, resolver *net.Resolver, domain string) ([]string, error) {
	addrs, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		ip := addr.IP
		if s.cfg.UseIPv4Only {
			if v4 := ip.To4(); v4 != nil {
				ips = append(ips, v4.String())
			}
			continue
		}
		ips = append(ips, ip.String())
	}
	return uniqueStrings(ips), nil
}

func (s *dnsService) resolveIP(domain string) (string, bool) {
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := withTimeout(s.ctx, domainTimeout(s.cfg))
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
		cancel()
		if err == nil && len(addrs) > 0 {
			if s.cfg.UseIPv4Only {
				for _, addr := range addrs {
					if v4 := addr.IP.To4(); v4 != nil {
						return v4.String(), true
					}
				}
			} else {
				return addrs[0].IP.String(), true
			}
		}
		if attempt == 0 {
			if !sleepContext(s.ctx, 200*time.Millisecond) {
				return "", false
			}
		}
	}
	return "", false
}
