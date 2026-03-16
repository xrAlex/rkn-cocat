package dns

import (
	"context"
	"sort"
	"strings"

	"rkn-cocat/internal/entity"
)

func newDNSService(ctx context.Context, cfg entity.GlobalConfig) *dnsService {
	if ctx == nil {
		ctx = context.Background()
	}
	return &dnsService{
		ctx:    ctx,
		cfg:    cfg,
		dnsEDE: newDNSEDEService(ctx, cfg),
	}
}

func newDNSEDEService(ctx context.Context, cfg entity.GlobalConfig) *dnsEDEService {
	if ctx == nil {
		ctx = context.Background()
	}
	return &dnsEDEService{
		ctx:        ctx,
		cfg:        cfg,
		classifier: newErrorClassifier(cfg),
	}
}

func newDNSTransportMatrixService(ctx context.Context, cfg entity.GlobalConfig) *dnsTransportMatrixService {
	if ctx == nil {
		ctx = context.Background()
	}
	return &dnsTransportMatrixService{
		ctx:        ctx,
		cfg:        cfg,
		dns:        newDNSService(ctx, cfg),
		classifier: newErrorClassifier(cfg),
	}
}

func (s *dnsEDEService) prepareDomains() []string {
	domainsRaw := limitItems(s.cfg.DNSEDEDomains, s.cfg.DNSEDEProbeDomains)
	domains := make([]string, 0, len(domainsRaw))
	for _, item := range domainsRaw {
		domain := cleanHostname(item)
		if domain == "" {
			continue
		}
		domains = append(domains, domain)
	}
	domains = uniqueStrings(domains)
	sort.Strings(domains)
	return domains
}

func (s *dnsEDEService) buildEndpoints() []dnsEDEEndpoint {
	total := len(s.cfg.DNSEDELocalResolvers) + len(s.cfg.DNSEDEDoHServers) + len(s.cfg.DNSEDEDoTServers)
	endpoints := make([]dnsEDEEndpoint, 0, total)

	for _, server := range s.cfg.DNSEDELocalResolvers {
		resolver := server
		endpoints = append(endpoints, dnsEDEEndpoint{
			Name:      strings.TrimSpace(resolver.Name),
			Transport: "LOCAL UDP53",
			Query: func(domain string, qType uint16) dnsWireResult {
				return s.queryWireOverUDP(resolver.IP, domain, qType)
			},
		})
	}

	for _, server := range s.cfg.DNSEDEDoHServers {
		resolver := server
		endpoints = append(endpoints, dnsEDEEndpoint{
			Name:      strings.TrimSpace(resolver.Name),
			Transport: "DoH",
			Query: func(domain string, qType uint16) dnsWireResult {
				return s.queryWireOverDoH(resolver.URL, domain, qType)
			},
		})
	}

	for _, server := range s.cfg.DNSEDEDoTServers {
		resolver := server
		endpoints = append(endpoints, dnsEDEEndpoint{
			Name:      strings.TrimSpace(resolver.Name),
			Transport: "DoT",
			Query: func(domain string, qType uint16) dnsWireResult {
				return s.queryWireOverDoT(resolver, domain, qType)
			},
		})
	}

	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Transport == endpoints[j].Transport {
			return endpoints[i].Name < endpoints[j].Name
		}
		return endpoints[i].Transport < endpoints[j].Transport
	})
	return endpoints
}

func (s *dnsTransportMatrixService) prepareDomains() []string {
	return limitItems(s.cfg.DNSMatrixDomains, s.cfg.DNSTransportDomains)
}
