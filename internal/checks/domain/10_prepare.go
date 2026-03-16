package domain

import (
	"context"
	"fmt"
	"sort"

	"rkn-cocat/internal/checks/classifier"
	"rkn-cocat/internal/checks/common"
	checksdns "rkn-cocat/internal/checks/dns"
	"rkn-cocat/internal/entity"
)

func NewPipeline(ctx context.Context, cfg entity.GlobalConfig, sem chan struct{}, stubIPs map[string]struct{}) *Pipeline {
	if stubIPs == nil {
		stubIPs = map[string]struct{}{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return &Pipeline{
		ctx:     ctx,
		sem:     sem,
		stubIPs: stubIPs,
		checks:  newTransportCheckService(ctx, cfg, sem),
		dns:     checksdns.NewService(ctx, cfg),
	}
}

func PrepareEntries(_ context.Context, pipeline *Pipeline, domains []string) []entity.DomainEntry {
	if pipeline == nil {
		return nil
	}
	return pipeline.prepareEntries(domains)
}

func applyDomainFallback(entry *entity.DomainEntry, status string, detail string) {
	entry.T13Res = entity.TLSResult{Status: status, Detail: detail, Elapsed: 0}
	entry.T12Res = entity.TLSResult{Status: status, Detail: detail, Elapsed: 0}
	entry.HTTPRes = entity.HTTPResult{Status: status, Detail: detail}
}

func (p *Pipeline) prepareEntries(domains []string) []entity.DomainEntry {
	entries := make([]entity.DomainEntry, len(domains))
	_ = common.RunParallelContext(p.ctx, len(domains), func(_ context.Context, idx int) {
		entries[idx] = p.resolveDomain(domains[idx])
	})
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Domain < entries[j].Domain
	})
	return entries
}

func (p *Pipeline) resolveDomain(domainRaw string) entity.DomainEntry {
	domain := common.CleanHostname(domainRaw)

	if !common.Acquire(p.ctx, p.sem) {
		return entity.DomainEntry{
			Domain:     domain,
			DNSState:   dnsStateFail,
			T13Res:     entity.TLSResult{Status: common.StatusError, Detail: "Операция отменена", Elapsed: 0},
			T12Res:     entity.TLSResult{Status: common.StatusError, Detail: "Операция отменена", Elapsed: 0},
			HTTPRes:    entity.HTTPResult{Status: common.StatusError, Detail: "Операция отменена"},
			ResolvedIP: "",
		}
	}
	resolvedIP, ok := p.dns.ResolveIP(domain)
	common.Release(p.sem)

	entry := entity.DomainEntry{
		Domain:     domain,
		ResolvedIP: resolvedIP,
		DNSState:   dnsStateOK,
		T13Res:     entity.TLSResult{Status: "—", Detail: "", Elapsed: 0},
		T12Res:     entity.TLSResult{Status: "—", Detail: "", Elapsed: 0},
		HTTPRes:    entity.HTTPResult{Status: "—", Detail: ""},
	}

	if !ok {
		applyDomainFallback(&entry, common.StatusDNSFail, "Домен не найден")
		entry.DNSState = dnsStateFail
	} else if _, fake := p.stubIPs[resolvedIP]; fake {
		detail := fmt.Sprintf("DNS подмена -> %s", resolvedIP)
		applyDomainFallback(&entry, common.StatusDNSFake, detail)
		entry.DNSState = dnsStateFake
	}
	return entry
}

func newTransportCheckService(ctx context.Context, cfg entity.GlobalConfig, sem chan struct{}) *transportCheckService {
	if ctx == nil {
		ctx = context.Background()
	}
	return &transportCheckService{
		ctx:        ctx,
		cfg:        cfg,
		sem:        sem,
		classifier: classifier.New(cfg),
	}
}

func newSNIDiffRow(entry entity.DomainEntry) sniDiffRow {
	return sniDiffRow{
		Domain:    entry.Domain,
		IP:        entry.ResolvedIP,
		TCPStatus: "—",
		TargetSNI: "—",
		NoSNI:     "—",
		Verdict:   common.StatusSNIInconclusive,
	}
}

func newSNIDiffService(ctx context.Context, cfg entity.GlobalConfig, sem chan struct{}) *sniDiffService {
	if ctx == nil {
		ctx = context.Background()
	}
	return &sniDiffService{
		ctx:        ctx,
		cfg:        cfg,
		sem:        sem,
		classifier: classifier.New(cfg),
	}
}
