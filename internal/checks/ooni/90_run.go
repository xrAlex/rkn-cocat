package ooni

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"

	"rkn-cocat/internal/entity"
)

func runOONIBlockingTest(ctx context.Context, cfg entity.GlobalConfig, progress progressFunc) PhaseResult[entity.OONIStats] {
	if ctx == nil {
		ctx = context.Background()
	}

	effectiveSinceDays := ooniNormalizedSinceDays(cfg.OONISinceDays)
	section := newOONISection(cfg, effectiveSinceDays)

	domains := uniqueStrings(cfg.OONIDomains)
	ips := uniqueStrings(cfg.OONIIPs)
	if len(domains) == 0 && len(ips) == 0 {
		appendOONIEmptyTargets(&section)
		return PhaseResult[entity.OONIStats]{Section: section}
	}

	client := &http.Client{Timeout: secondsToDuration(cfg.OONITimeoutSec)}
	workerCount := cfg.OONIConcurrency
	if cfg.MaxConcurrent > 0 && workerCount > cfg.MaxConcurrent {
		workerCount = cfg.MaxConcurrent
	}
	if workerCount <= 0 {
		workerCount = 1
	}

	ooniCfg := entity.OONIRuntimeConfig{
		ProbeCC:   cfg.OONIProbeCC,
		SinceDays: effectiveSinceDays,
		BaseURL:   cfg.OONIBaseURL,
		UserAgent: cfg.OONIUserAgent,
		TCPPorts:  cfg.OONITCPPorts,
	}
	service := newOONIService(ctx, client, ooniCfg)

	jobs := make(chan ooniJob)
	allResults := make([]entity.OONIResult, 0, len(domains)+len(ips))
	var resultsMu sync.Mutex
	var completed atomic.Int32
	totalTargets := len(domains) + len(ips)

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}

					var result entity.OONIResult
					if job.TargetType == ooniTargetDomain {
						result = service.checkDomain(job.Target)
					} else {
						result = service.checkIP(job.Target)
					}
					if ctx.Err() != nil {
						return
					}

					resultsMu.Lock()
					allResults = append(allResults, result)
					resultsMu.Unlock()

					if progress != nil {
						done := int(completed.Add(1))
						progress(done, totalTargets, job.TargetType+":"+job.Target)
					}
				}
			}
		}()
	}

	for _, domain := range domains {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return PhaseResult[entity.OONIStats]{Section: section}
		case jobs <- ooniJob{Target: domain, TargetType: ooniTargetDomain}:
		}
	}
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return PhaseResult[entity.OONIStats]{Section: section}
		case jobs <- ooniJob{Target: ip, TargetType: ooniTargetIP}:
		}
	}

	close(jobs)
	wg.Wait()

	sort.Slice(allResults, func(i, j int) bool {
		if allResults[i].TargetType != allResults[j].TargetType {
			return allResults[i].TargetType < allResults[j].TargetType
		}
		return allResults[i].Target < allResults[j].Target
	})

	stats, rows := aggregateOONIResults(allResults)
	appendOONIResultsTable(&section, rows)

	return PhaseResult[entity.OONIStats]{
		Stats:   stats,
		Section: section,
	}
}
