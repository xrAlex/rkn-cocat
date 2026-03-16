package sweep

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"time"

	"rkn-cocat/internal/checks/classifier"
	"rkn-cocat/internal/checks/common"
	checksdns "rkn-cocat/internal/checks/dns"
	"rkn-cocat/internal/entity"
	reportmodel "rkn-cocat/internal/report"
)

type PhaseResult[T any] struct {
	Stats   T
	Section reportmodel.Section
}

type errorClassifier struct {
	inner *classifier.ErrorClassifier
}

type dnsService struct {
	inner *checksdns.Service
}

const (
	statusError           = common.StatusError
	statusGlobalConfigErr = common.StatusGlobalConfigErr

	statusDNSFail = common.StatusDNSFail
	statusDNSFake = common.StatusDNSFake

	statusSweepPass    = common.StatusSweepPass
	statusSweepBlock   = common.StatusSweepBlock
	statusSweepOutside = common.StatusSweepOutside
	statusSweepErr     = common.StatusSweepErr
	statusSweepShort   = common.StatusSweepShort
	statusSweepBreak   = common.StatusSweepBreak
)

func toCommonPhaseResult[T any](result PhaseResult[T]) common.PhaseResult[T] {
	return common.PhaseResult[T]{
		Stats:   result.Stats,
		Section: result.Section,
	}
}

func newErrorClassifier(cfg entity.GlobalConfig) *errorClassifier {
	return &errorClassifier{inner: classifier.New(cfg)}
}

func (c *errorClassifier) classifyConnectError(err error, bytesRead int) (string, string, int) {
	return c.inner.ClassifyConnectError(err, bytesRead)
}

func (c *errorClassifier) classifyReadError(err error, bytesRead int) (string, string, int) {
	return c.inner.ClassifyReadError(err, bytesRead)
}

func newDNSService(ctx context.Context, cfg entity.GlobalConfig) *dnsService {
	return &dnsService{inner: checksdns.NewService(ctx, cfg)}
}

func (s *dnsService) resolveIP(domain string) (string, bool) {
	return s.inner.ResolveIP(domain)
}

func limitItems[T any](items []T, max int) []T { return common.LimitItems(items, max) }
func runParallelContext(ctx context.Context, count int, fn func(context.Context, int)) error {
	return common.RunParallelContext(ctx, count, fn)
}
func uniqueStrings(items []string) []string    { return common.UniqueStrings(items) }
func getGroupName(provider string) string      { return common.GetGroupName(provider) }
func extractIDNum(id string) int               { return common.ExtractIDNum(id) }
func extractTargetDomain(rawURL string) string { return common.ExtractTargetDomain(rawURL) }
func buildResourceLabel(domain string, id string, provider string) string {
	return common.BuildResourceLabel(domain, id, provider)
}
func tcp1620Timeout(cfg entity.GlobalConfig) time.Duration { return common.TCP1620Timeout(cfg) }
func acquire(ctx context.Context, sem chan struct{}) bool  { return common.Acquire(ctx, sem) }
func release(sem chan struct{})                            { common.Release(sem) }
func newNoRedirectHTTPClient(cfg entity.GlobalConfig, tlsCfg *tls.Config, timeout time.Duration) *http.Client {
	return common.NewNoRedirectHTTPClient(cfg, tlsCfg, timeout)
}
func newConfiguredRequest(ctx context.Context, method string, rawURL string, body io.Reader, cfg entity.GlobalConfig) (*http.Request, error) {
	return common.NewConfiguredRequest(ctx, method, rawURL, body, cfg)
}
func cleanDetail(detail string) string { return common.CleanDetail(detail) }

func RunSizeSweepTest(ctx context.Context, cfg entity.GlobalConfig, items []entity.TCPTarget, sem chan struct{}, stubIPs map[string]struct{}) common.PhaseResult[entity.SweepStats] {
	return toCommonPhaseResult(runSizeSweepTest(ctx, cfg, items, sem, stubIPs))
}
