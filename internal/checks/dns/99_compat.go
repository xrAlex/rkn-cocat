package dns

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"time"

	"rkn-cocat/internal/checks/classifier"
	"rkn-cocat/internal/checks/common"
	"rkn-cocat/internal/entity"
	reportmodel "rkn-cocat/internal/report"
)

type PhaseResult[T any] struct {
	Stats   T
	Section reportmodel.Section
}

type Service struct {
	inner *dnsService
}

type errorClassifier struct {
	inner *classifier.ErrorClassifier
}

const (
	statusOK      = common.StatusOK
	statusError   = common.StatusError
	statusBlocked = common.StatusBlocked
	statusTimeout = common.StatusTimeout
	statusEmpty   = common.StatusEmpty

	statusNXDOMAIN         = common.StatusNXDOMAIN
	statusSERVFAIL         = common.StatusSERVFAIL
	statusRefused          = common.StatusRefused
	statusValidWithDNSHint = common.StatusValidWithDNSHint
	statusNoErrorAnswer    = common.StatusNoErrorAnswer
	statusNoErrorEmptyView = common.StatusNoErrorEmptyView
	statusNoErrorEmpty     = common.StatusNoErrorEmpty

	statusAllOK   = common.StatusAllOK
	statusPartial = common.StatusPartial
	statusMixed   = common.StatusMixed
	statusValid   = common.StatusValid
)

const (
	dnsTypeA     = common.DNSTypeA
	dnsTypeCNAME = common.DNSTypeCNAME
	dnsTypeAAAA  = common.DNSTypeAAAA
)

func toCommonPhaseResult[T any](result PhaseResult[T]) common.PhaseResult[T] {
	return common.PhaseResult[T]{
		Stats:   result.Stats,
		Section: result.Section,
	}
}

func NewService(ctx context.Context, cfg entity.GlobalConfig) *Service {
	return &Service{inner: newDNSService(ctx, cfg)}
}

func newErrorClassifier(cfg entity.GlobalConfig) *errorClassifier {
	return &errorClassifier{inner: classifier.New(cfg)}
}

func (c *errorClassifier) classifyDNSTransportError(err error) (string, string) {
	return c.inner.ClassifyDNSTransportError(err)
}

func limitItems[T any](items []T, max int) []T       { return common.LimitItems(items, max) }
func cleanHostname(value string) string              { return common.CleanHostname(value) }
func uniqueStrings(items []string) []string          { return common.UniqueStrings(items) }
func containsAny(text string, markers []string) bool { return common.ContainsAny(text, markers) }
func buildDNSQuery(domain string, qType uint16) ([]byte, error) {
	return common.BuildDNSQuery(domain, qType)
}
func domainTimeout(cfg entity.GlobalConfig) time.Duration { return common.DomainTimeout(cfg) }
func dnsTimeout(cfg entity.GlobalConfig) time.Duration    { return common.DNSTimeout(cfg) }
func cleanDetail(detail string) string                    { return common.CleanDetail(detail) }
func parseDNSWireMessage(msg []byte) (entity.DNSWireMessage, error) {
	return common.ParseDNSWireMessage(msg)
}
func isTimeoutErr(err error) bool { return common.IsTimeoutErr(err) }
func newConfiguredRequest(ctx context.Context, method string, rawURL string, body io.Reader, cfg entity.GlobalConfig) (*http.Request, error) {
	return common.NewConfiguredRequest(ctx, method, rawURL, body, cfg)
}
func newHTTPTransport(cfg entity.GlobalConfig, tlsCfg *tls.Config, timeout time.Duration) *http.Transport {
	return common.NewHTTPTransport(cfg, tlsCfg, timeout)
}
func withTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return common.WithTimeout(ctx, timeout)
}
func sleepContext(ctx context.Context, d time.Duration) bool { return common.SleepContext(ctx, d) }
func takeFirst(items []string, limit int) []string           { return common.TakeFirst(items, limit) }
func extractIPs(value any) []string                          { return common.ExtractIPs(value) }
func strVal(value any) string                                { return common.StrVal(value) }
func sameSet(left []string, right []string) bool             { return common.SameSet(left, right) }

func RunEDEDiagnosticsTest(ctx context.Context, cfg entity.GlobalConfig) common.PhaseResult[entity.DNSEDEStats] {
	return toCommonPhaseResult(runDNSEDEDiagnosticsTest(ctx, cfg))
}

func RunTransportMatrixTest(ctx context.Context, cfg entity.GlobalConfig) common.PhaseResult[entity.DNSTransportStats] {
	return toCommonPhaseResult(runDNSTransportMatrixTest(ctx, cfg))
}

func (s *Service) ResolveIP(domain string) (string, bool) {
	return s.inner.resolveIP(domain)
}
