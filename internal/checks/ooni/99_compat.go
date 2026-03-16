package ooni

import (
	"context"
	"time"

	"rkn-cocat/internal/checks/common"
	"rkn-cocat/internal/entity"
	reportmodel "rkn-cocat/internal/report"
)

type PhaseResult[T any] struct {
	Stats   T
	Section reportmodel.Section
}

const (
	statusOK               = common.StatusOK
	statusBlocked          = common.StatusBlocked
	statusNoData           = common.StatusNoData
	statusUnknown          = common.StatusUnknown
	statusOONITCPFail      = common.StatusOONITCPFail
	statusOONITCPReachable = common.StatusOONITCPReachable
)

func toCommonPhaseResult[T any](result PhaseResult[T]) common.PhaseResult[T] {
	return common.PhaseResult[T]{
		Stats:   result.Stats,
		Section: result.Section,
	}
}

func uniqueStrings(items []string) []string           { return common.UniqueStrings(items) }
func secondsToDuration(seconds float64) time.Duration { return common.SecondsToDuration(seconds) }
func buildResourceLabel(domain string, id string, provider string) string {
	return common.BuildResourceLabel(domain, id, provider)
}

func RunBlockingTest(ctx context.Context, cfg entity.GlobalConfig, progress func(int, int, string)) common.PhaseResult[entity.OONIStats] {
	return toCommonPhaseResult(runOONIBlockingTest(ctx, cfg, progress))
}
