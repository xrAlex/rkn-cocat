package common

import reportmodel "rkn-cocat/internal/report"

type PhaseResult[T any] struct {
	Stats   T
	Section reportmodel.Section
}
