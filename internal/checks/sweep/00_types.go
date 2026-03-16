package sweep

import (
	"context"

	"rkn-cocat/internal/entity"
)

type sweepRow struct {
	ID         string
	Provider   string
	Domain     string
	TargetIP   string
	Status     string
	BreakKB    int
	BreakText  string
	Detail     string
	ResolvedIP string
}

type sizeSweepService struct {
	ctx        context.Context
	cfg        entity.GlobalConfig
	sem        chan struct{}
	stubIPs    map[string]struct{}
	classifier *errorClassifier
	dns        *dnsService
}
