package sweep

import (
	"context"

	"rkn-cocat/internal/entity"
)

func newSizeSweepService(ctx context.Context, cfg entity.GlobalConfig, sem chan struct{}, stubIPs map[string]struct{}) *sizeSweepService {
	if stubIPs == nil {
		stubIPs = map[string]struct{}{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return &sizeSweepService{
		ctx:        ctx,
		cfg:        cfg,
		sem:        sem,
		stubIPs:    stubIPs,
		classifier: newErrorClassifier(cfg),
		dns:        newDNSService(ctx, cfg),
	}
}

func (s *sizeSweepService) selectedItems(items []entity.TCPTarget) []entity.TCPTarget {
	return limitItems(items, s.cfg.SweepProbeTargets)
}

func (s *sizeSweepService) hasValidSweepRange() bool {
	return s.cfg.SweepMinKB > 0 && s.cfg.SweepMaxKB > 0 && s.cfg.SweepMaxKB >= s.cfg.SweepMinKB
}
